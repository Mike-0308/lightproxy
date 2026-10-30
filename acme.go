package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func tlsConfigInsecure(insecure bool) *tls.Config {
	return &tls.Config{InsecureSkipVerify: insecure}
}

// ACME v2 客户端（DNS-01）。只用标准库实现，不引入 lego 之类的依赖——
// 在 32 位路由器上，多一个依赖就是多几 MB 体积和几百 KB 常驻内存。
//
// 选 DNS-01 而不是 HTTP-01 的原因：TXT 记录验证走阿里云解析，
// 不需要 80 端口从公网可达，也不会和反向代理抢 /.well-known 路径，
// 而且顺带能签泛域名。

// ---------------- 协议数据结构 ----------------

type acmeDirectory struct {
	NewNonce   string `json:"newNonce"`
	NewAccount string `json:"newAccount"`
	NewOrder   string `json:"newOrder"`
	NewAuthz   string `json:"newAuthz"`
	RevokeCert string `json:"revokeCert"`
	KeyChange  string `json:"keyChange"`
}

type acmeProblem struct {
	Type        string `json:"type"`
	Detail      string `json:"detail"`
	Status      int    `json:"status"`
	Subproblems []struct {
		Type   string `json:"type"`
		Detail string `json:"detail"`
	} `json:"subproblems,omitempty"`
}

func (p *acmeProblem) Error() string {
	code := p.Type
	if i := strings.LastIndexByte(code, ':'); i >= 0 {
		code = code[i+1:]
	}
	if p.Detail == "" {
		return "CA 返回错误 " + code
	}
	return code + ": " + p.Detail
}

type acmeIdentifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type acmeChallenge struct {
	Type   string       `json:"type"`
	URL    string       `json:"url"`
	Token  string       `json:"token"`
	Status string       `json:"status"`
	Error  *acmeProblem `json:"error,omitempty"`
}

type acmeAuthorization struct {
	Status     string          `json:"status"`
	Identifier acmeIdentifier  `json:"identifier"`
	Challenges []acmeChallenge `json:"challenges"`
	Wildcard   bool            `json:"wildcard,omitempty"`
}

type acmeOrder struct {
	Status         string           `json:"status"`
	Identifiers    []acmeIdentifier `json:"identifiers"`
	Authorizations []string         `json:"authorizations"`
	Finalize       string           `json:"finalize"`
	Certificate    string           `json:"certificate"`
	Error          *acmeProblem     `json:"error,omitempty"`
}

// ---------------- 客户端 ----------------

type acmeClient struct {
	dir   acmeDirectory
	key   *ecdsa.PrivateKey
	kid   string
	nonce string
	http  *http.Client
}

func caDirectoryURL(ca string) string {
	switch strings.ToLower(strings.TrimSpace(ca)) {
	case "", "letsencrypt", "le":
		return "https://acme-v02.api.letsencrypt.org/directory"
	case "staging", "letsencrypt-staging":
		return "https://acme-staging-v02.api.letsencrypt.org/directory"
	case "zerossl":
		return "https://acme.zerossl.com/v2/DV90"
	default:
		if strings.HasPrefix(ca, "http://") || strings.HasPrefix(ca, "https://") {
			return ca
		}
		return "https://acme-v02.api.letsencrypt.org/directory"
	}
}

func loadOrCreateAccountKey(path string) (*ecdsa.PrivateKey, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("账户密钥文件格式不对: %s", path)
		}
		if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
			return k, nil
		}
		if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if ec, ok := k.(*ecdsa.PrivateKey); ok {
				return ec, nil
			}
		}
		return nil, fmt.Errorf("无法解析账户密钥: %s", path)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if dir := filepath.Dir(path); dir != "" {
		os.MkdirAll(dir, 0o755)
	}
	blk := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, blk, 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func newACMEClient(ca, keyPath string, insecure bool) (*acmeClient, error) {
	key, err := loadOrCreateAccountKey(keyPath)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{
		Proxy:               nil,
		MaxIdleConns:        4,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     60 * time.Second,
		TLSHandshakeTimeout: 15 * time.Second,
		TLSClientConfig:     tlsConfigInsecure(insecure),
	}
	c := &acmeClient{key: key, http: &http.Client{Timeout: 45 * time.Second, Transport: tr}}

	url := caDirectoryURL(ca)
	resp, err := c.http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("访问 CA 目录失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("CA 目录返回 HTTP %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, &c.dir); err != nil {
		return nil, fmt.Errorf("CA 目录无法解析: %w", err)
	}
	if c.dir.NewAccount == "" || c.dir.NewOrder == "" || c.dir.NewNonce == "" {
		return nil, errors.New("CA 目录缺少必要端点")
	}
	return c, nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (c *acmeClient) jwk() map[string]string {
	x := make([]byte, 32)
	y := make([]byte, 32)
	c.key.X.FillBytes(x)
	c.key.Y.FillBytes(y)
	return map[string]string{"crv": "P-256", "kty": "EC", "x": b64(x), "y": b64(y)}
}

// thumbprint 用 RFC 7638 规定的字段字典序拼接，不能直接 json.Marshal 结构体。
func (c *acmeClient) thumbprint() string {
	x := make([]byte, 32)
	y := make([]byte, 32)
	c.key.X.FillBytes(x)
	c.key.Y.FillBytes(y)
	s := `{"crv":"P-256","kty":"EC","x":"` + b64(x) + `","y":"` + b64(y) + `"}`
	h := sha256.Sum256([]byte(s))
	return b64(h[:])
}

// es256Sign 输出 r||s 定长 64 字节，不是 ASN.1 —— 这是 JWS 的硬性要求。
func es256Sign(key *ecdsa.PrivateKey, data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, h[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

func (c *acmeClient) buildJWS(url string, payload any, useJWK bool) ([]byte, error) {
	protected := map[string]any{"alg": "ES256", "nonce": c.nonce, "url": url}
	if useJWK {
		protected["jwk"] = c.jwk()
	} else {
		if c.kid == "" {
			return nil, errors.New("账户尚未注册")
		}
		protected["kid"] = c.kid
	}
	pb, err := json.Marshal(protected)
	if err != nil {
		return nil, err
	}
	payloadB64 := ""
	if payload != nil {
		pj, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		payloadB64 = b64(pj)
	}
	sig, err := es256Sign(c.key, []byte(b64(pb)+"."+payloadB64))
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]string{
		"protected": b64(pb),
		"payload":   payloadB64,
		"signature": b64(sig),
	})
}

func (c *acmeClient) fetchNonce() error {
	req, err := http.NewRequest(http.MethodHead, c.dir.NewNonce, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("获取 nonce 失败: %w", err)
	}
	resp.Body.Close()
	n := resp.Header.Get("Replay-Nonce")
	if n == "" {
		return errors.New("CA 没有返回 nonce")
	}
	c.nonce = n
	return nil
}

// do 发送一个已签名的请求；payload 为 nil 时按 POST-as-GET 处理。
func (c *acmeClient) do(url string, payload any, useJWK bool) ([]byte, http.Header, error) {
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if c.nonce == "" {
			if err := c.fetchNonce(); err != nil {
				return nil, nil, err
			}
		}
		body, err := c.buildJWS(url, payload, useJWK)
		if err != nil {
			return nil, nil, err
		}
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, nil, err
		}
		req.Header.Set("Content-Type", "application/jose+json")
		req.Header.Set("User-Agent", "lightproxy/"+version)
		resp, err := c.http.Do(req)
		if err != nil {
			return nil, nil, err
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()

		if n := resp.Header.Get("Replay-Nonce"); n != "" {
			c.nonce = n
		} else {
			c.nonce = ""
		}
		if resp.StatusCode < 400 {
			return data, resp.Header, nil
		}
		var p acmeProblem
		json.Unmarshal(data, &p)
		if p.Type == "" {
			p.Type = fmt.Sprintf("HTTP %d", resp.StatusCode)
			p.Detail = firstLine(string(data))
		}
		lastErr = &p
		// nonce 过期是正常现象，换一个重试即可
		if strings.HasSuffix(p.Type, ":badNonce") && attempt < 2 {
			continue
		}
		return data, resp.Header, lastErr
	}
	return nil, nil, lastErr
}

func (c *acmeClient) ensureAccount(email string) error {
	payload := map[string]any{"termsOfServiceAgreed": true}
	if email != "" {
		payload["contact"] = []string{"mailto:" + email}
	}
	_, hdr, err := c.do(c.dir.NewAccount, payload, true)
	if err != nil {
		return err
	}
	kid := hdr.Get("Location")
	if kid == "" {
		return errors.New("CA 未返回账户地址")
	}
	c.kid = kid
	return nil
}

func (c *acmeClient) newOrder(domains []string) (*acmeOrder, string, error) {
	ids := make([]acmeIdentifier, 0, len(domains))
	for _, d := range domains {
		ids = append(ids, acmeIdentifier{Type: "dns", Value: d})
	}
	data, hdr, err := c.do(c.dir.NewOrder, map[string]any{"identifiers": ids}, false)
	if err != nil {
		return nil, "", err
	}
	var o acmeOrder
	if err := json.Unmarshal(data, &o); err != nil {
		return nil, "", fmt.Errorf("订单无法解析: %w", err)
	}
	return &o, hdr.Get("Location"), nil
}

// dns01Value 是 DNS-01 要放进 TXT 的值：base64url(sha256(keyAuth))。
func (c *acmeClient) dns01Value(token string) string {
	keyAuth := token + "." + c.thumbprint()
	h := sha256.Sum256([]byte(keyAuth))
	return b64(h[:])
}

func retryAfter(h http.Header, def time.Duration) time.Duration {
	if v := h.Get("Retry-After"); v != "" {
		var sec int
		if _, err := fmt.Sscanf(v, "%d", &sec); err == nil && sec > 0 && sec < 120 {
			return time.Duration(sec) * time.Second
		}
	}
	return def
}

func (c *acmeClient) waitAuthz(url string) error {
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		data, hdr, err := c.do(url, nil, false)
		if err != nil {
			return err
		}
		var az acmeAuthorization
		if err := json.Unmarshal(data, &az); err != nil {
			return fmt.Errorf("授权信息无法解析: %w", err)
		}
		switch az.Status {
		case "valid":
			return nil
		case "invalid":
			reason := "未知原因"
			for _, ch := range az.Challenges {
				if ch.Error != nil {
					reason = ch.Error.Error()
					break
				}
			}
			return fmt.Errorf("%s 验证未通过：%s", az.Identifier.Value, reason)
		}
		time.Sleep(retryAfter(hdr, 3*time.Second))
	}
	return errors.New("等待域名验证超时")
}

func (c *acmeClient) waitOrder(url string) (*acmeOrder, error) {
	deadline := time.Now().Add(3 * time.Minute)
	for time.Now().Before(deadline) {
		data, hdr, err := c.do(url, nil, false)
		if err != nil {
			return nil, err
		}
		var o acmeOrder
		if err := json.Unmarshal(data, &o); err != nil {
			return nil, fmt.Errorf("订单无法解析: %w", err)
		}
		switch o.Status {
		case "valid":
			return &o, nil
		case "invalid":
			if o.Error != nil {
				return nil, o.Error
			}
			return nil, errors.New("订单状态为 invalid")
		}
		time.Sleep(retryAfter(hdr, 2*time.Second))
	}
	return nil, errors.New("等待签发超时")
}

// ---------------- 签发流程 ----------------

type issueParams struct {
	Domains     []string
	Email       string
	KeyType     string
	CA          string
	AK          string
	SK          string
	Insecure    bool
	AccountKey  string
	SkipDNSWait bool
}

// 便于测试时替换
var acmeLookupTXT = defaultLookupTXT

func defaultLookupTXT(name string) []string {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 4 * time.Second}
			return d.DialContext(ctx, "udp", "223.5.5.5:53")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	txts, err := r.LookupTXT(ctx, name)
	if err != nil {
		return nil
	}
	return txts
}

func waitTXT(name, want string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		for _, t := range acmeLookupTXT(name) {
			if t == want {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("等待 %s 的 TXT 记录生效超时（DNS 缓存可能还没过期，稍后重试即可）", name)
		}
		time.Sleep(3 * time.Second)
	}
}

// challengeFQDN 由域名推出 TXT 记录名：泛域名去掉 *.
func challengeFQDN(domain string) string {
	return "_acme-challenge." + strings.TrimPrefix(strings.ToLower(domain), "*.")
}

// pickZone 在账号下的域名里找最长后缀匹配，并算出 RR。
func pickZone(fqdn string, zones []string) (zone, rr string, ok bool) {
	fqdn = strings.TrimSuffix(strings.ToLower(fqdn), ".")
	best := ""
	for _, z := range zones {
		z = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(z)), ".")
		if z == "" {
			continue
		}
		if fqdn == z || strings.HasSuffix(fqdn, "."+z) {
			if len(z) > len(best) {
				best = z
			}
		}
	}
	if best == "" {
		return "", "", false
	}
	rr = strings.TrimSuffix(fqdn, "."+best)
	if rr == fqdn || rr == "" {
		rr = "@"
	}
	return best, rr, true
}

func generateCertKey(keyType string) (any, error) {
	if keyType == "rsa2048" {
		return rsa.GenerateKey(rand.Reader, 2048)
	}
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func marshalKeyPEM(key any) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// runACMEIssue 走完一次完整签发，返回证书链与私钥的 PEM。
func runACMEIssue(p issueParams, logs *LogBuffer) (certPEM, keyPEM []byte, err error) {
	note := func(f string, a ...any) {
		if logs != nil {
			logs.Infof(f, a...)
		}
	}

	client, err := newACMEClient(p.CA, p.AccountKey, p.Insecure)
	if err != nil {
		return nil, nil, fmt.Errorf("连接 CA 失败: %w", err)
	}
	if err := client.ensureAccount(p.Email); err != nil {
		return nil, nil, fmt.Errorf("注册 ACME 账户失败: %w", err)
	}
	note("ACME 账户就绪，开始申请 %d 个域名", len(p.Domains))

	order, orderURL, err := client.newOrder(p.Domains)
	if err != nil {
		return nil, nil, fmt.Errorf("创建订单失败: %w", err)
	}

	dns := newAliyunClient(p.AK, p.SK, p.Insecure)
	zones, err := dns.ListDomains()
	if err != nil {
		return nil, nil, fmt.Errorf("读取阿里云域名列表失败（检查 AccessKey 权限）: %w", err)
	}
	if len(zones) == 0 {
		return nil, nil, errors.New("阿里云账号下没有域名，无法添加验证记录")
	}

	type pendingItem struct {
		authzURL string
		chal     acmeChallenge
		fqdn     string
		txt      string
	}

	var items []pendingItem
	var recordIDs []string
	defer func() {
		for _, id := range recordIDs {
			if e := dns.DeleteRecord(id); e != nil {
				note("清理验证记录失败（可忽略，下次签发会覆盖）：%v", e)
			}
		}
	}()

	// 先把所有 TXT 一并加上，再一起等生效，省掉逐个域名串行等待的时间
	for _, authURL := range order.Authorizations {
		data, _, e := client.do(authURL, nil, false)
		if e != nil {
			return nil, nil, fmt.Errorf("读取授权信息失败: %w", e)
		}
		var az acmeAuthorization
		if e := json.Unmarshal(data, &az); e != nil {
			return nil, nil, e
		}
		if az.Status == "valid" {
			continue
		}
		var chal *acmeChallenge
		for i := range az.Challenges {
			if az.Challenges[i].Type == "dns-01" {
				chal = &az.Challenges[i]
				break
			}
		}
		if chal == nil {
			return nil, nil, fmt.Errorf("%s 的 CA 没有提供 DNS-01 验证方式", az.Identifier.Value)
		}
		fqdn := challengeFQDN(az.Identifier.Value)
		zone, rr, ok := pickZone(fqdn, zones)
		if !ok {
			return nil, nil, fmt.Errorf("阿里云账号下找不到 %s 所属的域名，无法添加验证记录", fqdn)
		}
		val := client.dns01Value(chal.Token)
		id, e := dns.AddRecord(zone, rr, "TXT", val, 600)
		if e != nil {
			return nil, nil, fmt.Errorf("添加 TXT 记录 %s.%s 失败: %w", rr, zone, e)
		}
		if id != "" {
			recordIDs = append(recordIDs, id)
		}
		note("已添加验证记录 %s.%s", rr, zone)
		items = append(items, pendingItem{authzURL: authURL, chal: *chal, fqdn: fqdn, txt: val})
	}

	if !p.SkipDNSWait {
		for _, it := range items {
			if e := waitTXT(it.fqdn, it.txt, 3*time.Minute); e != nil {
				return nil, nil, e
			}
			note("验证记录已生效：%s", it.fqdn)
		}
	}

	for _, it := range items {
		if _, _, e := client.do(it.chal.URL, map[string]any{}, false); e != nil {
			return nil, nil, fmt.Errorf("触发域名验证失败: %w", e)
		}
	}
	for _, it := range items {
		if e := client.waitAuthz(it.authzURL); e != nil {
			return nil, nil, e
		}
	}
	note("全部域名验证通过，开始签发")

	certKey, err := generateCertKey(p.KeyType)
	if err != nil {
		return nil, nil, fmt.Errorf("生成证书私钥失败: %w", err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: p.Domains}, certKey)
	if err != nil {
		return nil, nil, fmt.Errorf("生成 CSR 失败: %w", err)
	}
	if _, _, err := client.do(order.Finalize, map[string]any{"csr": b64(csr)}, false); err != nil {
		return nil, nil, fmt.Errorf("提交 CSR 失败: %w", err)
	}

	final, err := client.waitOrder(orderURL)
	if err != nil {
		return nil, nil, err
	}
	if final.Certificate == "" {
		return nil, nil, errors.New("签发成功但 CA 未给出证书地址")
	}
	certData, _, err := client.do(final.Certificate, nil, false)
	if err != nil {
		return nil, nil, fmt.Errorf("下载证书失败: %w", err)
	}
	if !bytes.Contains(certData, []byte("BEGIN CERTIFICATE")) {
		return nil, nil, errors.New("CA 返回的证书内容不是 PEM 格式")
	}
	keyData, err := marshalKeyPEM(certKey)
	if err != nil {
		return nil, nil, err
	}
	return certData, keyData, nil
}

// ---------------- 管理器 ----------------

type ACMEStatus struct {
	Enabled   bool      `json:"enabled"`
	Domains   []string  `json:"domains"`
	Issuing   bool      `json:"issuing"`
	Stage     string    `json:"stage,omitempty"`
	LastRun   time.Time `json:"lastRun"`
	LastError string    `json:"lastError,omitempty"`
	LastOK    string    `json:"lastOk,omitempty"`
	NotAfter  string    `json:"notAfter,omitempty"`
	Subject   string    `json:"subject,omitempty"`
}

type ACMEManager struct {
	mu       sync.Mutex
	cfg      ACMEConfig
	keyPath  string
	logs     *LogBuffer
	status   ACMEStatus
	onReload func() error

	stopOnce sync.Once
	stop     chan struct{}
}

func NewACMEManager(cfg ACMEConfig, keyPath string, logs *LogBuffer, onReload func() error) *ACMEManager {
	return &ACMEManager{
		cfg:      cfg,
		keyPath:  keyPath,
		logs:     logs,
		onReload: onReload,
		stop:     make(chan struct{}),
		status:   ACMEStatus{Enabled: cfg.Enable, Domains: cfg.Domains},
	}
}

func (m *ACMEManager) Stop() {
	m.stopOnce.Do(func() { close(m.stop) })
}

func (m *ACMEManager) Snapshot() ACMEStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.status
	st.Enabled = m.cfg.Enable
	st.Domains = m.cfg.Domains
	if st.NotAfter == "" {
		if leaf := m.readLeaf(); leaf != nil {
			st.NotAfter = leaf.NotAfter.Format("2006-01-02 15:04")
			st.Subject = leaf.Subject.CommonName
		}
	}
	return st
}

func (m *ACMEManager) certPath() string {
	if m.cfg.CertDir == "" || len(m.cfg.Domains) == 0 {
		return ""
	}
	base := strings.TrimPrefix(m.cfg.Domains[0], "*.")
	return filepath.Join(m.cfg.CertDir, base+".crt")
}

func (m *ACMEManager) readLeaf() *x509.Certificate {
	p := m.certPath()
	if p == "" {
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return leaf
}

// Start 启动后台巡检：每小时看一次，临期就续。
func (m *ACMEManager) Start() {
	if !m.cfg.Enable {
		return
	}
	go func() {
		// 开机先等网络就绪，避免一上来就连不上 CA
		select {
		case <-time.After(25 * time.Second):
		case <-m.stop:
			return
		}
		for {
			m.checkOnce()
			select {
			case <-time.After(time.Hour):
			case <-m.stop:
				return
			}
		}
	}()
}

func (m *ACMEManager) checkOnce() {
	m.mu.Lock()
	leaf := m.readLeaf()
	need := leaf == nil
	reason := "证书不存在"
	if leaf != nil {
		left := time.Until(leaf.NotAfter)
		if left < time.Duration(m.cfg.RenewDays)*24*time.Hour {
			need = true
			reason = fmt.Sprintf("剩余 %d 天，进入续期窗口", int(left.Hours()/24))
		}
	}
	m.mu.Unlock()
	if !need {
		return
	}
	if m.logs != nil {
		m.logs.Infof("自动证书：%s，开始签发", reason)
	}
	if err := m.IssueNow(); err != nil && m.logs != nil {
		m.logs.Errorf("自动证书签发失败: %v", err)
	}
}

// IssueNow 立即签发一次。串行执行，重复点击会直接返回"正在签发"。
func (m *ACMEManager) IssueNow() error {
	m.mu.Lock()
	if m.status.Issuing {
		m.mu.Unlock()
		return errors.New("正在签发中，请稍候")
	}
	if !m.cfg.Enable {
		m.mu.Unlock()
		return errors.New("自动证书未启用")
	}
	m.status.Issuing = true
	m.status.Stage = "准备中"
	m.status.LastError = ""
	cfg := m.cfg
	keyPath := m.keyPath
	m.mu.Unlock()

	setStage := func(s string) {
		m.mu.Lock()
		m.status.Stage = s
		m.mu.Unlock()
		if m.logs != nil {
			m.logs.Infof("自动证书：%s", s)
		}
	}

	setStage("连接 CA")
	certPEM, keyPEM, err := runACMEIssue(issueParams{
		Domains:    cfg.Domains,
		Email:      cfg.Email,
		KeyType:    cfg.KeyType,
		CA:         cfg.CA,
		AK:         cfg.AccessKey,
		SK:         cfg.SecretKey,
		Insecure:   cfg.Insecure,
		AccountKey: keyPath,
	}, m.logs)

	if err != nil {
		m.mu.Lock()
		m.status.Issuing = false
		m.status.Stage = ""
		m.status.LastError = err.Error()
		m.status.LastRun = time.Now()
		m.mu.Unlock()
		return err
	}

	setStage("写入证书文件")
	if err := os.MkdirAll(cfg.CertDir, 0o755); err != nil {
		m.fail(err)
		return err
	}
	base := strings.TrimPrefix(cfg.Domains[0], "*.")
	certFile := filepath.Join(cfg.CertDir, base+".crt")
	keyFile := filepath.Join(cfg.CertDir, base+".key")
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		m.fail(err)
		return err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		m.fail(err)
		return err
	}

	setStage("重载证书")
	var reloadErr error
	if m.onReload != nil {
		reloadErr = m.onReload()
	}
	if reloadErr != nil {
		m.logs.Warnf("证书已写入但重载失败（多半是 TLS 未启用）: %v", reloadErr)
	}

	m.mu.Lock()
	m.status.Issuing = false
	m.status.Stage = ""
	m.status.LastRun = time.Now()
	m.status.LastOK = time.Now().Format("2006-01-02 15:04")
	m.status.NotAfter = ""
	m.status.Subject = ""
	leaf := m.readLeafLocked()
	if leaf != nil {
		m.status.NotAfter = leaf.NotAfter.Format("2006-01-02 15:04")
		m.status.Subject = leaf.Subject.CommonName
	}
	m.mu.Unlock()

	if m.logs != nil {
		m.logs.Infof("自动证书签发完成：%s", strings.Join(cfg.Domains, ", "))
	}
	return nil
}

func (m *ACMEManager) fail(err error) {
	m.mu.Lock()
	m.status.Issuing = false
	m.status.Stage = ""
	m.status.LastError = err.Error()
	m.status.LastRun = time.Now()
	m.mu.Unlock()
}

func (m *ACMEManager) readLeafLocked() *x509.Certificate {
	if m.cfg.CertDir == "" || len(m.cfg.Domains) == 0 {
		return nil
	}
	p := filepath.Join(m.cfg.CertDir, strings.TrimPrefix(m.cfg.Domains[0], "*.")+".crt")
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return leaf
}
