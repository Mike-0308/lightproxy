package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPickZone(t *testing.T) {
	zones := []string{"example.com", "sub.example.com", "another.net"}
	cases := []struct {
		fqdn, zone, rr string
		ok             bool
	}{
		{"_acme-challenge.example.com", "example.com", "_acme-challenge", true},
		{"_acme-challenge.nas.example.com", "example.com", "_acme-challenge.nas", true},
		{"_acme-challenge.a.sub.example.com", "sub.example.com", "_acme-challenge.a", true},
		{"_acme-challenge.another.net", "another.net", "_acme-challenge", true},
		{"_acme-challenge.unknown.org", "", "", false},
	}
	for _, c := range cases {
		zone, rr, ok := pickZone(c.fqdn, zones)
		if ok != c.ok || zone != c.zone || rr != c.rr {
			t.Errorf("pickZone(%q) = (%q,%q,%v)，期望 (%q,%q,%v)", c.fqdn, zone, rr, ok, c.zone, c.rr, c.ok)
		}
	}
}

func TestChallengeFQDN(t *testing.T) {
	if got := challengeFQDN("*.example.com"); got != "_acme-challenge.example.com" {
		t.Errorf("泛域名应去掉 * 前缀，得到 %q", got)
	}
	if got := challengeFQDN("NAS.Example.com"); got != "_acme-challenge.nas.example.com" {
		t.Errorf("应统一小写，得到 %q", got)
	}
}

func TestES256SignatureFormat(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("protected.payload")
	sig, err := es256Sign(key, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("ES256 签名必须是 r||s 共 64 字节，得到 %d 字节", len(sig))
	}

	// 拆回 r、s 后应能通过标准验签
	h := sha256.Sum256(data)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.PublicKey, h[:], r, s) {
		t.Fatal("签名无法通过 ecdsa.Verify")
	}
}

func TestThumbprintMatchesRFC7638(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &acmeClient{key: key}

	x := make([]byte, 32)
	y := make([]byte, 32)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
		base64.RawURLEncoding.EncodeToString(x),
		base64.RawURLEncoding.EncodeToString(y))
	sum := sha256.Sum256([]byte(canonical))
	want := base64.RawURLEncoding.EncodeToString(sum[:])

	if got := c.thumbprint(); got != want {
		t.Fatalf("thumbprint 不正确\n得到 %s\n期望 %s", got, want)
	}
}

func TestBuildJWSPostAsGet(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &acmeClient{key: key, kid: "https://ca/acct/1", nonce: "nonce123"}

	body, err := c.buildJWS("https://ca/authz/1", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	var jws struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(body, &jws); err != nil {
		t.Fatal(err)
	}
	// POST-as-GET 的 payload 必须是空字符串，不能是 "e30"（{}）或 "bnVsbA"
	if jws.Payload != "" {
		t.Fatalf("POST-as-GET 的 payload 应为空，得到 %q", jws.Payload)
	}
	protRaw, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		t.Fatal(err)
	}
	var prot map[string]any
	json.Unmarshal(protRaw, &prot)
	if prot["alg"] != "ES256" {
		t.Errorf("alg 应为 ES256，得到 %v", prot["alg"])
	}
	if prot["kid"] != "https://ca/acct/1" {
		t.Errorf("kid 不正确: %v", prot["kid"])
	}
	if prot["url"] != "https://ca/authz/1" {
		t.Errorf("url 不正确: %v", prot["url"])
	}
	if _, ok := prot["jwk"]; ok {
		t.Error("已注册账户不应带 jwk")
	}
}

// ---------------- 端到端：mock CA + mock 阿里云 ----------------

type mockCA struct {
	srv         *httptest.Server
	accountPK   *ecdsa.PublicKey
	authzDone   bool
	orderDone   bool
	certPEM     []byte
	authzDomain string
	t           *testing.T
}

func newMockCA(t *testing.T, domains []string) *mockCA {
	m := &mockCA{t: t}

	// 准备一张自签证书当作签发结果
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domains[0]},
		DNSNames:     domains,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(90 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	m.certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	return m
}

func (m *mockCA) handle(w http.ResponseWriter, r *http.Request) {
	base := m.srv.URL
	switch r.URL.Path {
	case "/directory":
		json.NewEncoder(w).Encode(map[string]string{
			"newNonce":   base + "/nonce",
			"newAccount": base + "/new-acct",
			"newOrder":   base + "/new-order",
		})
		return
	case "/nonce":
		w.Header().Set("Replay-Nonce", "nonce-"+fmt.Sprint(time.Now().UnixNano()))
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "需要 POST", 405)
		return
	}
	prot, payload := m.verifyJWS(w, r)
	if prot == nil {
		return
	}

	switch r.URL.Path {
	case "/new-acct":
		w.Header().Set("Location", base+"/acct/1")
		w.Header().Set("Replay-Nonce", "n2")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"status":"valid"}`))

	case "/new-order":
		var req struct {
			Identifiers []acmeIdentifier `json:"identifiers"`
		}
		json.Unmarshal(payload, &req)
		if len(req.Identifiers) == 0 {
			http.Error(w, "缺少 identifiers", 400)
			return
		}
		m.authzDomain = req.Identifiers[0].Value
		w.Header().Set("Location", base+"/order/1")
		w.Header().Set("Replay-Nonce", "n3")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{
			"status":         "pending",
			"identifiers":    req.Identifiers,
			"authorizations": []string{base + "/authz/1"},
			"finalize":       base + "/finalize",
		})

	case "/authz/1":
		st := "pending"
		if m.authzDone {
			st = "valid"
		}
		w.Header().Set("Replay-Nonce", "n4")
		json.NewEncoder(w).Encode(map[string]any{
			"status":     st,
			"identifier": map[string]string{"type": "dns", "value": m.authzDomain},
			"challenges": []map[string]any{{
				"type":   "dns-01",
				"url":    base + "/chall/1",
				"token":  "mock-token",
				"status": st,
			}},
		})

	case "/chall/1":
		m.authzDone = true
		w.Header().Set("Replay-Nonce", "n5")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"type":"dns-01","status":"processing"}`))

	case "/finalize":
		var req struct {
			CSR string `json:"csr"`
		}
		json.Unmarshal(payload, &req)
		der, err := base64.RawURLEncoding.DecodeString(req.CSR)
		if err != nil {
			http.Error(w, "CSR 不是合法 base64url", 400)
			return
		}
		if _, err := x509.ParseCertificateRequest(der); err != nil {
			http.Error(w, "CSR 无法解析: "+err.Error(), 400)
			return
		}
		m.orderDone = true
		w.Header().Set("Replay-Nonce", "n6")
		json.NewEncoder(w).Encode(map[string]any{"status": "processing", "finalize": base + "/finalize"})

	case "/order/1":
		if !m.orderDone {
			json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
			return
		}
		w.Header().Set("Replay-Nonce", "n7")
		json.NewEncoder(w).Encode(map[string]any{"status": "valid", "certificate": base + "/cert/1"})

	case "/cert/1":
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.Write(m.certPEM)

	default:
		http.Error(w, "未知路径 "+r.URL.Path, 404)
	}
}

// verifyJWS 校验 JWS 结构并用公钥验签，确保我们发出去的东西 CA 能认。
func (m *mockCA) verifyJWS(w http.ResponseWriter, r *http.Request) (map[string]any, []byte) {
	var jws struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		http.Error(w, "JWS 无法解析: "+err.Error(), 400)
		return nil, nil
	}
	protRaw, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		http.Error(w, "protected 不是 base64url", 400)
		return nil, nil
	}
	var prot map[string]any
	json.Unmarshal(protRaw, &prot)
	if prot["alg"] != "ES256" {
		http.Error(w, "alg 必须是 ES256", 400)
		return nil, nil
	}
	if prot["nonce"] == nil || prot["nonce"] == "" {
		http.Error(w, "缺少 nonce", 400)
		return nil, nil
	}
	if prot["url"] != m.srv.URL+r.URL.Path {
		http.Error(w, "url 与请求地址不符: "+fmt.Sprint(prot["url"]), 400)
		return nil, nil
	}

	// 首次注册用 jwk，之后都用 kid
	if jwkRaw, ok := prot["jwk"].(map[string]any); ok {
		xb, _ := base64.RawURLEncoding.DecodeString(fmt.Sprint(jwkRaw["x"]))
		yb, _ := base64.RawURLEncoding.DecodeString(fmt.Sprint(jwkRaw["y"]))
		if len(xb) != 32 || len(yb) != 32 {
			http.Error(w, "jwk 的 x/y 必须是 32 字节定长", 400)
			return nil, nil
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
		m.accountPK = pub
	} else if prot["kid"] == nil {
		http.Error(w, "既没有 jwk 也没有 kid", 400)
		return nil, nil
	}
	if m.accountPK == nil {
		http.Error(w, "账户公钥未知", 400)
		return nil, nil
	}

	sig, err := base64.RawURLEncoding.DecodeString(jws.Signature)
	if err != nil || len(sig) != 64 {
		http.Error(w, "signature 不是 64 字节的 r||s", 400)
		return nil, nil
	}
	h := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
	rr := new(big.Int).SetBytes(sig[:32])
	ss := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(m.accountPK, h[:], rr, ss) {
		http.Error(w, "签名校验失败", 400)
		return nil, nil
	}

	payload, _ := base64.RawURLEncoding.DecodeString(jws.Payload)
	return prot, payload
}

func newMockAliDNS(t *testing.T) (*httptest.Server, *[]string) {
	var added []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch r.URL.Query().Get("Action") {
		case "DescribeDomains":
			w.Write([]byte(`{"TotalCount":1,"Domains":{"Domain":[{"DomainName":"example.com"}]}}`))
		case "AddDomainRecord":
			rr := r.URL.Query().Get("RR")
			added = append(added, rr+"|"+r.URL.Query().Get("Value"))
			w.Write([]byte(`{"RecordId":"rec-1"}`))
		case "DeleteDomainRecord":
			w.Write([]byte(`{}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	return srv, &added
}

func TestACMEIssueEndToEnd(t *testing.T) {
	domains := []string{"nas.example.com"}
	ca := newMockCA(t, domains)
	defer ca.srv.Close()

	dnsSrv, added := newMockAliDNS(t)
	defer dnsSrv.Close()

	oldEndpoint := alidnsEndpoint
	alidnsEndpoint = dnsSrv.URL
	defer func() { alidnsEndpoint = oldEndpoint }()

	dir := t.TempDir()
	certPEM, keyPEM, err := runACMEIssue(issueParams{
		Domains:     domains,
		Email:       "me@example.com",
		KeyType:     "ec256",
		CA:          ca.srv.URL + "/directory",
		AK:          "ak",
		SK:          "sk",
		AccountKey:  filepath.Join(dir, "acct.key"),
		SkipDNSWait: true,
	}, nil)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	// TXT 记录确实写进去了，并且用的是 dns-01 摘要
	if len(*added) != 1 {
		t.Fatalf("应添加 1 条 TXT 记录，实际 %d 条", len(*added))
	}
	parts := strings.Split((*added)[0], "|")
	if parts[0] != "_acme-challenge.nas" {
		t.Errorf("RR 应为 _acme-challenge.nas，得到 %q", parts[0])
	}
	if len(parts[1]) != 43 {
		t.Errorf("dns-01 的值应为 43 字符的 base64url(sha256)，得到 %d 字符", len(parts[1]))
	}

	// 返回的证书与私钥都能正常解析，且域名匹配
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("证书不是合法 PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("证书无法解析: %v", err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "nas.example.com" {
		t.Errorf("证书域名不对: %v", leaf.DNSNames)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		t.Fatal("私钥不是合法 PEM")
	}
	if _, err := x509.ParsePKCS8PrivateKey(kb.Bytes); err != nil {
		t.Fatalf("私钥无法解析: %v", err)
	}

	// 账户密钥应被持久化，下次不再重新注册
	if _, err := os.Stat(filepath.Join(dir, "acct.key")); err != nil {
		t.Errorf("账户密钥未落盘: %v", err)
	}
}

func TestIssueFailsWhenZoneMissing(t *testing.T) {
	ca := newMockCA(t, []string{"a.unknown.org"})
	defer ca.srv.Close()

	dnsSrv, _ := newMockAliDNS(t)
	defer dnsSrv.Close()

	oldEndpoint := alidnsEndpoint
	alidnsEndpoint = dnsSrv.URL
	defer func() { alidnsEndpoint = oldEndpoint }()

	_, _, err := runACMEIssue(issueParams{
		Domains:     []string{"a.unknown.org"},
		Email:       "me@example.com",
		CA:          ca.srv.URL + "/directory",
		AK:          "ak",
		SK:          "sk",
		AccountKey:  filepath.Join(t.TempDir(), "acct.key"),
		SkipDNSWait: true,
	}, nil)
	// mock CA 的授权里报告的是 nas.example.com，与 order 域名不一致，
	// 这里主要确认"找不到 zone"能给出可读错误而不是 panic
	if err == nil {
		t.Fatal("域名不在账号下时应报错")
	}
}
