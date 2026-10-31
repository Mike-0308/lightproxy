package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type compiledRule struct {
	cfg  Rule
	rp   *httputil.ReverseProxy
	path string
}

type Proxy struct {
	rules  []*compiledRule
	logs   *LogBuffer
	access bool

	reqs atomic.Int64
	errs atomic.Int64
	live atomic.Int64
}

func NewProxy(cfg *Config, logs *LogBuffer) (*Proxy, error) {
	p := &Proxy{logs: logs, access: cfg.Runtime.AccessLog}
	for _, r := range cfg.Proxy {
		if r.Disable {
			continue
		}
		cr, err := buildRule(r, logs)
		if err != nil {
			return nil, fmt.Errorf("规则「%s」: %w", r.Name, err)
		}
		p.rules = append(p.rules, cr)
	}
	// 路径长的优先，保证 /api 比 / 先命中
	sort.SliceStable(p.rules, func(i, j int) bool {
		return len(p.rules[i].path) > len(p.rules[j].path)
	})
	return p, nil
}

func buildRule(r Rule, logs *LogBuffer) (*compiledRule, error) {
	target, err := url.Parse(r.Target)
	if err != nil || target.Host == "" {
		return nil, fmt.Errorf("上游地址无效: %s", r.Target)
	}
	prefix := normalizePath(r.Path)
	upstream := r.Target

	tr := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          48,
		MaxIdleConnsPerHost:   8,
		IdleConnTimeout:       45 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
		ReadBufferSize:        16 << 10,
		WriteBufferSize:       16 << 10,
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: r.Insecure},
	}

	headers := r.Headers
	delHeaders := r.DelHeaders

	rp := &httputil.ReverseProxy{
		Transport:     tr,
		FlushInterval: -1, // 立即刷新，兼容 SSE / 大文件下载
		Rewrite: func(pr *httputil.ProxyRequest) {
			rest := strings.TrimPrefix(pr.In.URL.Path, prefix)
			if rest == "" {
				rest = "/"
			} else if !strings.HasPrefix(rest, "/") {
				rest = "/" + rest
			}
			u := *target
			u.Path = joinPath(target.Path, rest)
			u.RawQuery = pr.In.URL.RawQuery
			pr.Out.URL = &u
			pr.Out.Host = target.Host
			if r.PreserveHost {
				pr.Out.Host = pr.In.Host
			}
			pr.SetXForwarded()
			if ip := clientIP(pr.In); ip != "" {
				pr.Out.Header.Set("X-Real-IP", ip)
			}
			for k, v := range headers {
				pr.Out.Header.Set(k, expandVars(v, pr.In))
			}
			for _, k := range delHeaders {
				pr.Out.Header.Del(strings.TrimSpace(k))
			}
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			logs.Warnf("反代失败 %s%s -> %s：%v", req.Host, req.URL.Path, upstream, err)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, "上游不可达\n\n目标: %s\n原因: %v\n", upstream, err)
		},
	}
	return &compiledRule{cfg: r, rp: rp, path: prefix}, nil
}

func joinPath(base, rest string) string {
	if base == "" || base == "/" {
		return rest
	}
	return strings.TrimRight(base, "/") + rest
}

func expandVars(v string, r *http.Request) string {
	v = strings.ReplaceAll(v, "{client}", clientIP(r))
	v = strings.ReplaceAll(v, "{host}", r.Host)
	v = strings.ReplaceAll(v, "{scheme}", scheme(r))
	return v
}

func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.IndexByte(v, ','); i > 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.reqs.Add(1)
	p.live.Add(1)
	defer p.live.Add(-1)

	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")

	rule := p.find(host, r.URL.Path)
	if rule == nil {
		p.errs.Add(1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintf(w, "没有匹配的转发规则\nhost: %s\npath: %s\n", host, r.URL.Path)
		return
	}

	start := time.Now()
	rec := &respRecorder{ResponseWriter: w, status: 200}
	rule.rp.ServeHTTP(rec, r)

	if p.access {
		p.logs.Infof("%d %s %s%s %s %dB %s", rec.status, r.Method, host, r.URL.Path,
			time.Since(start).Round(time.Millisecond), rec.bytes, rule.cfg.Target)
	}
	if rec.status >= 500 {
		p.errs.Add(1)
	}
}

func (p *Proxy) find(host, path string) *compiledRule {
	for _, r := range p.rules {
		if !hostMatch(r.cfg.Hosts, host) {
			continue
		}
		if !pathMatch(r.path, path) {
			continue
		}
		return r
	}
	return nil
}

func hostMatch(patterns []string, host string) bool {
	for _, p := range patterns {
		if p == "*" {
			return true
		}
		if strings.HasPrefix(p, "*.") {
			if strings.HasSuffix(host, p[1:]) && len(host) > len(p)-1 {
				return true
			}
			continue
		}
		if p == host {
			return true
		}
	}
	return false
}

func pathMatch(prefix, path string) bool {
	if prefix == "/" {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || path[len(prefix)] == '/'
}

// respRecorder 记录状态码与字节数，并通过 Unwrap 保留 Hijack（WebSocket）能力。
type respRecorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *respRecorder) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *respRecorder) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

func (w *respRecorder) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *respRecorder) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ---------------- 证书管理 ----------------

type certManager struct {
	logs *LogBuffer

	mu     sync.RWMutex
	byName map[string]*tls.Certificate
	def    *tls.Certificate
	any    *tls.Certificate // 客户端不发 SNI 时（比如直接用 IP 访问）拿来握手，好让请求走到 403 页
	names  []string
	err    error

	certFile, keyFile, dir string
}

func newCertManager(cfg TLSConfig, logs *LogBuffer) *certManager {
	return &certManager{
		logs:     logs,
		byName:   map[string]*tls.Certificate{},
		certFile: cfg.Cert,
		keyFile:  cfg.Key,
		dir:      cfg.CertDir,
	}
}

func (m *certManager) reload() error {
	byName := map[string]*tls.Certificate{}
	var def *tls.Certificate

	if m.certFile != "" && m.keyFile != "" {
		c, err := tls.LoadX509KeyPair(m.certFile, m.keyFile)
		if err != nil {
			return fmt.Errorf("加载默认证书失败: %w", err)
		}
		def = &c
		addCertNames(byName, &c)
	}

	if m.dir != "" {
		entries, err := os.ReadDir(m.dir)
		if err != nil {
			// 证书目录还没建（还没签发过）是正常状态，不当错误提示
			if !os.IsNotExist(err) {
				m.logs.Warnf("证书目录不可读: %v", err)
			}
		} else {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				name := e.Name()
				ext := strings.ToLower(filepath.Ext(name))
				if ext != ".crt" && ext != ".pem" && ext != ".cer" {
					continue
				}
				base := strings.TrimSuffix(name, filepath.Ext(name))
				keyPath := ""
				for _, kext := range []string{".key", ".pem"} {
					p := filepath.Join(m.dir, base+kext)
					if _, err := os.Stat(p); err == nil {
						keyPath = p
						break
					}
				}
				if keyPath == "" {
					continue
				}
				c, err := tls.LoadX509KeyPair(filepath.Join(m.dir, name), keyPath)
				if err != nil {
					m.logs.Warnf("证书 %s 加载失败: %v", name, err)
					continue
				}
				byName[strings.ToLower(base)] = &c
				addCertNames(byName, &c)
			}
		}
	}

	if def == nil && len(byName) == 0 {
		return errors.New("没有找到任何可用证书")
	}

	names := make([]string, 0, len(byName))
	for k := range byName {
		names = append(names, k)
	}
	sort.Strings(names)

	var any *tls.Certificate
	if def != nil {
		any = def
	} else if len(names) > 0 {
		any = byName[names[0]]
	}

	m.mu.Lock()
	m.byName = byName
	m.def = def
	m.any = any
	m.names = names
	m.err = nil
	m.mu.Unlock()
	m.logs.Infof("已加载证书 %d 个：%s", len(names), strings.Join(names, ", "))
	return nil
}

func addCertNames(dst map[string]*tls.Certificate, c *tls.Certificate) {
	if len(c.Certificate) == 0 {
		return
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return
	}
	for _, n := range leaf.DNSNames {
		dst[strings.ToLower(n)] = c
	}
	if leaf.Subject.CommonName != "" {
		dst[strings.ToLower(leaf.Subject.CommonName)] = c
	}
}

func (m *certManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.def == nil && len(m.byName) == 0 {
		return nil, errors.New("服务端未配置证书")
	}
	sni := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	// 直接用 IP 访问时浏览器/客户端不会发 SNI：随便给一张证书先把握手完成，
	// 后面「只允许域名访问」会回 403，比握手就直接失败（浏览器只报证书错误）更好懂。
	if sni == "" && m.any != nil {
		return m.any, nil
	}
	if c, ok := m.byName[sni]; ok {
		return c, nil
	}
	if i := strings.IndexByte(sni, '.'); i > 0 {
		if c, ok := m.byName["*"+sni[i:]]; ok {
			return c, nil
		}
	}
	if m.def != nil {
		return m.def, nil
	}
	return nil, fmt.Errorf("没有匹配 %q 的证书", sni)
}

func (m *certManager) Info() map[string]any {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := map[string]any{"names": m.names, "count": len(m.names), "default": m.def != nil}
	if m.def != nil && len(m.def.Certificate) > 0 {
		if leaf, err := x509.ParseCertificate(m.def.Certificate[0]); err == nil {
			out["notAfter"] = leaf.NotAfter.Format("2006-01-02")
			out["subject"] = leaf.Subject.CommonName
		}
	}
	return out
}
