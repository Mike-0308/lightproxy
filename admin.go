package main

import (
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed web
var webFS embed.FS

var webSub, _ = fs.Sub(webFS, "web")

var version = "1.3.0"

type App struct {
	mu      sync.Mutex
	cfgPath string
	cfg     *Config
	logs    *LogBuffer

	proxy   atomic.Pointer[Proxy]
	ddns    atomic.Pointer[DDNSManager]
	acme    atomic.Pointer[ACMEManager]
	forward *ForwardManager

	certs   *certManager
	servers []*http.Server
	started time.Time

	sessions    *sessionStore
	needRestart bool
}

func acmeKeyPath(cfgPath string) string {
	dir := filepath.Dir(cfgPath)
	if dir == "" || dir == "." {
		return "acme_account.key"
	}
	return filepath.Join(dir, "acme_account.key")
}

// mergeACMECreds 让自动证书在没单独填密钥时复用 DDNS 的那一份。
// 只在运行时合并，不写回配置——否则改了 DDNS 密钥这边会一直用旧的。
func mergeACMECreds(ac ACMEConfig, d DDNSConfig) ACMEConfig {
	if strings.TrimSpace(ac.AccessKey) == "" {
		ac.AccessKey = d.AccessKey
		ac.SecretKey = d.SecretKey
	}
	return ac
}

func NewApp(cfgPath string, cfg *Config, logs *LogBuffer) *App {
	a := &App{
		cfgPath:  cfgPath,
		cfg:      cfg,
		logs:     logs,
		started:  time.Now(),
		sessions: newSessionStore(12 * time.Hour),
	}
	p, err := NewProxy(cfg, logs)
	if err == nil {
		a.proxy.Store(p)
	} else {
		logs.Errorf("规则编译失败: %v", err)
		a.proxy.Store(&Proxy{logs: logs})
	}
	m := NewDDNSManager(cfg.DDNS, logs)
	a.ddns.Store(m)
	m.Start()

	a.forward = NewForwardManager(logs, cfgPath)
	am := NewACMEManager(mergeACMECreds(cfg.ACME, cfg.DDNS), acmeKeyPath(cfgPath), logs, a.reloadCerts)
	a.acme.Store(am)
	return a
}

// reloadCerts 供 ACME 签发完成后回调用，把新证书热加载进内存。
func (a *App) reloadCerts() error {
	a.mu.Lock()
	cm := a.certs
	a.mu.Unlock()
	if cm == nil {
		return errors.New("TLS 未启用，证书已写入磁盘但未加载")
	}
	return cm.reload()
}

func (a *App) Config() *Config {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cfg
}

// ApplyConfig 校验 -> 落盘 -> 热加载（反代规则与 DDNS 立即生效）。
func (a *App) ApplyConfig(next *Config, persist bool) error {
	if err := next.Normalize(); err != nil {
		return err
	}
	p, err := NewProxy(next, a.logs)
	if err != nil {
		return err
	}

	a.mu.Lock()
	old := a.cfg
	if persist {
		if err := SaveConfig(a.cfgPath, next); err != nil {
			a.mu.Unlock()
			return err
		}
	}
	a.cfg = next
	a.mu.Unlock()

	a.proxy.Store(p)

	if old.DDNS.Enable {
		if m := a.ddns.Load(); m != nil {
			m.Stop()
		}
	}
	m := NewDDNSManager(next.DDNS, a.logs)
	a.ddns.Store(m)
	m.Start()

	if a.forward != nil {
		if err := a.applyForward(next); err != nil {
			a.logs.Warnf("端口转发下发失败: %v", err)
		}
	}

	if !reflect.DeepEqual(old.ACME, next.ACME) {
		if am := a.acme.Load(); am != nil {
			am.Stop()
		}
		nm := NewACMEManager(mergeACMECreds(next.ACME, next.DDNS), acmeKeyPath(a.cfgPath), a.logs, a.reloadCerts)
		a.acme.Store(nm)
		nm.Start()
	}

	if old.Listen != next.Listen ||
		old.Admin.Listen != next.Admin.Listen ||
		old.TLS.Enable != next.TLS.Enable ||
		old.TLS.Cert != next.TLS.Cert ||
		old.TLS.Key != next.TLS.Key ||
		old.TLS.CertDir != next.TLS.CertDir ||
		old.TLS.HTTPListen != next.TLS.HTTPListen {
		a.mu.Lock()
		a.needRestart = true
		a.mu.Unlock()
		a.logs.Warnf("监听地址或 TLS 设置已修改，需重启进程后生效")
	}
	a.logs.Infof("配置已保存，规则 %d 条", len(p.rules))
	return nil
}

func (a *App) Start() error {
	cfg := a.Config()

	var servers []*http.Server
	handler := a.proxyHandler()

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	servers = append(servers, srv)

	if cfg.TLS.Enable {
		a.certs = newCertManager(cfg.TLS, a.logs)
		if err := a.certs.reload(); err != nil {
			return err
		}
		srv.TLSConfig = &tls.Config{
			GetCertificate: a.certs.GetCertificate,
			MinVersion:     tls.VersionTLS12,
			NextProtos:     []string{"h2", "http/1.1"},
		}
		go func() {
			a.logs.Infof("反向代理监听 %s（HTTPS）", cfg.Listen)
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				a.logs.Errorf("HTTPS 监听失败: %v", err)
			}
		}()

		if cfg.TLS.HTTPListen != "" {
			rs := &http.Server{
				Addr:              cfg.TLS.HTTPListen,
				Handler:           a.redirectHandler(),
				ReadHeaderTimeout: 10 * time.Second,
			}
			servers = append(servers, rs)
			go func() {
				a.logs.Infof("HTTP 跳转监听 %s", cfg.TLS.HTTPListen)
				if err := rs.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					a.logs.Errorf("HTTP 跳转监听失败: %v", err)
				}
			}()
		}
	} else {
		go func() {
			a.logs.Infof("反向代理监听 %s（HTTP）", cfg.Listen)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				a.logs.Errorf("监听失败: %v", err)
			}
		}()
	}

	admin := &http.Server{
		Addr:              cfg.Admin.Listen,
		Handler:           a.guardedAdmin(),
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	servers = append(servers, admin)
	go func() {
		a.logs.Infof("管理面板监听 http://%s/", cfg.Admin.Listen)
		if err := admin.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			a.logs.Errorf("管理面板监听失败: %v", err)
		}
	}()

	a.mu.Lock()
	a.servers = servers
	a.mu.Unlock()

	// 端口转发：内核里的规则重启后可能被清掉，这里补一次
	if cfg.Forward.Enable {
		go func() {
			if err := a.applyForward(cfg); err != nil {
				a.logs.Warnf("启动时下发端口转发失败: %v", err)
			}
		}()
	}
	if am := a.acme.Load(); am != nil {
		am.Start()
	}
	return nil
}

// localForwardPorts 返回需要对外放行的本机端口（反代监听 + HTTP 跳转）。
// 管理面板端口故意不包含在内：面板只该经反代域名访问。
func localForwardPorts(cfg *Config) []int {
	var out []int
	add := func(addr string) {
		if addr == "" {
			return
		}
		_, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return
		}
		p, err := strconv.Atoi(portStr)
		if err != nil || p <= 0 || p > 65535 {
			return
		}
		for _, x := range out {
			if x == p {
				return
			}
		}
		out = append(out, p)
	}
	add(cfg.Listen)
	if cfg.TLS.Enable && cfg.TLS.Redirect && cfg.TLS.HTTPListen != "" {
		add(cfg.TLS.HTTPListen)
	}
	return out
}

// applyForward 把当前配置连同本机监听端口一起下发给防火墙。
func (a *App) applyForward(cfg *Config) error {
	if a.forward == nil {
		return nil
	}
	fc := cfg.Forward
	fc.LocalPorts = localForwardPorts(cfg)
	return a.forward.Apply(fc)
}

// proxyHandler 是反代入口：先过「只允许域名访问」的判断，再交给规则匹配。
func (a *App) proxyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := a.Config()
		if reason := cfg.allowProxyRequest(r); reason != "" {
			denyHost(w, r, reason)
			return
		}
		p := a.proxy.Load()
		if p == nil {
			http.Error(w, "服务未就绪", http.StatusServiceUnavailable)
			return
		}
		p.ServeHTTP(w, r)
	})
}

// guardedAdmin 是管理面板入口：同样拦 IP 直连，允许经反代域名访问。
func (a *App) guardedAdmin() http.Handler {
	inner := a.adminHandler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := a.Config()
		if reason := cfg.allowAdminRequest(r); reason != "" {
			denyHost(w, r, reason)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// redirectHandler 把 HTTP 请求 301 到 HTTPS。
// 外网映射端口不是 443 时（例如 8443），Location 里要带上端口，否则跳过去打不开。
func (a *App) redirectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := splitHostPort(host); err == nil && h != "" {
			host = h
		}
		target := "https://" + host
		if p := a.Config().TLS.PublicPort; p != 0 && p != 443 {
			target += ":" + strconv.Itoa(p)
		}
		http.Redirect(w, r, target+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
}

func splitHostPort(s string) (string, string, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return s, "", nil
	}
	if strings.Count(s, ":") > 1 {
		return s, "", nil // IPv6 字面量，忽略
	}
	return s[:i], s[i+1:], nil
}

// ---------------- 会话 ----------------

type sessionStore struct {
	mu  sync.Mutex
	m   map[string]time.Time
	ttl time.Duration
}

func newSessionStore(ttl time.Duration) *sessionStore {
	return &sessionStore{m: map[string]time.Time{}, ttl: ttl}
}

func (s *sessionStore) Create() string {
	b := make([]byte, 16)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	s.mu.Lock()
	s.m[tok] = time.Now().Add(s.ttl)
	s.mu.Unlock()
	return tok
}

func (s *sessionStore) Valid(tok string) bool {
	if tok == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.m, tok)
		return false
	}
	return true
}

func (s *sessionStore) Drop(tok string) {
	s.mu.Lock()
	delete(s.m, tok)
	s.mu.Unlock()
}

// ---------------- 路由 ----------------

func (a *App) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(webSub))))
	mux.HandleFunc("/", a.handleIndex)
	mux.HandleFunc("/api/login", a.handleLogin)
	mux.HandleFunc("/api/logout", a.handleLogout)
	mux.HandleFunc("/api/status", a.authed(a.handleStatus))
	mux.HandleFunc("/api/config", a.authed(a.handleConfig))
	mux.HandleFunc("/api/config/export", a.authed(a.handleConfigExport))
	mux.HandleFunc("/api/config/import", a.authed(a.handleConfigImport))
	mux.HandleFunc("/api/ddns/run", a.authed(a.handleDDNSRun))
	mux.HandleFunc("/api/ddns/test", a.authed(a.handleDDNSTest))
	mux.HandleFunc("/api/ddns/ip", a.authed(a.handleDDNSIP))
	mux.HandleFunc("/api/logs", a.authed(a.handleLogs))
	mux.HandleFunc("/api/forward/apply", a.authed(a.handleForwardApply))
	mux.HandleFunc("/api/forward/clear", a.authed(a.handleForwardClear))
	mux.HandleFunc("/api/acme/issue", a.authed(a.handleACMEIssue))
	mux.HandleFunc("/api/acme/test", a.authed(a.handleACMETest))
	mux.HandleFunc("/api/reload", a.authed(a.handleReload))
	mux.HandleFunc("/api/restart", a.authed(a.handleRestart))
	return mux
}

func (a *App) authed(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg := a.Config()
		if cfg.Admin.Pass == "" {
			fn(w, r)
			return
		}
		c, err := r.Cookie("lp_sess")
		if err != nil || !a.sessions.Valid(c.Value) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "未登录或会话已过期"})
			return
		}
		fn(w, r)
	}
}

func (a *App) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	cfg := a.Config()
	authed := true
	if cfg.Admin.Pass != "" {
		c, err := r.Cookie("lp_sess")
		authed = err == nil && a.sessions.Valid(c.Value)
	}
	page := "web/index.html"
	if !authed {
		page = "web/login.html"
	}
	data, err := webFS.ReadFile(page)
	if err != nil {
		http.Error(w, "页面缺失", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(data)
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	var body struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "请求格式错误"})
		return
	}
	cfg := a.Config()
	if cfg.Admin.Pass == "" {
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	userOK := subtle.ConstantTimeCompare([]byte(body.User), []byte(cfg.Admin.User)) == 1
	passOK := subtle.ConstantTimeCompare([]byte(body.Pass), []byte(cfg.Admin.Pass)) == 1
	if !userOK || !passOK {
		time.Sleep(300 * time.Millisecond)
		a.logs.Warnf("管理面板登录失败，来自 %s", clientIP(r))
		writeJSON(w, 401, map[string]any{"error": "用户名或密码错误"})
		return
	}
	tok := a.sessions.Create()
	http.SetCookie(w, &http.Cookie{
		Name: "lp_sess", Value: tok, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int((12 * time.Hour).Seconds()),
		Secure: r.TLS != nil,
	})
	a.logs.Infof("管理面板登录成功，来自 %s", clientIP(r))
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("lp_sess"); err == nil {
		a.sessions.Drop(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "lp_sess", Value: "", Path: "/", MaxAge: -1, HttpOnly: true})
	writeJSON(w, 200, map[string]any{"ok": true})
}

type memInfo struct {
	HeapMB     float64 `json:"heapMB"`
	SysMB      float64 `json:"sysMB"`
	RSSMB      float64 `json:"rssMB"`
	Goroutines int     `json:"goroutines"`
}

func (a *App) handleStatus(w http.ResponseWriter, r *http.Request) {
	cfg := a.Config()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	host, _ := os.Hostname()
	p := a.proxy.Load()
	stats := map[string]int64{"requests": 0, "errors": 0, "live": 0}
	var rules []map[string]any
	if p != nil {
		stats["requests"] = p.reqs.Load()
		stats["errors"] = p.errs.Load()
		stats["live"] = p.live.Load()
		for _, cr := range p.rules {
			rules = append(rules, map[string]any{
				"name": cr.cfg.Name, "hosts": cr.cfg.Hosts,
				"path": cr.path, "target": cr.cfg.Target,
			})
		}
	}

	var ddnsStatus DDNSStatus
	if m := a.ddns.Load(); m != nil {
		ddnsStatus = m.Snapshot()
	}

	certInfo := map[string]any{}
	if a.certs != nil {
		certInfo = a.certs.Info()
	}

	var fwd FirewallState
	if a.forward != nil {
		fwd = a.forward.Snapshot()
	}
	var acmeSt ACMEStatus
	if am := a.acme.Load(); am != nil {
		acmeSt = am.Snapshot()
	}

	a.mu.Lock()
	needRestart := a.needRestart
	a.mu.Unlock()

	writeJSON(w, 200, map[string]any{
		"version":     version,
		"uptimeSec":   int64(time.Since(a.started).Seconds()),
		"hostname":    host,
		"listen":      cfg.Listen,
		"adminListen": cfg.Admin.Listen,
		"tls":         cfg.TLS.Enable,
		"tlsInfo":     certInfo,
		"rules":       rules,
		"security": map[string]any{
			"requireDomain": cfg.Security.RequireDomain,
			"allowLoopback": cfg.Security.AllowLoopback,
		},
		"redirect":    cfg.TLS.Redirect,
		"extraHosts":  cfg.Security.ExtraHosts,
		"ddns":        ddnsStatus,
		"forward":     fwd,
		"acme":        acmeSt,
		"mem": memInfo{
			HeapMB:     round1(float64(ms.HeapAlloc) / (1 << 20)),
			SysMB:      round1(float64(ms.Sys) / (1 << 20)),
			RSSMB:      round1(readRSSMB()),
			Goroutines: runtime.NumGoroutine(),
		},
		"stats":       stats,
		"needRestart": needRestart,
	})
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}

func readRSSMB() float64 {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(data))
	if len(f) < 2 {
		return 0
	}
	pages, err := strconv.ParseFloat(f[1], 64)
	if err != nil {
		return 0
	}
	return pages * float64(os.Getpagesize()) / (1 << 20)
}

func (a *App) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.mu.Lock()
		cfg := a.cfg
		need := a.needRestart
		a.mu.Unlock()
		writeJSON(w, 200, map[string]any{"config": cfg, "needRestart": need})
	case http.MethodPost:
		var next Config
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&next); err != nil {
			writeJSON(w, 400, map[string]any{"error": "配置格式错误: " + err.Error()})
			return
		}
		if err := a.ApplyConfig(&next, true); err != nil {
			writeJSON(w, 400, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	default:
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
	}
}

// handleConfigExport 下载当前配置（JSON 附件）。文件含 AccessKey 等敏感信息，
// 响应头里提醒，前端 UI 也会说明。
func (a *App) handleConfigExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	a.mu.Lock()
	cfg := a.cfg
	a.mu.Unlock()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	name := fmt.Sprintf("lightproxy-config-%s.json", time.Now().Format("20060102-150405"))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Write(data)
}

// handleConfigImport 接受导出的配置文件并热应用。
// 兼容两种载荷：纯配置 JSON，或 {"config": {...}} 包裹（即面板 /api/config 的原样回传）。
func (a *App) handleConfigImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&raw); err != nil {
		writeJSON(w, 400, map[string]any{"error": "配置文件格式错误: " + err.Error()})
		return
	}
	body, ok := raw["config"]
	if !ok {
		body, _ = json.Marshal(raw)
	}
	var next Config
	if err := json.Unmarshal(body, &next); err != nil {
		writeJSON(w, 400, map[string]any{"error": "配置内容无法解析: " + err.Error()})
		return
	}
	if err := a.ApplyConfig(&next, true); err != nil {
		writeJSON(w, 400, map[string]any{"error": "配置校验失败: " + err.Error()})
		return
	}
	a.logs.Infof("已导入配置文件并热应用")
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleDDNSRun(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	m := a.ddns.Load()
	if m == nil {
		writeJSON(w, 400, map[string]any{"error": "DDNS 未启用"})
		return
	}
	err := m.RunNow()
	resp := map[string]any{"ok": err == nil, "status": m.Snapshot()}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSON(w, 200, resp)
}

func (a *App) handleDDNSTest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccessKeyID     string `json:"accessKeyId"`
		AccessKeySecret string `json:"accessKeySecret"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body)

	cfg := a.Config().DDNS
	if body.AccessKeyID != "" {
		cfg.AccessKey = strings.TrimSpace(body.AccessKeyID)
		cfg.SecretKey = strings.TrimSpace(body.AccessKeySecret)
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "请先填写 AccessKey ID 与 Secret"})
		return
	}
	c := newAliyunClient(cfg.AccessKey, cfg.SecretKey, cfg.Insecure)
	n, err := c.TestCredentials()
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "domains": n})
}

func (a *App) handleDDNSIP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IPMode    string   `json:"ipMode"`
		Interface string   `json:"interface"`
		IPSources []string `json:"ipSources"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&body)

	cfg := a.Config().DDNS
	if body.IPMode != "" {
		cfg.IPMode = body.IPMode
	}
	if body.Interface != "" {
		cfg.Interface = body.Interface
	}
	if len(body.IPSources) > 0 {
		cfg.IPSources = body.IPSources
	}
	m := NewDDNSManager(cfg, a.logs)

	v4, e4 := m.detect(4)
	v6, e6 := m.detect(6)
	resp := map[string]any{"ipv4": v4, "ipv6": v6}
	if e4 != nil {
		resp["error4"] = e4.Error()
	}
	if e6 != nil {
		resp["error6"] = e6.Error()
	}
	writeJSON(w, 200, resp)
}

func (a *App) handleReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	if a.certs == nil {
		writeJSON(w, 400, map[string]any{"error": "当前未启用 HTTPS，无需重载证书"})
		return
	}
	if err := a.certs.reload(); err != nil {
		writeJSON(w, 400, map[string]any{"error": err.Error()})
		return
	}
	info := a.certs.Info()
	writeJSON(w, 200, map[string]any{"ok": true, "names": info["names"], "info": info})
}

func (a *App) handleLogs(w http.ResponseWriter, r *http.Request) {
	n, _ := strconv.Atoi(r.URL.Query().Get("n"))
	if n <= 0 {
		n = 200
	}
	writeJSON(w, 200, map[string]any{"lines": a.logs.Tail(n)})
}

// ---------------- 端口转发 ----------------

func (a *App) handleForwardApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	if a.forward == nil {
		writeJSON(w, 500, map[string]any{"error": "端口转发模块未就绪"})
		return
	}
	if err := a.applyForward(a.Config()); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error(), "state": a.forward.Snapshot()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "state": a.forward.Snapshot()})
}

func (a *App) handleForwardClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	if a.forward == nil {
		writeJSON(w, 500, map[string]any{"error": "端口转发模块未就绪"})
		return
	}
	cfg := a.Config()
	fc := cfg.Forward
	fc.Enable = false
	if err := a.forward.Apply(fc); err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	a.logs.Infof("已清空端口转发规则")
	writeJSON(w, 200, map[string]any{"ok": true, "state": a.forward.Snapshot()})
}

// ---------------- 自动证书 ----------------

func (a *App) handleACMEIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	am := a.acme.Load()
	if am == nil || !a.Config().ACME.Enable {
		writeJSON(w, 400, map[string]any{"error": "请先在页面上启用自动证书并保存"})
		return
	}
	go func() {
		if err := am.IssueNow(); err != nil {
			a.logs.Errorf("手动签发证书失败: %v", err)
		}
	}()
	writeJSON(w, 200, map[string]any{"ok": true, "message": "已开始签发，进度会显示在面板上"})
}

// handleACMETest 在真正签发前做一次体检：AccessKey 能不能用、
// 每个域名能不能在账号里找到对应 zone。多数签发失败都出在这两步。
func (a *App) handleACMETest(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccessKeyID     string   `json:"accessKeyId"`
		AccessKeySecret string   `json:"accessKeySecret"`
		Domains         []string `json:"domains"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body)

	cur := a.Config()
	cfg := mergeACMECreds(cur.ACME, cur.DDNS)
	ak := strings.TrimSpace(body.AccessKeyID)
	sk := strings.TrimSpace(body.AccessKeySecret)
	if ak == "" {
		ak, sk = cfg.AccessKey, cfg.SecretKey
	}
	if ak == "" || sk == "" {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "请先填写阿里云 AccessKey"})
		return
	}
	domains := body.Domains
	if len(domains) == 0 {
		domains = cfg.Domains
	}

	c := newAliyunClient(ak, sk, cfg.Insecure)
	zones, err := c.ListDomains()
	if err != nil {
		writeJSON(w, 200, map[string]any{"ok": false, "error": "读取域名失败：" + err.Error()})
		return
	}

	type checkRow struct {
		Domain string `json:"domain"`
		Zone   string `json:"zone"`
		RR     string `json:"rr"`
		OK     bool   `json:"ok"`
	}
	var rows []checkRow
	allOK := len(domains) > 0
	for _, d := range domains {
		fqdn := challengeFQDN(d)
		zone, rr, ok := pickZone(fqdn, zones)
		if !ok {
			allOK = false
		}
		rows = append(rows, checkRow{Domain: d, Zone: zone, RR: rr, OK: ok})
	}
	writeJSON(w, 200, map[string]any{"ok": allOK, "zones": zones, "rows": rows})
}


func (a *App) handleRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]any{"error": "method not allowed"})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "message": "正在重启…"})
	a.logs.Infof("收到重启请求")
	restartProcess()
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
