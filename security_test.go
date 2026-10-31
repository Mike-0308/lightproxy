package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newReq(host, remote string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	r.Host = host
	r.RemoteAddr = remote
	return r
}

func TestProxyDeniesIPHost(t *testing.T) {
	c := &Config{Security: SecurityConfig{RequireDomain: true}}
	c.Proxy = []Rule{{Hosts: []string{"nas.example.com"}, Target: "http://192.168.1.10:5000"}}

	cases := []struct {
		name, host, remote string
		deny               bool
	}{
		{"外网 IPv4 直连", "203.0.113.7:8443", "198.51.100.9:1234", true},
		{"外网 IPv6 直连", "[2408:8274:1234::5]:8443", "2408:8274:abcd::9:1234", true},
		{"外网域名访问", "nas.example.com:8443", "198.51.100.9:1234", false},
		{"未知域名不在这里拦", "other.example.com", "198.51.100.9:1234", false},
		// 内网放行：不管 Host 是内网 IP、公网 IP 还是 IPv6
		{"内网用内网 IP 访问", "192.168.1.1:8443", "192.168.1.50:5000", false},
		{"内网用公网 IP 作 Host", "203.0.113.7:8443", "192.168.1.50:5000", false},
		{"内网 IPv6 来源", "[2408:8274:1234::5]:8443", "fe80::1234:5678", false},
		{"内网 ULA 来源", "192.168.1.1:8443", "fd00::9:5000", false},
	}
	for _, c2 := range cases {
		got := c.allowProxyRequest(newReq(c2.host, c2.remote)) != ""
		if got != c2.deny {
			t.Errorf("%s: 期望拦截=%v，实际=%v", c2.name, c2.deny, got)
		}
	}
}

func TestProxyLoopbackAlwaysAllowed(t *testing.T) {
	c := &Config{Security: SecurityConfig{RequireDomain: true}}
	if reason := c.allowProxyRequest(newReq("127.0.0.1:8080", "127.0.0.1:50000")); reason != "" {
		t.Errorf("本机回环应始终放行，实际: %s", reason)
	}
	if reason := c.allowProxyRequest(newReq("127.0.0.1:8080", "[::1]:50000")); reason != "" {
		t.Errorf("IPv6 回环应始终放行，实际: %s", reason)
	}
}

func TestAdminBehindProxy(t *testing.T) {
	c := &Config{Security: SecurityConfig{RequireDomain: true}}
	c.Proxy = []Rule{{Hosts: []string{"lp.example.com"}, Target: "http://127.0.0.1:8081"}}

	// 反代转发过来（来源是本机回环）：内网来源始终放行
	r := newReq("127.0.0.1:8081", "127.0.0.1:50000")
	r.Header.Set("X-Forwarded-Host", "lp.example.com")
	if reason := c.allowAdminRequest(r); reason != "" {
		t.Errorf("经反代访问面板应放行，实际: %s", reason)
	}

	// 内网 IP 直连面板：放行（内网没有安全风险）
	r2 := newReq("192.168.1.1:8081", "192.168.1.50:50000")
	if reason := c.allowAdminRequest(r2); reason != "" {
		t.Errorf("内网 IP 直连面板应放行，实际: %s", reason)
	}

	// 外网来源（假设面板端口被误开到外网）：
	// 域名放行、未知域名和 IP 都拦
	ext := "198.51.100.9:50000"
	r4 := newReq("lp.example.com:8081", ext)
	if reason := c.allowAdminRequest(r4); reason != "" {
		t.Errorf("外网用已配置域名访问面板应放行，实际: %s", reason)
	}
	r5 := newReq("evil.example.org:8081", ext)
	if reason := c.allowAdminRequest(r5); reason == "" {
		t.Error("外网未知域名应被拦截")
	}
	r6 := newReq("192.168.1.1:8081", ext)
	if reason := c.allowAdminRequest(r6); reason == "" {
		t.Error("外网 IP 直连面板应被拦截")
	}
}

func TestKnownHostWildcard(t *testing.T) {
	c := &Config{}
	c.Proxy = []Rule{{Hosts: []string{"*.example.com", "example.com"}}}
	if !c.knownHost("a.example.com") {
		t.Error("泛域名应匹配子域名")
	}
	if c.knownHost("a.b.example.com.evil.com") {
		t.Error("后缀伪造不应匹配")
	}
	if !c.knownHost("example.com") {
		t.Error("主域名应匹配")
	}
}

func TestRequireDomainOffByDefault(t *testing.T) {
	c := &Config{}
	if reason := c.allowProxyRequest(newReq("203.0.113.7:8443", "198.51.100.9:1234")); reason != "" {
		t.Errorf("默认开关关闭时不应拦截，实际: %s", reason)
	}
}

func TestRedirectKeepsPublicPort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.PublicPort = 8443
	a := &App{cfg: cfg}

	req := newReq("nas.example.com:8080", "198.51.100.9:1234")
	req.URL.Path = "/photos"
	req.URL.RawQuery = "a=1"
	rec := httptest.NewRecorder()
	a.redirectHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("期望 301，得到 %d", rec.Code)
	}
	if want := "https://nas.example.com:8443/photos?a=1"; rec.Header().Get("Location") != want {
		t.Errorf("Location 期望 %s，得到 %s", want, rec.Header().Get("Location"))
	}

	// 443 不带端口
	cfg.TLS.PublicPort = 443
	rec2 := httptest.NewRecorder()
	a.redirectHandler().ServeHTTP(rec2, newReq("nas.example.com:8080", "198.51.100.9:1234"))
	if want := "https://nas.example.com/"; rec2.Header().Get("Location") != want {
		t.Errorf("Location 期望 %s，得到 %s", want, rec2.Header().Get("Location"))
	}
}

// Host 是 IP 字面量时不跳转（内网 IP 直连的 http 服务不能被强行拽到 https），
// 交回反代按正常规则处理；只有域名访问才 301。
func TestRedirectSkipsIPHost(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.PublicPort = 8443
	a := &App{cfg: cfg}
	a.proxy.Store(&Proxy{})

	for _, host := range []string{
		"192.168.10.1",           // IPv4 不带端口
		"192.168.10.1:80",        // IPv4 带端口
		"203.0.113.7",            // 公网 IPv4 也不跳转（拦不拦由访问控制管）
		"[fd00::9]:80",           // IPv6 ULA
		"[2408:8274:abcd::9]:80", // 公网 IPv6
	} {
		rec := httptest.NewRecorder()
		a.redirectHandler().ServeHTTP(rec, newReq(host, "192.168.10.50:5000"))
		if rec.Code == http.StatusMovedPermanently || rec.Code == http.StatusFound {
			t.Errorf("IP 访问 %s 不应跳转，实际 %d", host, rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("IP 访问 %s 不应带 Location，实际 %s", host, loc)
		}
	}

	// 域名访问仍然 301 到 HTTPS（带公网端口）
	rec := httptest.NewRecorder()
	a.redirectHandler().ServeHTTP(rec, newReq("nas.example.com:80", "192.168.10.50:5000"))
	if rec.Code != http.StatusMovedPermanently {
		t.Fatalf("域名访问期望 301，得到 %d", rec.Code)
	}
	if want := "https://nas.example.com:8443/"; rec.Header().Get("Location") != want {
		t.Errorf("Location 期望 %s，得到 %s", want, rec.Header().Get("Location"))
	}
}

// ---------------- 安全入口 ----------------

func TestNormalizeEntryPath(t *testing.T) {
	ok := map[string]string{
		"":         "",
		"/":        "",
		"xxxx":     "/xxxx",
		"/xxxx/":   "/xxxx",
		" /a/b ":   "/a/b",
		"/a_b-c.d": "/a_b-c.d",
		"\\entry":  "/entry",
	}
	for in, want := range ok {
		got, err := normalizeEntryPath(in)
		if err != nil {
			t.Errorf("%q 应该合法，却报错: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("%q 规范化期望 %q，得到 %q", in, want, got)
		}
	}

	bad := []string{
		"/a b",     // 空格
		"/a?b",     // 会被当成查询串
		"/a#b",     // 锚点
		"/a%20b",   // 转义
		"/a/b/c/d", // 超过 3 层
		"/a//b",    // 空路径段
		"/" + string(make([]byte, 0)) + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // 太长
	}
	for _, in := range bad {
		if _, err := normalizeEntryPath(in); err == nil {
			t.Errorf("%q 应该被拒绝", in)
		}
	}
}

func entryCfg(entry string) *Config {
	c := &Config{Security: SecurityConfig{EntryPath: entry}}
	c.Admin.User = "admin"
	c.Admin.Pass = "secret"
	return c
}

func TestEntrySwitch(t *testing.T) {
	c := entryCfg("/entry")

	cases := []struct {
		name, path, remote string
		wantPath           string
		wantOK             bool
	}{
		{"外网访问根路径", "/", "198.51.100.9:1234", "/", false},
		{"外网访问入口", "/entry", "198.51.100.9:1234", "/", true},
		{"外网访问入口带斜杠", "/entry/", "198.51.100.9:1234", "/", true},
		{"外网访问入口内页面", "/entry/vnc/", "198.51.100.9:1234", "/vnc/", true},
		{"前缀相同但不是一个入口", "/entryx", "198.51.100.9:1234", "/entryx", false},
		{"内网不受限", "/", "192.168.31.50:5000", "/", true},
		{"本机不受限", "/api/status", "127.0.0.1:5000", "/api/status", true},
	}
	for _, c2 := range cases {
		r := newReq("lightproxy.example.com:8686", c2.remote)
		r.URL.Path = c2.path
		path, ok := c.entrySwitch(r)
		if ok != c2.wantOK || path != c2.wantPath {
			t.Errorf("%s: 期望 (%q,%v)，得到 (%q,%v)", c2.name, c2.wantPath, c2.wantOK, path, ok)
		}
	}

	// 入口说明关闭时一律放行
	off := entryCfg("")
	r := newReq("lightproxy.example.com:8686", "198.51.100.9:1234")
	if path, ok := off.entrySwitch(r); !ok || path != "/" {
		t.Errorf("未启用安全入口时应放行，得到 (%q,%v)", path, ok)
	}
}

// 从入口进来的浏览器会带票据，页面里的绝对路径资源要能放行。
func TestEntryCookie(t *testing.T) {
	c := entryCfg("/entry")
	ext := "198.51.100.9:1234"

	r := newReq("lightproxy.example.com:8686", ext)
	r.URL.Path = "/static/app.js"
	if _, ok := c.entrySwitch(r); ok {
		t.Fatal("没有票据时 /static 应被拦")
	}

	r2 := newReq("lightproxy.example.com:8686", ext)
	r2.URL.Path = "/static/app.js"
	r2.AddCookie(&http.Cookie{Name: entryCookieName, Value: c.entryToken()})
	if path, ok := c.entrySwitch(r2); !ok || path != "/static/app.js" {
		t.Errorf("带票据应放行且不改路径，得到 (%q,%v)", path, ok)
	}

	// 伪造的票据不认
	r3 := newReq("lightproxy.example.com:8686", ext)
	r3.URL.Path = "/static/app.js"
	r3.AddCookie(&http.Cookie{Name: entryCookieName, Value: "deadbeef"})
	if _, ok := c.entrySwitch(r3); ok {
		t.Error("伪造票据不应放行")
	}

	// 改了入口路径，旧票据自动失效
	c2 := entryCfg("/other")
	r4 := newReq("lightproxy.example.com:8686", ext)
	r4.URL.Path = "/static/app.js"
	r4.AddCookie(&http.Cookie{Name: entryCookieName, Value: c.entryToken()})
	if _, ok := c2.entrySwitch(r4); ok {
		t.Error("改了入口后旧票据应失效")
	}
}

// 走入口时种票据，方便入口内的应用继续加载自己的静态资源。
func TestEntrySetsCookie(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Security.EntryPath = "/entry"
	a := &App{cfg: cfg}
	a.proxy.Store(&Proxy{})

	req := newReq("lightproxy.example.com:8686", "198.51.100.9:1234")
	req.URL.Path = "/entry"
	rec := httptest.NewRecorder()
	a.proxyHandler().ServeHTTP(rec, req)

	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("走安全入口应种上票据 cookie")
	}
	// 根路径不该种
	rec2 := httptest.NewRecorder()
	a.proxyHandler().ServeHTTP(rec2, newReq("lightproxy.example.com:8686", "198.51.100.9:1234"))
	if len(rec2.Result().Cookies()) != 0 {
		t.Error("被拦下的请求不该种 cookie")
	}
}

// http:// 打到 HTTPS 端口时，回 307 让浏览器自己换到 https，端口保持不变。
func TestPlainRequestOnTLSPortRedirects(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TLS.Enable = true
	cfg.TLS.PublicPort = 8686
	a := &App{cfg: cfg}
	a.proxy.Store(&Proxy{})

	req := newReq("lightproxy.example.com:8686", "198.51.100.9:1234")
	req.URL.Path = "/nas"
	req.URL.RawQuery = "a=1"
	rec := httptest.NewRecorder()
	a.plainOnTLSHandler().ServeHTTP(rec, req)

	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("期望 307，得到 %d", rec.Code)
	}
	if want := "https://lightproxy.example.com:8686/nas?a=1"; rec.Header().Get("Location") != want {
		t.Errorf("Location 期望 %s，得到 %s", want, rec.Header().Get("Location"))
	}

	// 不带端口（走 443 映射）时用配置里的公网端口
	cfg.TLS.PublicPort = 443
	rec2 := httptest.NewRecorder()
	a.plainOnTLSHandler().ServeHTTP(rec2, newReq("lightproxy.example.com", "198.51.100.9:1234"))
	if want := "https://lightproxy.example.com/"; rec2.Header().Get("Location") != want {
		t.Errorf("Location 期望 %s，得到 %s", want, rec2.Header().Get("Location"))
	}

	// Host 是 IP 时不跳转（证书对不上，跳过去只会报错），按普通请求处理
	rec3 := httptest.NewRecorder()
	a.plainOnTLSHandler().ServeHTTP(rec3, newReq("192.168.31.1:16666", "192.168.31.50:5000"))
	if rec3.Header().Get("Location") != "" {
		t.Errorf("IP 访问不应跳转，得到 %s", rec3.Header().Get("Location"))
	}

	// 开了安全入口后，明文请求没带入口路径也要 404，且不泄露跳转地址
	cfg.Security.EntryPath = "/entry"
	rec4 := httptest.NewRecorder()
	a.plainOnTLSHandler().ServeHTTP(rec4, newReq("lightproxy.example.com:8686", "198.51.100.9:1234"))
	if rec4.Code != http.StatusNotFound {
		t.Errorf("没走入入口应 404，得到 %d", rec4.Code)
	}
	rec5 := httptest.NewRecorder()
	req5 := newReq("lightproxy.example.com:8686", "198.51.100.9:1234")
	req5.URL.Path = "/entry/nas"
	a.plainOnTLSHandler().ServeHTTP(rec5, req5)
	if want := "https://lightproxy.example.com:8686/entry/nas"; rec5.Header().Get("Location") != want {
		t.Errorf("入口跳转 Location 期望 %s，得到 %s", want, rec5.Header().Get("Location"))
	}
}
