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
		"192.168.10.1",          // IPv4 不带端口
		"192.168.10.1:80",       // IPv4 带端口
		"203.0.113.7",           // 公网 IPv4 也不跳转（拦不拦由访问控制管）
		"[fd00::9]:80",          // IPv6 ULA
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
