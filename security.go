package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// 「只允许用域名访问」的实现。
//
// 路由器自带 IPv6 防火墙只能挡端口，挡不住「IP:端口 直接访问」——
// 只要端口放行了，任何人拿 IP 就能打开面板。这里在应用层再拦一道：
// 凡是 Host 是 IP 字面量的请求一律 403，只认域名（并且域名还得是配置里认识的）。

// requestHost 取请求的 Host，去掉端口与结尾点，转小写。
func requestHost(r *http.Request) string {
	h := strings.ToLower(r.Host)
	if hp, _, err := net.SplitHostPort(h); err == nil && hp != "" {
		h = hp
	}
	return strings.TrimSuffix(h, ".")
}

// isIPHost 判断 Host 是不是 IP 字面量（IPv4 或带方括号的 IPv6）。
func isIPHost(h string) bool {
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return net.ParseIP(h) != nil
}

// isLANAddr 判断请求来源是不是内网：RFC1918 私网、本机回环、链路本地（fe80::/10）、
// IPv6 ULA（fc00::/7）。内网访问没有安全风险，「只允许域名访问」只拦外网。
func isLANAddr(remoteAddr string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

// knownHost 判断域名是否是配置里出现过的（反代规则域名或额外放行域名）。
func (c *Config) knownHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return false
	}
	for _, h := range c.Security.ExtraHosts {
		if h == host {
			return true
		}
	}
	for _, r := range c.Proxy {
		if r.Disable {
			continue
		}
		for _, h := range r.Hosts {
			if h == host {
				return true
			}
			// *.example.com 泛域名匹配
			if strings.HasPrefix(h, "*.") && strings.HasSuffix(host, h[1:]) && host != h[2:] {
				return true
			}
		}
	}
	return false
}

// allowProxyRequest 决定反代请求是否放行。返回的字符串是拒绝原因，空表示放行。
// 规则：内网/本机来源始终放行；外网来源时 Host 不能是 IP，必须是域名。
func (c *Config) allowProxyRequest(r *http.Request) string {
	if !c.Security.RequireDomain {
		return ""
	}
	host := requestHost(r)
	if isIPHost(host) && !isLANAddr(r.RemoteAddr) {
		return "已开启「只允许域名访问」：外网不能用 IP 直接访问，请使用域名"
	}
	return ""
}

// allowAdminRequest 决定管理面板请求是否放行。
// 面板通常藏在反代后面（上游 127.0.0.1:8081），此时 Host 被改写成了 IP。
// 内网/本机来源始终放行（面板端口不开到外网，能直接连上来的只有内网和反代自身）。
func (c *Config) allowAdminRequest(r *http.Request) string {
	if !c.Security.RequireDomain {
		return ""
	}
	if isLANAddr(r.RemoteAddr) {
		return ""
	}
	host := requestHost(r)
	if !isIPHost(host) {
		if c.knownHost(host) {
			return ""
		}
		return "该域名不在允许列表里，请用反代规则里配置的域名访问"
	}
	// 公网来源且 Host 是 IP：看 X-Forwarded-Host 里有没有已配置的域名
	if fh := strings.ToLower(r.Header.Get("X-Forwarded-Host")); fh != "" {
		if hp, _, err := net.SplitHostPort(fh); err == nil && hp != "" {
			fh = hp
		}
		fh = strings.TrimSuffix(fh, ".")
		if !isIPHost(fh) && c.knownHost(fh) {
			return ""
		}
	}
	return "已开启「只允许域名访问」：外网请通过反向代理的域名访问面板"
}

// denyHost 统一输出 403，并说明原因，方便排查是不是域名没配对。
func denyHost(w http.ResponseWriter, r *http.Request, reason string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	host := requestHost(r)
	fmt.Fprintf(w, "403 拒绝访问\n\n%s\n\n当前 Host: %s\n", reason, host)
}

// ---------------- 安全入口 ----------------
//
// 只允许域名访问解决了「IP 直连」，但域名本身是公开的（证书透明日志里就有），
// 扫描器拿域名逐端口扫一样能撞到反代。安全入口再加一道：外网必须走
// https://域名:端口/<入口>，直接访问域名根路径一律 404，看起来就像没服务。
//
// 内网/本机来源不受限制——在家用 IP 或内网域名直接访问仍然照常，不会把自己锁在外面。

const entryCookieName = "lp_entry"

// entrySwitch 判断请求能否通过安全入口，并返回剥离入口前缀后的路径。
// ok=false 表示按「没有这个服务」处理（404）。
func (c *Config) entrySwitch(r *http.Request) (path string, ok bool) {
	p := r.URL.Path
	entry := c.Security.EntryPath
	if entry == "" {
		return p, true
	}
	// 带上了入口路径：不管内外网都剥掉前缀，这样把外网链接贴到内网也能直接用
	if p == entry || p == entry+"/" {
		return "/", true
	}
	if strings.HasPrefix(p, entry+"/") {
		return p[len(entry):], true
	}
	// 没带入口：内网与本机照常访问，免得在家把自己锁在外面
	if isLANAddr(r.RemoteAddr) {
		return p, true
	}
	// 从入口进来的浏览器会拿到一张票据，之后页面里的 /static、/api 之类的
	// 绝对路径请求靠它放行，否则入口内的应用会白屏。
	if c.entryCookieOK(r) {
		return p, true
	}
	return p, false
}

// entryToken 由入口路径与面板账号派生，改入口或改密码后旧票据自动失效。
func (c *Config) entryToken() string {
	if c.Security.EntryPath == "" {
		return ""
	}
	sum := sha256.Sum256([]byte("lightproxy-entry\x00" + c.Security.EntryPath + "\x00" + c.Admin.User + "\x00" + c.Admin.Pass))
	return hex.EncodeToString(sum[:16])
}

func (c *Config) entryCookieOK(r *http.Request) bool {
	want := c.entryToken()
	if want == "" {
		return false
	}
	ck, err := r.Cookie(entryCookieName)
	if err != nil || ck.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(ck.Value), []byte(want)) == 1
}

// markEntryCookie 在真正走进口的请求上种票据，有效期 7 天。
func (c *Config) markEntryCookie(w http.ResponseWriter, r *http.Request) {
	if c.Security.EntryPath == "" || c.entryCookieOK(r) {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     entryCookieName,
		Value:    c.entryToken(),
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
		MaxAge:   7 * 24 * 3600,
	})
}

// denyEntry 对没走入入口的请求回一个最普通的 404，不暴露反向代理的存在。
func denyEntry(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, "404 page not found\n")
}
