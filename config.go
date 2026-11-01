package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config 是全部配置。整体序列化为一个 JSON 文件，路由器上手工改也很方便。
type Config struct {
	Listen   string         `json:"listen"`
	Admin    AdminConfig    `json:"admin"`
	TLS      TLSConfig      `json:"tls"`
	Security SecurityConfig `json:"security"`
	Proxy    []Rule         `json:"proxy"`
	DDNS     DDNSConfig     `json:"ddns"`
	ACME     ACMEConfig     `json:"acme"`
	Forward  ForwardConfig  `json:"forward"`
	Runtime  RuntimeConfig  `json:"runtime"`
	WOL      WOLConfig      `json:"wol"`
	Term     TermConfig     `json:"term"`

	// baseDir 是配置文件所在目录（不序列化），用来推导默认证书目录：
	// 装到 /data/lightproxy 时，证书自动落在 /data/lightproxy/certs。
	baseDir string
	// certDirAuto 表示证书目录是推导出来的（用户没手填），
	// 落盘和导出时不写死路径，换设备/换安装目录后自动跟过去。
	certDirAuto bool
}

type AdminConfig struct {
	Listen string `json:"listen"`
	User   string `json:"user"`
	Pass   string `json:"pass"`
}

// SecurityConfig 是「只允许用域名访问」相关的开关。
// 路由器开着 IPv6 防火墙时，光靠防火墙只能挡端口，挡不住「IP:端口 直接访问」；
// 打开 RequireDomain 后，外网来源的 IP 直连一律拒绝，只认域名；
// 内网（RFC1918/链路本地/ULA）与本机回环始终放行。
type SecurityConfig struct {
	RequireDomain bool `json:"requireDomain"`
	// AllowLoopback 已废弃（内网与本机回环始终放行），仅为兼容旧配置文件保留。
	AllowLoopback bool     `json:"allowLoopback,omitempty"`
	ExtraHosts    []string `json:"extraHosts,omitempty"`
	// EntryPath 是「安全入口」路径，例如 /xxxx。
	// 填了以后外网必须带上这个前缀才能访问，直接访问域名根路径一律 404；
	// 内网来源不受影响，免得自己在家里也被挡住。
	EntryPath string `json:"entryPath,omitempty"`
	// KnockForward 开启「转发端口敲门放行」：用户态转发的端口不再对任何人响应，
	// 只有浏览器先通过一次安全入口的来源网络才放行（按来源 /64 记录，IPv4 按单个
	// IP），名单外的连接接受后立即断开，扫描器识别不出端口后面的服务。
	// 依赖 EntryPath（没配入口路径时此项不生效），有效期与入口票据一致（7 天）。
	KnockForward bool `json:"knockForward,omitempty"`
}

// knockRequired 返回转发端口是否需要敲门放行（敲门开关依赖安全入口）。
func (c *Config) knockRequired() bool {
	return c.Security.KnockForward && c.Security.EntryPath != ""
}

type TLSConfig struct {
	Enable     bool   `json:"enable"`
	Cert       string `json:"cert"`
	Key        string `json:"key"`
	CertDir    string `json:"certDir"`
	HTTPListen string `json:"httpListen"`
	// Redirect 打开后，HTTP 监听上的请求统一 301 到 HTTPS。
	Redirect bool `json:"redirect"`
	// PublicPort 是外网看到的 HTTPS 端口（非 443 时跳转要带上）。
	PublicPort int `json:"publicPort,omitempty"`
}

type Rule struct {
	Name         string            `json:"name"`
	Disable      bool              `json:"disable,omitempty"`
	Hosts        []string          `json:"hosts"`
	Path         string            `json:"path"`
	Target       string            `json:"target"`
	PreserveHost bool              `json:"preserveHost,omitempty"`
	Insecure     bool              `json:"insecure,omitempty"`
	Headers      map[string]string `json:"headers,omitempty"`
	DelHeaders   []string          `json:"delHeaders,omitempty"`
}

type DDNSConfig struct {
	Enable    bool        `json:"enable"`
	Provider  string      `json:"provider"`
	AccessKey string      `json:"accessKeyId"`
	SecretKey string      `json:"accessKeySecret"`
	Records   []DNSRecord `json:"records"`
	Interval  int         `json:"interval"`
	IPMode    string      `json:"ipMode"`
	Interface string      `json:"interface"`
	IPSources []string    `json:"ipSources"`
	TTL       int         `json:"ttl"`
	Insecure  bool        `json:"insecure,omitempty"`
}

type DNSRecord struct {
	Domain  string `json:"domain"`
	RR      string `json:"rr"`
	Type    string `json:"type"`
	TTL     int    `json:"ttl,omitempty"`
	Disable bool   `json:"disable,omitempty"`
}

type RuntimeConfig struct {
	MemLimitMB int    `json:"memLimitMB"`
	GCPercent  int    `json:"gcPercent,omitempty"`
	AccessLog  bool   `json:"accessLog"`
	LogFile    string `json:"logFile"`
}

// ACMEConfig 是自动申请证书的配置。走 DNS-01，复用阿里云解析，
// 不占用 80 端口，也不会和反向代理抢域名验证路径。
type ACMEConfig struct {
	Enable    bool     `json:"enable"`
	Email     string   `json:"email"`
	CA        string   `json:"ca"`
	Domains   []string `json:"domains"`
	CertDir   string   `json:"certDir"`
	KeyType   string   `json:"keyType"`
	RenewDays int      `json:"renewDays"`
	AccessKey string   `json:"accessKeyId,omitempty"`
	SecretKey string   `json:"accessKeySecret,omitempty"`
	Insecure  bool     `json:"insecure,omitempty"`
}

type ForwardConfig struct {
	Enable  bool          `json:"enable"`
	Backend string        `json:"backend"`
	Hairpin bool          `json:"hairpin,omitempty"`
	Rules   []ForwardRule `json:"rules"`
	// V6Forward 开启「IPv6 用户态转发」：外网 IPv6 → 内网 IPv4 的端口映射走
	// 进程内裸 TCP/UDP 转发（内核 NAT66 不支持跨协议族）。缺省视为开启；
	// 关掉后只有 IPv4 DNAT 生效（无公网 IPv4 的家宽外网就进不来了）。
	V6Forward *bool `json:"v6Forward,omitempty"`
	// LocalPorts 由程序在运行时填充（反代监听端口 + HTTP 跳转端口），不写进配置文件。
	// 开启端口转发后会一并写进 INPUT 放行，这样路由器自带防火墙开着也能从外网访问到反代；
	// 管理面板端口不在其中，永远不对外放行。
	LocalPorts []int `json:"-"`
	// Occupied 由程序在运行时填充：本机已被占用的端口（反代/跳转/面板），
	// 转发规则撞上这些端口时整条跳过，避免劫持自己的服务。不写进配置文件。
	Occupied []int `json:"-"`
}

// V6On 返回是否启用 IPv6 用户态转发（缺省开启）。
func (fc *ForwardConfig) V6On() bool {
	return fc.V6Forward == nil || *fc.V6Forward
}

// ForwardRule 是一条「外网端口 → 内网主机」的内核 DNAT 规则。
// 转发在内核完成，不占用用户态内存，并发再高也只是消耗连接跟踪表。
type ForwardRule struct {
	Name    string `json:"name"`
	Disable bool   `json:"disable,omitempty"`
	Proto   string `json:"proto"`
	Port    int    `json:"port"`
	ToHost  string `json:"toHost"`
	ToPort  int    `json:"toPort"`
	Note    string `json:"note,omitempty"`
}

func DefaultConfig() *Config {
	return &Config{
		// 默认避开 8080/8081：小米等路由器的管理后台（LuCI）在 8080，
		// 抢了端口会导致路由器 Web 端打不开。面板也换到 18080，避免和常见服务打架。
		Listen: ":16666",
		Admin: AdminConfig{
			Listen: "0.0.0.0:18080",
			User:   "admin",
			Pass:   "",
		},
		Proxy: []Rule{},
		DDNS: DDNSConfig{
			Provider:  "aliyun",
			Interval:  300,
			IPMode:    "api",
			TTL:       600,
			IPSources: []string{"http://ip.3322.net", "http://ddns.oray.com/checkip", "https://api.ipify.org"},
		},
		ACME:     ACMEConfig{CA: "letsencrypt", KeyType: "ec256", RenewDays: 30},
		Forward:  ForwardConfig{Backend: "auto"},
		Security: SecurityConfig{AllowLoopback: true},
		Runtime:  RuntimeConfig{MemLimitMB: 32, AccessLog: false},
		// 唤醒只有 UDP，没有常驻开销，默认开着。
		WOL: WOLConfig{Devices: []WOLDevice{}},
		// 终端默认也开，但限制内网来源；它等于面板后面的一个 root shell，
		// 所以 LANOnly 默认 true，要公网用必须自己关掉这一项。
		Term: TermConfig{
			Enable: true, LANOnly: true, KeepMin: 60, MaxSessions: 4,
			SSH: []SSHConn{},
		},
	}
}

// WOLConfig 是网络唤醒的设备表，只存设备信息，不存状态。
type WOLConfig struct {
	Devices []WOLDevice `json:"devices"`
}

// TermConfig 是 Web 终端配置。
type TermConfig struct {
	Enable      bool      `json:"enable"`
	LANOnly     bool      `json:"lanOnly"`
	KeepMin     int       `json:"keepMin"`     // 断开后保留会话的分钟数，0 表示断开即销毁
	MaxSessions int       `json:"maxSessions"` // 同时存在的会话上限
	Shell       string    `json:"shell"`       // 本机终端默认 shell，留空自动选
	SSH         []SSHConn `json:"ssh"`
}

// SSHConn 是一条保存下来的 SSH 连接。
// 密码与私钥口令按明文存在 config.json 里（和 AccessKey 一样），
// 文件权限 0600；不想落盘就只用私钥，不填口令。
type SSHConn struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	User     string `json:"user"`
	Auth     string `json:"auth"` // password | key
	Password string `json:"password,omitempty"`
	KeyPath  string `json:"keyPath,omitempty"`
	KeyPass  string `json:"keyPass,omitempty"`
	Insecure bool   `json:"insecure,omitempty"` // 跳过主机密钥校验（旧设备常见）
}

// setBaseFrom 记录配置文件所在目录，供 deriveCertDir 推导默认证书目录。
func (c *Config) setBaseFrom(cfgPath string) {
	dir := filepath.Dir(cfgPath)
	if dir == "" {
		dir = "."
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	c.baseDir = dir
}

// deriveCertDir 返回默认证书目录：配置目录下的 certs。
// 装到 /data/lightproxy 就是 /data/lightproxy/certs，
// 用户不用再手填路径，申请的证书和 HTTPS 加载用的是同一个目录。
func (c *Config) deriveCertDir() string {
	base := c.baseDir
	if base == "" {
		if abs, err := filepath.Abs("."); err == nil {
			base = abs
		} else {
			base = "."
		}
	}
	return filepath.Join(base, "certs")
}

// LoadConfig 读取配置；文件不存在时生成默认配置并返回 firstRun=true。
func LoadConfig(path string) (cfg *Config, firstRun bool, err error) {
	data, rerr := os.ReadFile(path)
	if rerr != nil {
		if !os.IsNotExist(rerr) {
			return nil, false, rerr
		}
		c := DefaultConfig()
		c.Admin.Pass = randomPassword()
		if werr := SaveConfig(path, c); werr != nil {
			return nil, false, werr
		}
		return c, true, nil
	}
	c := DefaultConfig()
	c.setBaseFrom(path)
	if err := json.Unmarshal(data, c); err != nil {
		return nil, false, fmt.Errorf("配置文件不是合法 JSON: %w", err)
	}
	if err := c.Normalize(); err != nil {
		return nil, false, err
	}
	return c, false, nil
}

// forPersist 返回用于落盘/导出的副本：自动推导出来的证书目录不写死，
// 换设备或换安装目录后会按新位置自动重建。
func (c *Config) forPersist() *Config {
	if !c.certDirAuto {
		return c
	}
	cp := *c
	cp.TLS.CertDir = ""
	if cp.ACME.CertDir == c.deriveCertDir() {
		cp.ACME.CertDir = ""
	}
	return &cp
}

// SaveConfig 原子写入，权限 0600（含 AccessKey 等敏感信息）。
func SaveConfig(path string, c *Config) error {
	c.setBaseFrom(path)
	if err := c.Normalize(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c.forPersist(), "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// checkListen 校验监听地址：格式形如 host:port，且端口必须是 1-65535 的数字。
// net.SplitHostPort 本身不验证端口是否为数字，":bad host" 也会被它接受。
func checkListen(addr, what string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s无效（应形如 %s）: %s", what, what, addr)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("%s的端口必须是 1-65535 的数字: %s", what, addr)
	}
	return nil
}

// Normalize 补默认值并校验，返回第一条错误。
func (c *Config) Normalize() error {
	c.Listen = strings.TrimSpace(c.Listen)
	if c.Listen == "" {
		c.Listen = ":16666"
	}
	if err := checkListen(c.Listen, "反代监听地址（应形如 :16666）"); err != nil {
		return err
	}

	c.Admin.Listen = strings.TrimSpace(c.Admin.Listen)
	if c.Admin.Listen == "" {
		c.Admin.Listen = "0.0.0.0:18080"
	}
	if err := checkListen(c.Admin.Listen, "管理面板监听地址（应形如 0.0.0.0:18080）"); err != nil {
		return err
	}
	if c.Admin.User == "" {
		c.Admin.User = "admin"
	}

	// 证书目录留空就用配置目录下的 certs，申请证书与 HTTPS 加载共用这一个目录，
	// 用户不必再手填路径。
	c.TLS.CertDir = strings.TrimSpace(c.TLS.CertDir)
	if c.TLS.CertDir == "" {
		c.TLS.CertDir = c.deriveCertDir()
		c.certDirAuto = true
	} else {
		c.certDirAuto = false
	}
	c.TLS.Cert = strings.TrimSpace(c.TLS.Cert)
	c.TLS.Key = strings.TrimSpace(c.TLS.Key)
	if c.TLS.Enable {
		if c.TLS.Cert != "" && c.TLS.Key == "" {
			return fmt.Errorf("已填写证书文件，但缺少私钥文件")
		}
	}
	if c.TLS.HTTPListen != "" {
		if err := checkListen(c.TLS.HTTPListen, "HTTP 跳转监听地址"); err != nil {
			return err
		}
	}
	// 勾了「HTTP 自动跳转」却没填监听地址：不默认接管 80。
	// 小米等路由器的管理后台（uhttpd）就监听 80，抢了会让路由器 Web 打不开；
	// 而且家宽 80 通常被运营商封，留空等于不启用 HTTP 入口。
	if c.TLS.Redirect && c.TLS.HTTPListen == "" {
		c.TLS.Redirect = false
	}
	if c.TLS.PublicPort < 0 || c.TLS.PublicPort > 65535 {
		return fmt.Errorf("HTTPS 公网端口无效: %d", c.TLS.PublicPort)
	}
	if c.TLS.PublicPort == 0 {
		c.TLS.PublicPort = 443
	}

	// 只允许域名访问：额外放行的域名统一小写、去端口、去结尾点
	var extra []string
	for _, h := range c.Security.ExtraHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if hp, _, err := net.SplitHostPort(h); err == nil && hp != "" {
			h = hp
		}
		extra = append(extra, strings.TrimSuffix(h, "."))
	}
	c.Security.ExtraHosts = extra

	entry, err := normalizeEntryPath(c.Security.EntryPath)
	if err != nil {
		return err
	}
	c.Security.EntryPath = entry

	names := map[string]bool{}
	for i := range c.Proxy {
		r := &c.Proxy[i]
		r.Name = strings.TrimSpace(r.Name)
		if r.Name == "" {
			r.Name = fmt.Sprintf("规则 %d", i+1)
		}
		if names[r.Name] {
			return fmt.Errorf("规则名重复: %s", r.Name)
		}
		names[r.Name] = true

		var hosts []string
		for _, h := range r.Hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				continue
			}
			if hp, _, err := net.SplitHostPort(h); err == nil && hp != "" {
				h = hp
			}
			hosts = append(hosts, strings.TrimSuffix(h, "."))
		}
		if len(hosts) == 0 {
			return fmt.Errorf("规则「%s」没有填写域名", r.Name)
		}
		r.Hosts = hosts
		r.Path = normalizePath(r.Path)

		t := strings.TrimSpace(r.Target)
		if t == "" {
			return fmt.Errorf("规则「%s」没有填写上游地址", r.Name)
		}
		if !strings.Contains(t, "://") {
			t = "http://" + t
		}
		u, err := url.Parse(t)
		if err != nil || u.Host == "" {
			return fmt.Errorf("规则「%s」上游地址无效: %s", r.Name, r.Target)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("规则「%s」上游只支持 http/https", r.Name)
		}
		r.Target = strings.TrimRight(t, "/")

		if r.Headers != nil {
			clean := make(map[string]string, len(r.Headers))
			for k, v := range r.Headers {
				if k = strings.TrimSpace(k); k != "" {
					clean[k] = v
				}
			}
			r.Headers = clean
		}
	}

	d := &c.DDNS
	if d.Provider == "" {
		d.Provider = "aliyun"
	}
	if d.Interval < 60 {
		d.Interval = 300
	}
	if d.TTL <= 0 {
		d.TTL = 600
	}
	if d.IPMode == "" {
		d.IPMode = "api"
	}
	if d.Enable {
		if d.Provider != "aliyun" {
			return fmt.Errorf("DDNS 目前只支持 aliyun")
		}
		if strings.TrimSpace(d.AccessKey) == "" || strings.TrimSpace(d.SecretKey) == "" {
			return fmt.Errorf("启用 DDNS 需要填写 AccessKey ID 与 Secret")
		}
		if len(d.Records) == 0 {
			return fmt.Errorf("启用 DDNS 但没有任何域名记录")
		}
	}
	for i := range d.Records {
		r := &d.Records[i]
		r.Domain = strings.ToLower(strings.TrimSpace(r.Domain))
		r.RR = strings.TrimSpace(r.RR)
		if r.RR == "" {
			r.RR = "@"
		}
		r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
		if r.Type == "" {
			r.Type = "A"
		}
		if r.Type != "A" && r.Type != "AAAA" {
			return fmt.Errorf("记录 %s.%s 的类型只能是 A 或 AAAA", r.RR, r.Domain)
		}
		if r.Domain == "" || !strings.Contains(r.Domain, ".") {
			return fmt.Errorf("第 %d 条记录的域名无效: %q", i+1, r.Domain)
		}
	}
	if d.IPMode == "interface" && strings.TrimSpace(d.Interface) == "" && !d.Enable {
		// 允许未启用时留空
	}

	if err := c.normalizeACME(); err != nil {
		return err
	}
	if err := c.normalizeForward(); err != nil {
		return err
	}
	if c.Runtime.MemLimitMB > 0 && c.Runtime.MemLimitMB < 16 {
		c.Runtime.MemLimitMB = 16
	}
	if err := c.normalizeTerm(); err != nil {
		return err
	}
	return nil
}

func (c *Config) normalizeACME() error {
	ac := &c.ACME
	ac.Email = strings.TrimSpace(ac.Email)
	ac.CA = strings.TrimSpace(ac.CA)
	if ac.CA == "" {
		ac.CA = "letsencrypt"
	}
	if ac.KeyType != "rsa2048" {
		ac.KeyType = "ec256"
	}
	if ac.RenewDays < 7 {
		ac.RenewDays = 30
	}
	if ac.RenewDays > 60 {
		ac.RenewDays = 60
	}
	// 证书目录留空就跟着 HTTPS 用同一个自动目录，不用手填
	ac.CertDir = strings.TrimSpace(ac.CertDir)
	if ac.CertDir == "" {
		ac.CertDir = c.TLS.CertDir
	}

	var doms []string
	seen := map[string]bool{}
	for _, d := range ac.Domains {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
		if d == "" || seen[d] {
			continue
		}
		if net.ParseIP(d) != nil {
			return fmt.Errorf("证书域名不能填 IP 地址: %s（IP 证书需要 HTTP-01 或手动签发）", d)
		}
		if !strings.Contains(strings.TrimPrefix(d, "*."), ".") {
			return fmt.Errorf("证书域名无效: %q", d)
		}
		seen[d] = true
		doms = append(doms, d)
	}
	ac.Domains = doms

	if !ac.Enable {
		return nil
	}
	if len(doms) == 0 {
		return fmt.Errorf("启用自动证书但没有任何域名")
	}
	// AccessKey 留空时复用 DDNS 的那一份，但不写回配置——
	// 否则以后改 DDNS 的密钥，自动证书这边会一直用旧的。
	if strings.TrimSpace(ac.AccessKey) == "" && strings.TrimSpace(c.DDNS.AccessKey) == "" {
		return fmt.Errorf("启用自动证书需要阿里云 AccessKey（可在 DDNS 页填写后自动复用）")
	}
	if ac.Email == "" {
		return fmt.Errorf("启用自动证书需要填写联系邮箱（CA 用于到期提醒）")
	}
	return nil
}

func (c *Config) normalizeForward() error {
	fc := &c.Forward
	fc.Backend = strings.ToLower(strings.TrimSpace(fc.Backend))
	if fc.Backend == "" {
		fc.Backend = "auto"
	}
	switch fc.Backend {
	case "auto", "iptables", "nftables", "off":
	default:
		return fmt.Errorf("端口转发后端只能是 auto/iptables/nftables/off，收到 %q", fc.Backend)
	}

	names := map[string]bool{}
	used := map[string]bool{}
	for i := range fc.Rules {
		r := &fc.Rules[i]
		r.Name = strings.TrimSpace(r.Name)
		if r.Name == "" {
			r.Name = fmt.Sprintf("转发 %d", i+1)
		}
		if names[r.Name] {
			return fmt.Errorf("端口转发规则名重复: %s", r.Name)
		}
		names[r.Name] = true

		r.Proto = strings.ToLower(strings.TrimSpace(r.Proto))
		if r.Proto == "" {
			r.Proto = "tcp"
		}
		if r.Proto != "tcp" && r.Proto != "udp" && r.Proto != "both" {
			return fmt.Errorf("规则「%s」的协议只能是 tcp/udp/both", r.Name)
		}
		if r.Port < 1 || r.Port > 65535 {
			return fmt.Errorf("规则「%s」的外网端口无效: %d", r.Name, r.Port)
		}
		if r.ToPort < 1 || r.ToPort > 65535 {
			return fmt.Errorf("规则「%s」的目标端口无效: %d", r.Name, r.ToPort)
		}
		r.ToHost = strings.TrimSpace(r.ToHost)
		ip := net.ParseIP(r.ToHost)
		if ip == nil {
			return fmt.Errorf("规则「%s」的目标主机必须是 IP，不能用域名（DNAT 在内核完成，不做解析）", r.Name)
		}
		if ip.To4() == nil {
			return fmt.Errorf("规则「%s」的目标主机暂只支持 IPv4 地址", r.Name)
		}
		r.ToHost = ip.To4().String()
		if !r.Disable {
			for _, p := range protoList(r.Proto) {
				key := fmt.Sprintf("%s:%d", p, r.Port)
				if used[key] {
					return fmt.Errorf("外网端口 %d/%s 被多条规则重复占用", r.Port, p)
				}
				used[key] = true
			}
		}
	}
	return nil
}

func protoList(p string) []string {
	if p == "both" {
		return []string{"tcp", "udp"}
	}
	return []string{p}
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		return "/"
	}
	return p
}

// normalizeEntryPath 校验并规范化「安全入口」：必须是以 / 开头的字面路径，
// 只允许字母、数字和 - _ . ~，不允许 * ? # % & = 之类会被 URL 转义或当通配用的字符，
// 免得用户填了 /a?b 之后自己都访问不进去。留空表示不启用。
func normalizeEntryPath(p string) (string, error) {
	p = strings.TrimSpace(p)
	p = strings.ReplaceAll(p, "\\", "/")
	if p == "" || p == "/" {
		return "", nil
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	p = strings.TrimRight(p, "/")
	if p == "" || p == "/" {
		return "", nil
	}
	if len(p) > 64 {
		return "", fmt.Errorf("安全入口太长（最多 64 个字符）: %s", p)
	}
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if len(segs) > 3 {
		return "", fmt.Errorf("安全入口最多 3 层，例如 /entry 或 /a/b: %s", p)
	}
	for _, s := range segs {
		if s == "" {
			return "", fmt.Errorf("安全入口不能有空路径段（不要连写 //）: %s", p)
		}
		for i := 0; i < len(s); i++ {
			ch := s[i]
			ok := ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' ||
				ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.' || ch == '~'
			if !ok {
				return "", fmt.Errorf("安全入口只能包含字母、数字和 - _ . ~，不能用 %q（也不要带 ?、#、%%）: %s", string(ch), p)
			}
		}
	}
	return p, nil
}
func randomPassword() string {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "admin888"
	}
	return hex.EncodeToString(b)
}

func defaultConfigPath() string {
	if p := os.Getenv("LP_CONFIG"); p != "" {
		return p
	}
	if exe, err := os.Executable(); err == nil {
		p := filepath.Join(filepath.Dir(exe), "config.json")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	if _, err := os.Stat("/etc/lightproxy/config.json"); err == nil {
		return "/etc/lightproxy/config.json"
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "config.json")
	}
	return "config.json"
}
