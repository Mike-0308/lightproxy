package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// 各家 DNS 服务商的适配层。
//
// 每个服务商一个文件、只实现下面的 dnsProvider 接口，同步逻辑（ddns.go）完全共用一份。
// 不引官方 SDK：90% 的云厂商 SDK 会带进几十 MB 依赖，而这里每家只需要 4 个 HTTP 接口。

// dnsHit 是一条已存在的解析记录。
type dnsHit struct {
	ID    string
	Zone  string
	RR    string
	Type  string
	Value string
	TTL   int
	Line  string
}

type dnsProvider interface {
	Provider() string
	ListZones() ([]string, error)
	Records(zone, rr, typ string) ([]dnsHit, error)
	Create(zone, rr, typ, value string, ttl int) (dnsHit, error)
	Update(h dnsHit, value string, ttl int) error
	Test() (int, error)
}

// directDNS 是 DuckDNS / dynv6 这类「一个 token 直接覆盖一条记录」的服务商：
// 没有 zone、没有记录 ID，也不需要先查询——SET 本身就是幂等的。
type directDNS interface {
	SetDirect(host, typ, value string) (note string, err error)
}

// providerSpec 描述一个服务商在面板上需要的填写项。
// 前端据此渲染下拉框与输入框标签，避免各处硬编码。
type providerSpec struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	KeyLbl  string `json:"keyLabel"`
	KeyPH   string `json:"keyPlaceholder"`
	SecLbl  string `json:"secLabel"`
	SecPH   string `json:"secPlaceholder"`
	NeedSec bool   `json:"needSecret"`
	Direct  bool   `json:"direct"` // true: 域名栏填子域名，不走 zone/记录两级
	Hint    string `json:"hint"`
	Docs    string `json:"docs"`
}

var providerSpecs = []providerSpec{
	{
		ID: "aliyun", Name: "阿里云解析", KeyLbl: "AccessKey ID", KeyPH: "LTAI...",
		SecLbl: "AccessKey Secret", SecPH: "********", NeedSec: true,
		Hint: "建议用 RAM 子账号，只授予 AliyunDNSFullAccess",
		Docs: "https://ram.console.aliyun.com/users",
	},
	{
		ID: "tencent", Name: "腾讯云 DNSPod", KeyLbl: "SecretId", KeyPH: "AKID...",
		SecLbl: "SecretKey", SecPH: "********", NeedSec: true,
		Hint: "DNSPod 已并入腾讯云，用云 API 密钥；子账号需 QcloudDNSPodFullAccess",
		Docs: "https://console.cloud.tencent.com/cam/capi",
	},
	{
		ID: "huawei", Name: "华为云 DNS", KeyLbl: "Access Key ID", KeyPH: "HPUA...",
		SecLbl: "Secret Access Key", SecPH: "********", NeedSec: true,
		Hint: "我的凭证 → 访问密钥；账号需有 DNS FullAccess",
		Docs: "https://console.huaweicloud.com/iam/#/mine/accessKey",
	},
	{
		ID: "baidu", Name: "百度智能云 DNS", KeyLbl: "Access Key ID", KeyPH: "f81d3b34...",
		SecLbl: "Secret Access Key", SecPH: "********", NeedSec: true,
		Hint: "安全认证 → AccessKey；域名需已托管在百度云解析",
		Docs: "https://console.bce.baidu.com/iam/#/iam/accesslist",
	},
	{
		ID: "volcengine", Name: "火山引擎 TrafficRoute", KeyLbl: "Access Key ID", KeyPH: "AKLT...",
		SecLbl: "Secret Access Key", SecPH: "********", NeedSec: true,
		Hint: "访问控制 → 密钥管理；需 DNS 读写权限",
		Docs: "https://console.volcengine.com/iam/keymanage/",
	},
	{
		ID: "cloudflare", Name: "Cloudflare", KeyLbl: "API Token", KeyPH: "Bearer Token（Zone.DNS 编辑权限）",
		Hint: "用「API 令牌」而不是 Global API Key；权限选 Zone → DNS → Edit",
		Docs: "https://dash.cloudflare.com/profile/api-tokens",
	},
	{
		ID: "duckdns", Name: "DuckDNS（免费）", KeyLbl: "Token", KeyPH: "在 duckdns.org 首页复制 token",
		Direct: true,
		Hint:   "域名栏填子域名，如 myhome（不用写 .duckdns.org）；只支持 A / AAAA",
		Docs:   "https://www.duckdns.org/",
	},
	{
		ID: "dynv6", Name: "dynv6（免费）", KeyLbl: "HTTP Token", KeyPH: "在 dynv6.com 域名的 instructions 页获取",
		Direct: true,
		Hint:   "域名栏填完整域名，如 myhome.dynv6.net；IPv6 用户的首选",
		Docs:   "https://dynv6.com/zones",
	},
}

func providerSpecOf(id string) (providerSpec, bool) {
	id = normalizeProvider(id)
	for _, s := range providerSpecs {
		if s.ID == id {
			return s, true
		}
	}
	return providerSpec{}, false
}

// normalizeProvider 兼容旧配置里的写法（AliDNS / dnspod / cf 等）。
func normalizeProvider(id string) string {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "", "aliyun", "alidns", "ali":
		return "aliyun"
	case "tencent", "dnspod", "qcloud", "tencentcloud":
		return "tencent"
	case "huawei", "huaweicloud", "hw":
		return "huawei"
	case "baidu", "bce", "baiducloud":
		return "baidu"
	case "volcengine", "volc", "bytedance", "trafficroute":
		return "volcengine"
	case "cloudflare", "cf":
		return "cloudflare"
	case "duckdns", "duck":
		return "duckdns"
	case "dynv6":
		return "dynv6"
	}
	return strings.ToLower(strings.TrimSpace(id))
}

func newDNSProvider(cfg DDNSConfig) (dnsProvider, error) {
	key := strings.TrimSpace(cfg.AccessKey)
	sec := strings.TrimSpace(cfg.SecretKey)
	switch normalizeProvider(cfg.Provider) {
	case "aliyun":
		return newAliyunClient(key, sec, cfg.Insecure), nil
	case "tencent":
		return newTencentClient(key, sec, cfg.Insecure), nil
	case "huawei":
		return newHuaweiClient(key, sec, cfg.Insecure), nil
	case "baidu":
		return newBaiduClient(key, sec, cfg.Insecure), nil
	case "volcengine":
		return newVolcClient(key, sec, cfg.Insecure), nil
	case "cloudflare":
		return newCloudflareClient(key, cfg.Insecure), nil
	case "duckdns":
		return newDuckClient(key, cfg.Insecure), nil
	case "dynv6":
		return newDynv6Client(key, cfg.Insecure), nil
	}
	return nil, fmt.Errorf("不支持的 DNS 服务商: %q", cfg.Provider)
}

// ---------------- 公共工具 ----------------

// newDNSHTTPClient 给各适配层共用；DDNS 是低频调用，连接池给一点点就够。
func newDNSHTTPClient(insecure bool) *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy:               nil,
			MaxIdleConns:        4,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: insecure},
		},
	}
}

func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacHex(key []byte, data string) string {
	return hex.EncodeToString(hmacSHA256(key, data))
}

// canonicalQuery 按 key 字典序拼出签名用的 query string（RFC3986 编码）。
// 复用 percentEncode，保证与阿里云那套编码规则完全一致。
func canonicalQuery(v url.Values) string {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		vs := v[k]
		sort.Strings(vs)
		for j, val := range vs {
			if i > 0 || j > 0 {
				b.WriteByte('&')
			}
			b.WriteString(percentEncode(k))
			b.WriteByte('=')
			b.WriteString(percentEncode(val))
		}
	}
	return b.String()
}

// joinRR 把 (zone, rr) 还原成完整域名。
func joinRR(zone, rr string) string {
	if rr == "" || rr == "@" {
		return zone
	}
	return rr + "." + zone
}

// splitRR 是 joinRR 的反向操作（用于拿到厂商返回的 FQDN 后还原主机记录）。
func splitRR(fqdn, zone string) string {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")
	if strings.EqualFold(fqdn, zone) {
		return "@"
	}
	if strings.HasSuffix(strings.ToLower(fqdn), "."+strings.ToLower(zone)) {
		return fqdn[:len(fqdn)-len(zone)-1]
	}
	return fqdn
}

// numStr 兼容「ID 有时是数字、有时是字符串」的返回（腾讯云给数字，火山给字符串）。
type numStr string

func (n *numStr) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "null" {
		s = ""
	}
	*n = numStr(s)
	return nil
}
