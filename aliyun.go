package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// 阿里云 DNS（AliDNS）RPC 客户端。只实现本工具用到的 4 个接口，
// 不引入官方 SDK——在 32 位路由器上能省下十几 MB 依赖和体积。

// 默认公网地址；LP_ALIYUN_ENDPOINT 可覆盖（自建代理 / 本地联调）
var alidnsEndpoint = func() string {
	if v := os.Getenv("LP_ALIYUN_ENDPOINT"); v != "" {
		return v
	}
	return "https://alidns.aliyuncs.com/"
}()

type aliyunClient struct {
	accessKey string
	secretKey string
	http      *http.Client
}

type APIError struct {
	Code    string
	Message string
	Status  int
}

func (e *APIError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("阿里云接口返回 HTTP %d", e.Status)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func newAliyunClient(ak, sk string, insecure bool) *aliyunClient {
	return &aliyunClient{
		accessKey: ak,
		secretKey: sk,
		http:      newDNSHTTPClient(insecure),
	}
}

// sign 实现阿里云 RPC 签名 v1（HMAC-SHA1）。
func (c *aliyunClient) sign(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var canon strings.Builder
	for i, k := range keys {
		if i > 0 {
			canon.WriteByte('&')
		}
		canon.WriteString(percentEncode(k))
		canon.WriteByte('=')
		canon.WriteString(percentEncode(params[k]))
	}
	stringToSign := "GET&" + percentEncode("/") + "&" + percentEncode(canon.String())

	mac := hmac.New(sha1.New, []byte(c.secretKey+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

func (c *aliyunClient) call(action string, extra map[string]string) (map[string]json.RawMessage, error) {
	params := map[string]string{
		"Action":           action,
		"Format":           "JSON",
		"Version":          "2015-01-09",
		"AccessKeyId":      c.accessKey,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"SignatureNonce":   nonce(),
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	for k, v := range extra {
		params[k] = v
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		out, err := c.once(params)
		if err == nil {
			return out, nil
		}
		lastErr = err
		if ae, ok := err.(*APIError); ok && ae.Status < 500 {
			// 业务错误（签名、权限、参数）重试没有意义
			return nil, err
		}
	}
	return nil, lastErr
}

func (c *aliyunClient) once(params map[string]string) (map[string]json.RawMessage, error) {
	sig := c.sign(params)
	q := make([]string, 0, len(params)+1)
	for k, v := range params {
		q = append(q, percentEncode(k)+"="+percentEncode(v))
	}
	q = append(q, "Signature="+percentEncode(sig))

	req, err := http.NewRequest(http.MethodGet, alidnsEndpoint+"?"+strings.Join(q, "&"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "lightproxy/"+version)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("阿里云返回无法解析（HTTP %d）: %.200s", resp.StatusCode, string(body))
	}
	var ae APIError
	ae.Status = resp.StatusCode
	if v, ok := raw["Code"]; ok {
		json.Unmarshal(v, &ae.Code)
	}
	if v, ok := raw["Message"]; ok {
		json.Unmarshal(v, &ae.Message)
	}
	if ae.Code != "" || resp.StatusCode != 200 {
		return nil, &ae
	}
	return raw, nil
}

func percentEncode(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'A' && ch <= 'Z', ch >= 'a' && ch <= 'z', ch >= '0' && ch <= '9',
			ch == '-', ch == '_', ch == '.', ch == '~':
			b.WriteByte(ch)
		default:
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String()
}

func nonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------------- 具体接口 ----------------

type aliyunRecord struct {
	RecordID string `json:"RecordId"`
	RR       string `json:"RR"`
	Type     string `json:"Type"`
	Value    string `json:"Value"`
	TTL      int    `json:"TTL"`
	Status   string `json:"Status"`
	Line     string `json:"Line"`
}

func (c *aliyunClient) DescribeSubDomain(sub, typ string) ([]aliyunRecord, error) {
	raw, err := c.call("DescribeSubDomainRecords", map[string]string{
		"SubDomain": sub,
		"Type":      typ,
		"PageSize":  "100",
	})
	if err != nil {
		return nil, err
	}
	var wrap struct {
		DomainRecords struct {
			Record []aliyunRecord `json:"Record"`
		} `json:"DomainRecords"`
	}
	if v, ok := raw["DomainRecords"]; ok {
		json.Unmarshal(v, &wrap.DomainRecords)
	}
	return wrap.DomainRecords.Record, nil
}

func (c *aliyunClient) UpdateRecord(recordID, rr, typ, value string, ttl int) error {
	_, err := c.call("UpdateDomainRecord", map[string]string{
		"RecordId": recordID,
		"RR":       rr,
		"Type":     typ,
		"Value":    value,
		"TTL":      fmt.Sprint(ttl),
	})
	return err
}

func (c *aliyunClient) AddRecord(domain, rr, typ, value string, ttl int) (string, error) {
	raw, err := c.call("AddDomainRecord", map[string]string{
		"DomainName": domain,
		"RR":         rr,
		"Type":       typ,
		"Value":      value,
		"TTL":        fmt.Sprint(ttl),
	})
	if err != nil {
		return "", err
	}
	var id string
	if v, ok := raw["RecordId"]; ok {
		json.Unmarshal(v, &id)
	}
	return id, nil
}

func (c *aliyunClient) DeleteRecord(recordID string) error {
	_, err := c.call("DeleteDomainRecord", map[string]string{"RecordId": recordID})
	return err
}

// ListDomains 返回账号下全部域名，ACME 用它推断某条记录属于哪个 zone。
func (c *aliyunClient) ListDomains() ([]string, error) {
	var out []string
	for page := 1; page <= 20; page++ {
		raw, err := c.call("DescribeDomains", map[string]string{
			"PageSize":   "100",
			"PageNumber": fmt.Sprint(page),
		})
		if err != nil {
			return nil, err
		}
		var wrap struct {
			Domains struct {
				Domain []struct {
					DomainName string `json:"DomainName"`
				} `json:"Domain"`
			} `json:"Domains"`
			TotalCount int `json:"TotalCount"`
		}
		if v, ok := raw["Domains"]; ok {
			json.Unmarshal(v, &wrap.Domains)
		}
		if v, ok := raw["TotalCount"]; ok {
			json.Unmarshal(v, &wrap.TotalCount)
		}
		for _, d := range wrap.Domains.Domain {
			out = append(out, d.DomainName)
		}
		if len(out) >= wrap.TotalCount || len(wrap.Domains.Domain) == 0 {
			break
		}
	}
	return out, nil
}

// TestCredentials 用一个只读接口验证 AK/SK 是否可用，并返回可用域名数量。
func (c *aliyunClient) TestCredentials() (int, error) {
	raw, err := c.call("DescribeDomains", map[string]string{"PageSize": "1"})
	if err != nil {
		return 0, err
	}
	var total int
	if v, ok := raw["TotalCount"]; ok {
		json.Unmarshal(v, &total)
	}
	return total, nil
}

// ---------------- dnsProvider 适配 ----------------

func (c *aliyunClient) Provider() string { return "aliyun" }

func (c *aliyunClient) ListZones() ([]string, error) { return c.ListDomains() }

func (c *aliyunClient) Records(zone, rr, typ string) ([]dnsHit, error) {
	list, err := c.DescribeSubDomain(joinRR(zone, rr), typ)
	if err != nil {
		return nil, err
	}
	out := make([]dnsHit, 0, len(list))
	for _, r := range list {
		if typ != "" && !strings.EqualFold(r.Type, typ) {
			continue
		}
		out = append(out, dnsHit{
			ID: r.RecordID, Zone: zone, RR: r.RR, Type: r.Type,
			Value: r.Value, TTL: r.TTL, Line: r.Line,
		})
	}
	return out, nil
}

func (c *aliyunClient) Create(zone, rr, typ, value string, ttl int) (dnsHit, error) {
	id, err := c.AddRecord(zone, rr, typ, value, ttl)
	if err != nil {
		return dnsHit{}, err
	}
	return dnsHit{ID: id, Zone: zone, RR: rr, Type: typ, Value: value, TTL: ttl}, nil
}

func (c *aliyunClient) Update(h dnsHit, value string, ttl int) error {
	return c.UpdateRecord(h.ID, h.RR, h.Type, value, ttl)
}

func (c *aliyunClient) Test() (int, error) { return c.TestCredentials() }
