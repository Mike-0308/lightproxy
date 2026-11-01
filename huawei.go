package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 华为云 DNS（SDK-HMAC-SHA256）。DNS 是全球服务，endpoint 不分 region，
// 签名也不做 region/service 派生——直接拿 SK 对 StringToSign 做 HMAC。

const (
	hwHost       = "dns.myhuaweicloud.com"
	hwDateFormat = "20060102T150405Z"
	hwAlgo       = "SDK-HMAC-SHA256"
)

type huaweiClient struct {
	ak, sk string
	http   *http.Client

	mu    sync.Mutex
	zones map[string]string // name(小写,无尾点) -> zone id
}

func newHuaweiClient(ak, sk string, insecure bool) *huaweiClient {
	return &huaweiClient{ak: ak, sk: sk, http: newDNSHTTPClient(insecure), zones: map[string]string{}}
}

type hwError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *hwError) Error() string { return e.Code + ": " + e.Message }

func (c *huaweiClient) do(method, path string, query url.Values, body []byte, out any) error {
	u := "https://" + hwHost + path
	if len(query) > 0 {
		u += "?" + canonicalQuery(query)
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	xDate := now.Format(hwDateFormat)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sdk-Date", xDate)
	req.Header.Set("User-Agent", "lightproxy/"+version)
	req.Host = hwHost

	// 只签固定的三个头，避免把 User-Agent 之类的易变头带进签名。
	signedHeaders := "content-type;host;x-sdk-date"
	canonicalHeaders := "content-type:application/json\nhost:" + hwHost + "\nx-sdk-date:" + xDate + "\n"

	// 华为的 CanonicalURI 要求每段做 RFC3986 编码且末尾必须补 "/"。
	canoURI := hwCanonicalURI(path)
	payloadHash := sha256Hex(body)
	canonicalRequest := method + "\n" + canoURI + "\n" + canonicalQuery(query) + "\n" +
		canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash

	stringToSign := hwAlgo + "\n" + xDate + "\n" + sha256Hex([]byte(canonicalRequest))
	signature := hmacHex([]byte(c.sk), stringToSign)

	req.Header.Set("Authorization", hwAlgo+" Access="+c.ak+", SignedHeaders="+signedHeaders+", Signature="+signature)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var he hwError
		if json.Unmarshal(raw, &he) == nil && he.Code != "" {
			return friendlyHuawei(&he)
		}
		return fmt.Errorf("华为云返回 HTTP %d: %.200s", resp.StatusCode, string(raw))
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// hwCanonicalURI 每段单独编码，末尾补 '/'。
func hwCanonicalURI(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		parts[i] = percentEncode(p)
	}
	out := strings.Join(parts, "/")
	if !strings.HasSuffix(out, "/") {
		out += "/"
	}
	return out
}

func (c *huaweiClient) zoneID(zone string) (string, error) {
	key := strings.ToLower(strings.TrimSuffix(zone, "."))
	c.mu.Lock()
	id, ok := c.zones[key]
	c.mu.Unlock()
	if ok {
		return id, nil
	}
	if _, err := c.ListZones(); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if id, ok := c.zones[key]; ok {
		return id, nil
	}
	return "", fmt.Errorf("华为云账号里没有域名 %s", zone)
}

// ---------------- dnsProvider ----------------

func (c *huaweiClient) Provider() string { return "huawei" }

func (c *huaweiClient) ListZones() ([]string, error) {
	var out []string
	found := map[string]string{}
	for page := 1; page <= 20; page++ {
		var res struct {
			Zones []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"zones"`
			Metadata struct {
				TotalCount int `json:"total_count"`
			} `json:"metadata"`
		}
		q := url.Values{}
		q.Set("type", "public")
		q.Set("limit", "500")
		q.Set("offset", strconv.Itoa((page-1)*500))
		if err := c.do(http.MethodGet, "/v2/zones", q, nil, &res); err != nil {
			return nil, err
		}
		for _, z := range res.Zones {
			name := strings.TrimSuffix(z.Name, ".")
			out = append(out, name)
			found[strings.ToLower(name)] = z.ID
		}
		if len(res.Zones) < 500 || len(out) >= res.Metadata.TotalCount {
			break
		}
	}
	c.mu.Lock()
	for k, v := range found {
		c.zones[k] = v
	}
	c.mu.Unlock()
	return out, nil
}

func (c *huaweiClient) Records(zone, rr, typ string) ([]dnsHit, error) {
	id, err := c.zoneID(zone)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("name", strings.TrimSuffix(joinRR(zone, rr), ".")+".")
	if typ != "" {
		q.Set("type", typ)
	}
	q.Set("limit", "100")
	var res struct {
		Recordsets []struct {
			ID      string   `json:"id"`
			Name    string   `json:"name"`
			Type    string   `json:"type"`
			Records []string `json:"records"`
			TTL     int      `json:"ttl"`
		} `json:"recordsets"`
	}
	if err := c.do(http.MethodGet, "/v2/zones/"+url.PathEscape(id)+"/recordsets", q, nil, &res); err != nil {
		return nil, err
	}
	out := make([]dnsHit, 0, len(res.Recordsets))
	for _, r := range res.Recordsets {
		if typ != "" && !strings.EqualFold(r.Type, typ) || len(r.Records) == 0 {
			continue
		}
		out = append(out, dnsHit{
			ID: r.ID, Zone: zone, RR: splitRR(r.Name, zone),
			Type: r.Type, Value: r.Records[0], TTL: r.TTL,
		})
	}
	return out, nil
}

func (c *huaweiClient) Create(zone, rr, typ, value string, ttl int) (dnsHit, error) {
	id, err := c.zoneID(zone)
	if err != nil {
		return dnsHit{}, err
	}
	fqdn := strings.TrimSuffix(joinRR(zone, rr), ".") + "."
	body, _ := json.Marshal(map[string]any{
		"name": fqdn, "type": typ, "records": []string{value}, "ttl": hwTTL(ttl),
	})
	var res struct {
		ID string `json:"id"`
	}
	if err := c.do(http.MethodPost, "/v2/zones/"+url.PathEscape(id)+"/recordsets", nil, body, &res); err != nil {
		return dnsHit{}, err
	}
	return dnsHit{ID: res.ID, Zone: zone, RR: rr, Type: typ, Value: value, TTL: hwTTL(ttl)}, nil
}

func (c *huaweiClient) Update(h dnsHit, value string, ttl int) error {
	id, err := c.zoneID(h.Zone)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{
		"name": strings.TrimSuffix(joinRR(h.Zone, h.RR), ".") + ".",
		"type": h.Type, "records": []string{value}, "ttl": hwTTL(ttl),
	})
	return c.do(http.MethodPut, "/v2/zones/"+url.PathEscape(id)+"/recordsets/"+url.PathEscape(h.ID), nil, body, nil)
}

func (c *huaweiClient) Test() (int, error) {
	q := url.Values{}
	q.Set("type", "public")
	q.Set("limit", "1")
	var res struct {
		Metadata struct {
			TotalCount int `json:"total_count"`
		} `json:"metadata"`
	}
	if err := c.do(http.MethodGet, "/v2/zones", q, nil, &res); err != nil {
		return 0, err
	}
	return res.Metadata.TotalCount, nil
}

// hwTTL 华为免费版要求 300 秒起。
func hwTTL(ttl int) int {
	if ttl < 300 {
		return 300
	}
	return ttl
}

func friendlyHuawei(e *hwError) error {
	switch {
	case strings.Contains(e.Code, "APIGW.0301") || strings.Contains(e.Message, "signature"):
		return fmt.Errorf("华为云签名校验失败，先确认路由器时间已同步（%s）", e.Message)
	case strings.Contains(e.Code, "DNS.0403"):
		return fmt.Errorf("华为云密钥权限不足，需要 DNS FullAccess（%s）", e.Message)
	}
	return e
}

var _ = sort.Strings
