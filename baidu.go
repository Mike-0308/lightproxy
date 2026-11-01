package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// 百度智能云 DNS（BCE 签名 bce-auth-v1）。

const (
	bceHost   = "dns.baidubce.com"
	bceExpire = "1800"
)

type baiduClient struct {
	ak, sk string
	http   *http.Client
}

func newBaiduClient(ak, sk string, insecure bool) *baiduClient {
	return &baiduClient{ak: ak, sk: sk, http: newDNSHTTPClient(insecure)}
}

type bceError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *bceError) Error() string {
	if e.Code == "" {
		return e.Message
	}
	return e.Code + ": " + e.Message
}

func (c *baiduClient) do(method, path string, query url.Values, body []byte, out any) error {
	q := canonicalQuery(query)
	u := "https://" + bceHost + path
	if q != "" {
		u += "?" + q
	}
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	req.Header.Set("Content-Type", "application/json;charset=UTF-8")
	req.Header.Set("x-bce-date", ts)
	req.Header.Set("User-Agent", "lightproxy/"+version)

	// 签名密钥 = hex(HMAC-SHA256(SK, authStringPrefix))，注意是十六进制串再当 key 用。
	prefix := "bce-auth-v1/" + c.ak + "/" + ts + "/" + bceExpire
	signingKey := hmacHex([]byte(c.sk), prefix)
	canonicalHeaders := "host:" + bceHost + "\nx-bce-date:" + ts
	canonicalRequest := method + "\n" + bceCanonicalURI(path) + "\n" + q + "\n" + canonicalHeaders
	signature := hmacHex([]byte(signingKey), canonicalRequest)
	req.Header.Set("Authorization", prefix+"/host;x-bce-date/"+signature)

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
		var be bceError
		if json.Unmarshal(raw, &be) == nil && (be.Code != "" || be.Message != "") {
			return friendlyBaidu(&be)
		}
		return fmt.Errorf("百度云返回 HTTP %d: %.200s", resp.StatusCode, string(raw))
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// bceCanonicalURI：路径做百分号编码但保留 "/"。
func bceCanonicalURI(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		parts[i] = percentEncode(p)
	}
	return strings.Join(parts, "/")
}

// ---------------- dnsProvider ----------------

func (c *baiduClient) Provider() string { return "baidu" }

func (c *baiduClient) ListZones() ([]string, error) {
	var out []string
	for page := 0; page < 20; page++ {
		q := url.Values{}
		q.Set("maxKeys", "1000")
		if page > 0 {
			q.Set("marker", fmt.Sprint(page*1000))
		}
		var res struct {
			Zones []struct {
				Name string `json:"name"`
			} `json:"zones"`
		}
		if err := c.do(http.MethodGet, "/v1/dns/zone", q, nil, &res); err != nil {
			return nil, err
		}
		for _, z := range res.Zones {
			out = append(out, strings.TrimSuffix(z.Name, "."))
		}
		if len(res.Zones) < 1000 {
			break
		}
	}
	return out, nil
}

func (c *baiduClient) Records(zone, rr, typ string) ([]dnsHit, error) {
	q := url.Values{}
	q.Set("rr", rr)
	q.Set("maxKeys", "1000")
	var res struct {
		Records []struct {
			ID       string `json:"id"`
			RecordID string `json:"recordId"`
			RR       string `json:"rr"`
			Type     string `json:"type"`
			Value    string `json:"value"`
			TTL      int    `json:"ttl"`
			Line     string `json:"line"`
		} `json:"records"`
	}
	if err := c.do(http.MethodGet, "/v1/dns/zone/"+url.PathEscape(zone)+"/record", q, nil, &res); err != nil {
		return nil, err
	}
	out := make([]dnsHit, 0, len(res.Records))
	for _, r := range res.Records {
		if typ != "" && !strings.EqualFold(r.Type, typ) {
			continue
		}
		id := r.ID
		if id == "" {
			id = r.RecordID
		}
		out = append(out, dnsHit{
			ID: id, Zone: zone, RR: r.RR, Type: r.Type, Value: r.Value, TTL: r.TTL, Line: r.Line,
		})
	}
	return out, nil
}

func (c *baiduClient) Create(zone, rr, typ, value string, ttl int) (dnsHit, error) {
	body, _ := json.Marshal(map[string]any{
		"rr": rr, "type": typ, "value": value, "ttl": bceTTL(ttl), "line": "default",
	})
	var res struct {
		RecordID string `json:"recordId"`
	}
	if err := c.do(http.MethodPost, "/v1/dns/zone/"+url.PathEscape(zone)+"/record", nil, body, &res); err != nil {
		return dnsHit{}, err
	}
	return dnsHit{ID: res.RecordID, Zone: zone, RR: rr, Type: typ, Value: value, TTL: bceTTL(ttl)}, nil
}

func (c *baiduClient) Update(h dnsHit, value string, ttl int) error {
	line := h.Line
	if line == "" {
		line = "default"
	}
	body, _ := json.Marshal(map[string]any{
		"rr": h.RR, "type": h.Type, "value": value, "ttl": bceTTL(ttl), "line": line,
	})
	return c.do(http.MethodPut, "/v1/dns/zone/"+url.PathEscape(h.Zone)+"/record/"+url.PathEscape(h.ID), nil, body, nil)
}

func (c *baiduClient) Test() (int, error) {
	q := url.Values{}
	q.Set("maxKeys", "1000")
	var res struct {
		Zones []json.RawMessage `json:"zones"`
	}
	if err := c.do(http.MethodGet, "/v1/dns/zone", q, nil, &res); err != nil {
		return 0, err
	}
	return len(res.Zones), nil
}

// bceTTL 百度云解析 TTL 下限 60 秒。
func bceTTL(ttl int) int {
	if ttl < 60 {
		return 60
	}
	return ttl
}

func friendlyBaidu(e *bceError) error {
	low := strings.ToLower(e.Message)
	switch {
	case strings.Contains(low, "signature"):
		return fmt.Errorf("百度云签名校验失败，先确认路由器时间已同步（%s）", e.Message)
	case strings.Contains(low, "permission") || strings.Contains(low, "denied"):
		return fmt.Errorf("百度云密钥权限不足（%s）", e.Message)
	case strings.Contains(low, "domain") && strings.Contains(low, "not"):
		return fmt.Errorf("百度云账号里没有这个域名，先把它接入云解析（%s）", e.Message)
	}
	return e
}
