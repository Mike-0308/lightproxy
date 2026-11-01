package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Cloudflare（API Token 鉴权，REST /client/v4）。

const cfBase = "https://api.cloudflare.com/client/v4"

type cloudflareClient struct {
	token string
	http  *http.Client
}

func newCloudflareClient(token string, insecure bool) *cloudflareClient {
	return &cloudflareClient{token: strings.TrimSpace(token), http: newDNSHTTPClient(insecure)}
}

func (c *cloudflareClient) do(method, path string, query url.Values, body any, out any) error {
	u := cfBase + path
	if q := canonicalQuery(query); q != "" {
		u += "?" + q
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "lightproxy/"+version)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var wrap struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
		Errors  []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return fmt.Errorf("Cloudflare 返回无法解析（HTTP %d）: %.200s", resp.StatusCode, string(raw))
	}
	if !wrap.Success {
		if len(wrap.Errors) > 0 {
			return friendlyCloudflare(wrap.Errors[0].Code, wrap.Errors[0].Message)
		}
		return fmt.Errorf("Cloudflare 返回 HTTP %d: %.200s", resp.StatusCode, string(raw))
	}
	if out == nil || len(wrap.Result) == 0 {
		return nil
	}
	return json.Unmarshal(wrap.Result, out)
}

// ---------------- dnsProvider ----------------

func (c *cloudflareClient) Provider() string { return "cloudflare" }

func (c *cloudflareClient) ListZones() ([]string, error) {
	var out []string
	for page := 1; page <= 20; page++ {
		q := url.Values{}
		q.Set("per_page", "50")
		q.Set("page", strconv.Itoa(page))
		var res []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := c.do(http.MethodGet, "/zones", q, nil, &res); err != nil {
			return nil, err
		}
		for _, z := range res {
			out = append(out, z.Name)
		}
		if len(res) < 50 {
			break
		}
	}
	return out, nil
}

func (c *cloudflareClient) zoneID(zone string) (string, error) {
	q := url.Values{}
	q.Set("name", zone)
	q.Set("per_page", "1")
	var res []struct {
		ID string `json:"id"`
	}
	if err := c.do(http.MethodGet, "/zones", q, nil, &res); err != nil {
		return "", err
	}
	if len(res) == 0 {
		return "", fmt.Errorf("Cloudflare 账号里没有域名 %s", zone)
	}
	return res[0].ID, nil
}

func (c *cloudflareClient) Records(zone, rr, typ string) ([]dnsHit, error) {
	zid, err := c.zoneID(zone)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("name", joinRR(zone, rr))
	if typ != "" {
		q.Set("type", typ)
	}
	q.Set("per_page", "100")
	var res []struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Type    string `json:"type"`
		Content string `json:"content"`
		TTL     int    `json:"ttl"`
	}
	if err := c.do(http.MethodGet, "/zones/"+zid+"/dns_records", q, nil, &res); err != nil {
		return nil, err
	}
	out := make([]dnsHit, 0, len(res))
	for _, r := range res {
		if typ != "" && !strings.EqualFold(r.Type, typ) {
			continue
		}
		out = append(out, dnsHit{
			ID: r.ID, Zone: zone, RR: splitRR(r.Name, zone),
			Type: r.Type, Value: r.Content, TTL: cfTTL(r.TTL),
		})
	}
	return out, nil
}

func (c *cloudflareClient) Create(zone, rr, typ, value string, ttl int) (dnsHit, error) {
	zid, err := c.zoneID(zone)
	if err != nil {
		return dnsHit{}, err
	}
	name := joinRR(zone, rr)
	body := map[string]any{
		"type": typ, "name": name, "content": value,
		"ttl": cfTTLOut(ttl), "proxied": false,
	}
	var res struct {
		ID string `json:"id"`
	}
	if err := c.do(http.MethodPost, "/zones/"+zid+"/dns_records", nil, body, &res); err != nil {
		return dnsHit{}, err
	}
	return dnsHit{ID: res.ID, Zone: zone, RR: rr, Type: typ, Value: value, TTL: cfTTLOut(ttl)}, nil
}

func (c *cloudflareClient) Update(h dnsHit, value string, ttl int) error {
	zid, err := c.zoneID(h.Zone)
	if err != nil {
		return err
	}
	body := map[string]any{
		"type": h.Type, "name": joinRR(h.Zone, h.RR), "content": value,
		"ttl": cfTTLOut(ttl), "proxied": false,
	}
	return c.do(http.MethodPut, "/zones/"+zid+"/dns_records/"+h.ID, nil, body, nil)
}

func (c *cloudflareClient) Test() (int, error) {
	q := url.Values{}
	q.Set("per_page", "50")
	// 这里要读 result_info，所以不走 do()，单独请求一次。
	u := cfBase + "/zones?" + canonicalQuery(q)
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var wrap struct {
		Success    bool `json:"success"`
		ResultInfo struct {
			TotalCount int `json:"total_count"`
		} `json:"result_info"`
		Errors []struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return 0, fmt.Errorf("Cloudflare 返回无法解析: %.200s", string(raw))
	}
	if !wrap.Success {
		if len(wrap.Errors) > 0 {
			return 0, friendlyCloudflare(wrap.Errors[0].Code, wrap.Errors[0].Message)
		}
		return 0, fmt.Errorf("Cloudflare 鉴权失败")
	}
	if wrap.ResultInfo.TotalCount > 0 {
		return wrap.ResultInfo.TotalCount, nil
	}
	list, err := c.ListZones()
	if err != nil {
		return 0, err
	}
	return len(list), nil
}

// cfTTL 读出时把 1（自动）还原成 600，避免每次都判成「需要更新」。
func cfTTL(ttl int) int {
	if ttl <= 1 {
		return 600
	}
	return ttl
}

// cfTTLOut 写入时低于 60 的一律用 1（自动）。
func cfTTLOut(ttl int) int {
	if ttl < 60 {
		return 1
	}
	return ttl
}

func friendlyCloudflare(code int, msg string) error {
	switch code {
	case 6003:
		return fmt.Errorf("Cloudflare Token 无效")
	case 9109:
		return fmt.Errorf("Cloudflare Token 无权访问该域名（检查 Zone.DNS 权限）")
	case 81044, 81057:
		return fmt.Errorf("Cloudflare 记录已存在或参数冲突（%s）", msg)
	}
	return fmt.Errorf("Cloudflare: %s", msg)
}
