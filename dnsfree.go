package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// DuckDNS 与 dynv6：只有一个 token、只维护一条记录，
// 没有 zone / 记录 ID 的概念，走 directDNS 快路径。

// ---------------- DuckDNS ----------------

type duckClient struct {
	token string
	http  *http.Client
}

func newDuckClient(token string, insecure bool) *duckClient {
	return &duckClient{token: strings.TrimSpace(token), http: newDNSHTTPClient(insecure)}
}

func (c *duckClient) Provider() string { return "duckdns" }

func (c *duckClient) ListZones() ([]string, error) { return nil, nil }

func (c *duckClient) Records(_, _, _ string) ([]dnsHit, error) { return nil, nil }

func (c *duckClient) Create(_, _, _, _ string, _ int) (dnsHit, error) {
	return dnsHit{}, fmt.Errorf("DuckDNS 不需要预建记录")
}

func (c *duckClient) Update(dnsHit, string, int) error {
	return fmt.Errorf("DuckDNS 不支持按记录更新")
}

// duckSub 从 myhome / myhome.duckdns.org 里取出 myhome。
func duckSub(host string) string {
	h := strings.ToLower(strings.TrimSpace(host))
	h = strings.TrimSuffix(h, ".duckdns.org")
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	return h
}

func (c *duckClient) SetDirect(host, typ, value string) (string, error) {
	sub := duckSub(host)
	if sub == "" {
		return "", fmt.Errorf("域名不能为空")
	}
	q := url.Values{}
	q.Set("domains", sub)
	q.Set("token", c.token)
	q.Set("verbose", "true")
	if typ == "AAAA" {
		q.Set("ipv6", value)
	} else {
		q.Set("ip", value)
	}
	body, err := c.get("https://www.duckdns.org/update?" + q.Encode())
	if err != nil {
		return "", err
	}
	first := strings.ToUpper(strings.TrimSpace(strings.SplitN(body, "\n", 2)[0]))
	if first != "OK" {
		if strings.Contains(strings.ToUpper(body), "KO") {
			return "", fmt.Errorf("DuckDNS 拒绝更新：token 或子域名不对（%s）", strings.TrimSpace(body))
		}
		return "", fmt.Errorf("DuckDNS 返回异常: %.100s", body)
	}
	return "已推送 " + sub + ".duckdns.org", nil
}

func (c *duckClient) Test() (int, error) {
	if c.token == "" {
		return 0, fmt.Errorf("请先填写 DuckDNS token")
	}
	body, err := c.get("https://www.duckdns.org/update?domains=&token=" + url.QueryEscape(c.token))
	if err != nil {
		return 0, err
	}
	if strings.Contains(strings.ToUpper(body), "KO") {
		return 0, fmt.Errorf("DuckDNS token 无效")
	}
	return 0, nil
}

func (c *duckClient) get(u string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "lightproxy/"+version)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// ---------------- dynv6 ----------------

type dynv6Client struct {
	token string
	http  *http.Client
}

func newDynv6Client(token string, insecure bool) *dynv6Client {
	return &dynv6Client{token: strings.TrimSpace(token), http: newDNSHTTPClient(insecure)}
}

func (c *dynv6Client) Provider() string { return "dynv6" }

func (c *dynv6Client) ListZones() ([]string, error) { return nil, nil }

func (c *dynv6Client) Records(_, _, _ string) ([]dnsHit, error) { return nil, nil }

func (c *dynv6Client) Create(_, _, _, _ string, _ int) (dnsHit, error) {
	return dnsHit{}, fmt.Errorf("dynv6 不需要预建记录")
}

func (c *dynv6Client) Update(dnsHit, string, int) error {
	return fmt.Errorf("dynv6 不支持按记录更新")
}

func (c *dynv6Client) SetDirect(host, typ, value string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("域名不能为空")
	}
	q := url.Values{}
	q.Set("hostname", host)
	q.Set("token", c.token)
	if typ == "AAAA" {
		q.Set("ipv6", value)
	} else {
		q.Set("ipv4", value)
	}
	req, err := http.NewRequest(http.MethodGet, "https://dynv6.com/api/update?"+q.Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "lightproxy/"+version)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	text := strings.TrimSpace(string(b))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("dynv6 返回 HTTP %d: %.100s", resp.StatusCode, text)
	}
	low := strings.ToLower(text)
	if strings.Contains(low, "not updated") || strings.Contains(low, "invalid") || strings.Contains(low, "unknown") {
		return "", fmt.Errorf("dynv6 拒绝更新（检查 token 与域名）: %.100s", text)
	}
	return "已推送 " + host, nil
}

func (c *dynv6Client) Test() (int, error) {
	if c.token == "" {
		return 0, fmt.Errorf("请先填写 dynv6 token")
	}
	// dynv6 没有只读的 token 校验接口，这里用一个不存在的域名探一下：
	// token 无效会返回 401/403，而不是 200。
	resp, err := c.http.Get("https://dynv6.com/api/update?hostname=&token=" + url.QueryEscape(c.token))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return 0, fmt.Errorf("dynv6 token 无效")
	}
	return 0, nil
}
