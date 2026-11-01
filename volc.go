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
	"time"
)

// 火山引擎 TrafficRoute DNS（HMAC-SHA256，与 AWS SigV4 同构）。

const (
	volcHost    = "dns.volcengineapi.com"
	volcRegion  = "cn-north-1"
	volcService = "dns"
	volcVersion = "2018-08-01"
)

type volcClient struct {
	ak, sk string
	http   *http.Client
}

func newVolcClient(ak, sk string, insecure bool) *volcClient {
	return &volcClient{ak: ak, sk: sk, http: newDNSHTTPClient(insecure)}
}

type volcError struct {
	Code    string
	Message string
}

func (e *volcError) Error() string { return e.Code + ": " + e.Message }

func (c *volcClient) call(action string, query url.Values, body []byte, out any) error {
	q := url.Values{}
	for k, v := range query {
		q[k] = v
	}
	q.Set("Action", action)
	q.Set("Version", volcVersion)

	now := time.Now().UTC()
	xDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	scope := date + "/" + volcRegion + "/" + volcService + "/request"

	signedHeaders := "content-type;host;x-date"
	canonicalHeaders := "content-type:application/json\nhost:" + volcHost + "\nx-date:" + xDate + "\n"
	canonicalRequest := http.MethodPost + "\n/\n" + canonicalQuery(q) + "\n" +
		canonicalHeaders + "\n" + signedHeaders + "\n" + sha256Hex(body)

	stringToSign := "HMAC-SHA256\n" + xDate + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))
	kDate := hmacSHA256([]byte(c.sk), date)
	kRegion := hmacSHA256(kDate, volcRegion)
	kService := hmacSHA256(kRegion, volcService)
	kSigning := hmacSHA256(kService, "request")
	sig := hmacHex(kSigning, stringToSign)

	u := "https://" + volcHost + "/?" + canonicalQuery(q)
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Date", xDate)
	req.Header.Set("Authorization", "HMAC-SHA256 Credential="+c.ak+"/"+scope+
		", SignedHeaders="+signedHeaders+", Signature="+sig)
	req.Header.Set("User-Agent", "lightproxy/"+version)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	var wrap struct {
		ResponseMetadata struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
		} `json:"ResponseMetadata"`
		Result json.RawMessage `json:"Result"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return fmt.Errorf("火山引擎返回无法解析（HTTP %d）: %.200s", resp.StatusCode, string(raw))
	}
	if e := wrap.ResponseMetadata.Error; e != nil && e.Code != "" {
		return friendlyVolc(&volcError{Code: e.Code, Message: e.Message})
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("火山引擎返回 HTTP %d: %.200s", resp.StatusCode, string(raw))
	}
	if out == nil || len(wrap.Result) == 0 {
		return nil
	}
	return json.Unmarshal(wrap.Result, out)
}

// ---------------- dnsProvider ----------------

func (c *volcClient) Provider() string { return "volcengine" }

func (c *volcClient) ListZones() ([]string, error) {
	var out []string
	for page := 1; page <= 20; page++ {
		q := url.Values{}
		q.Set("PageNumber", strconv.Itoa(page))
		q.Set("PageSize", "100")
		var res struct {
			Zones []struct {
				ZID      numStr `json:"ZID"`
				ZoneName string `json:"ZoneName"`
			} `json:"Zones"`
			TotalCount int `json:"TotalCount"`
		}
		if err := c.call("ListZones", q, nil, &res); err != nil {
			return nil, err
		}
		for _, z := range res.Zones {
			out = append(out, strings.TrimSuffix(z.ZoneName, "."))
		}
		if len(res.Zones) < 100 || len(out) >= res.TotalCount {
			break
		}
	}
	return out, nil
}

// zoneID 通过域名列表换取 ZID（火山的所有记录接口都要 ZID）。
func (c *volcClient) zoneID(zone string) (string, error) {
	for page := 1; page <= 20; page++ {
		q := url.Values{}
		q.Set("PageNumber", strconv.Itoa(page))
		q.Set("PageSize", "100")
		var res struct {
			Zones []struct {
				ZID      numStr `json:"ZID"`
				ZoneName string `json:"ZoneName"`
			} `json:"Zones"`
			TotalCount int `json:"TotalCount"`
		}
		if err := c.call("ListZones", q, nil, &res); err != nil {
			return "", err
		}
		for _, z := range res.Zones {
			if strings.EqualFold(strings.TrimSuffix(z.ZoneName, "."), zone) {
				return string(z.ZID), nil
			}
		}
		if len(res.Zones) < 100 {
			break
		}
	}
	return "", fmt.Errorf("火山引擎账号里没有域名 %s", zone)
}

func (c *volcClient) Records(zone, rr, typ string) ([]dnsHit, error) {
	zid, err := c.zoneID(zone)
	if err != nil {
		return nil, err
	}
	var out []dnsHit
	for page := 1; page <= 20; page++ {
		q := url.Values{}
		q.Set("ZID", zid)
		q.Set("PageNumber", strconv.Itoa(page))
		q.Set("PageSize", "500")
		var res struct {
			Records []struct {
				RecordID numStr `json:"RecordID"`
				Host     string `json:"Host"`
				Type     string `json:"Type"`
				Value    string `json:"Value"`
				TTL      int    `json:"TTL"`
				Line     string `json:"Line"`
			} `json:"Records"`
			TotalCount int `json:"TotalCount"`
		}
		if err := c.call("ListRecords", q, nil, &res); err != nil {
			return nil, err
		}
		for _, r := range res.Records {
			if typ != "" && !strings.EqualFold(r.Type, typ) {
				continue
			}
			if !strings.EqualFold(r.Host, rr) {
				continue
			}
			out = append(out, dnsHit{
				ID: string(r.RecordID), Zone: zone, RR: r.Host,
				Type: r.Type, Value: r.Value, TTL: r.TTL, Line: r.Line,
			})
		}
		if len(out) > 0 || len(res.Records) < 500 || page*500 >= res.TotalCount {
			break
		}
	}
	return out, nil
}

func (c *volcClient) Create(zone, rr, typ, value string, ttl int) (dnsHit, error) {
	zid, err := c.zoneID(zone)
	if err != nil {
		return dnsHit{}, err
	}
	body, _ := json.Marshal(map[string]any{
		"ZID": json.Number(zid), "Host": rr, "Type": typ, "Value": value,
		"TTL": ttl, "Line": "default", "Weight": 1,
	})
	var res struct {
		RecordID numStr `json:"RecordID"`
	}
	if err := c.call("CreateRecord", nil, body, &res); err != nil {
		return dnsHit{}, err
	}
	return dnsHit{ID: string(res.RecordID), Zone: zone, RR: rr, Type: typ, Value: value, TTL: ttl}, nil
}

func (c *volcClient) Update(h dnsHit, value string, ttl int) error {
	zid, err := c.zoneID(h.Zone)
	if err != nil {
		return err
	}
	line := h.Line
	if line == "" {
		line = "default"
	}
	body, _ := json.Marshal(map[string]any{
		"ZID": json.Number(zid), "RecordID": json.Number(h.ID), "Host": h.RR, "Type": h.Type,
		"Value": value, "TTL": ttl, "Line": line, "Weight": 1,
	})
	return c.call("UpdateRecord", nil, body, nil)
}

func (c *volcClient) Test() (int, error) {
	q := url.Values{}
	q.Set("PageNumber", "1")
	q.Set("PageSize", "100")
	var res struct {
		TotalCount int `json:"TotalCount"`
	}
	if err := c.call("ListZones", q, nil, &res); err != nil {
		return 0, err
	}
	return res.TotalCount, nil
}

func friendlyVolc(e *volcError) error {
	low := strings.ToLower(e.Message)
	switch {
	case strings.Contains(low, "signature"):
		return fmt.Errorf("火山引擎签名校验失败，先确认路由器时间已同步（%s）", e.Message)
	case strings.Contains(low, "access denied") || strings.Contains(low, "permission"):
		return fmt.Errorf("火山引擎密钥权限不足（%s）", e.Message)
	case e.Code == "ErrZoneNotFound":
		return fmt.Errorf("火山引擎账号里没有这个域名（%s）", e.Message)
	}
	return e
}
