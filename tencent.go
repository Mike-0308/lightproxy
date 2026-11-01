package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// 腾讯云 DNSPod（云 API 3.0，TC3-HMAC-SHA256 签名）。
// DNSPod 独立版已并入腾讯云，接口域名统一为 dnspod.tencentcloudapi.com。

const (
	tcHost    = "dnspod.tencentcloudapi.com"
	tcVersion = "2021-03-23"
	tcService = "dnspod"
)

type tencentClient struct {
	secretID  string
	secretKey string
	http      *http.Client
}

func newTencentClient(id, key string, insecure bool) *tencentClient {
	return &tencentClient{secretID: id, secretKey: key, http: newDNSHTTPClient(insecure)}
}

type tcError struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

func (e *tcError) Error() string { return e.Code + ": " + e.Message }

func (c *tencentClient) call(action string, payload any, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	ts := time.Now().Unix()
	date := time.Unix(ts, 0).UTC().Format("2006-01-02")
	const contentType = "application/json; charset=utf-8"
	signedHeaders := "content-type;host"
	canonicalHeaders := "content-type:" + contentType + "\nhost:" + tcHost + "\n"
	canonicalRequest := http.MethodPost + "\n/\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + sha256Hex(body)

	scope := date + "/" + tcService + "/tc3_request"
	stringToSign := "TC3-HMAC-SHA256\n" + strconv.FormatInt(ts, 10) + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))

	kDate := hmacSHA256([]byte("TC3"+c.secretKey), date)
	kService := hmacSHA256(kDate, tcService)
	kSigning := hmacSHA256(kService, "tc3_request")
	sig := hmacHex(kSigning, stringToSign)

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}
		lastErr = c.once(action, body, sig, scope, signedHeaders, ts, out)
		if lastErr == nil {
			return nil
		}
		if te, ok := lastErr.(*tcError); ok && !strings.HasPrefix(te.Code, "InternalError") {
			// 签名/权限/参数类错误重试没有意义
			return lastErr
		}
	}
	return lastErr
}

func (c *tencentClient) once(action string, body []byte, sig, scope, signedHeaders string, ts int64, out any) error {
	req, err := http.NewRequest(http.MethodPost, "https://"+tcHost+"/", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "TC3-HMAC-SHA256 Credential="+c.secretID+"/"+scope+
		", SignedHeaders="+signedHeaders+", Signature="+sig)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Version", tcVersion)
	req.Header.Set("X-TC-Timestamp", strconv.FormatInt(ts, 10))
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
		Response struct {
			Error *tcError        `json:"Error"`
			Raw   json.RawMessage `json:"-"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(raw, &wrap); err != nil {
		return fmt.Errorf("腾讯云返回无法解析（HTTP %d）: %.200s", resp.StatusCode, string(raw))
	}
	if wrap.Response.Error != nil {
		return wrap.Response.Error
	}
	if resp.StatusCode != http.StatusOK {
		return &tcError{Code: "HTTP" + strconv.Itoa(resp.StatusCode), Message: fmt.Sprintf("%.200s", string(raw))}
	}
	// 二次解析到具体结构：外层仍是 {"Response": {...}}
	var outer struct {
		Response json.RawMessage `json:"Response"`
	}
	if err := json.Unmarshal(raw, &outer); err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(outer.Response, out)
}

// ---------------- dnsProvider ----------------

func (c *tencentClient) Provider() string { return "tencent" }

func (c *tencentClient) ListZones() ([]string, error) {
	var out []string
	for offset := 0; offset < 3000; offset += 100 {
		var res struct {
			DomainList []struct {
				Name string `json:"Name"`
			} `json:"DomainList"`
			DomainCountInfo struct {
				AllTotal int `json:"AllTotal"`
			} `json:"DomainCountInfo"`
		}
		if err := c.call("DescribeDomainList", map[string]any{"Offset": offset, "Limit": 100}, &res); err != nil {
			return nil, err
		}
		for _, d := range res.DomainList {
			out = append(out, strings.TrimSuffix(d.Name, "."))
		}
		if len(res.DomainList) == 0 || len(out) >= res.DomainCountInfo.AllTotal {
			break
		}
	}
	return out, nil
}

func (c *tencentClient) Records(zone, rr, typ string) ([]dnsHit, error) {
	sub := rr
	if sub == "" {
		sub = "@"
	}
	var res struct {
		RecordList []struct {
			RecordID int64  `json:"RecordId"`
			Name     string `json:"Name"`
			Type     string `json:"Type"`
			Value    string `json:"Value"`
			TTL      int    `json:"TTL"`
			Line     string `json:"Line"`
			Status   string `json:"Status"`
		} `json:"RecordList"`
	}
	req := map[string]any{"Domain": zone, "Subdomain": sub, "Limit": 3000}
	if typ != "" {
		req["RecordType"] = typ
	}
	if err := c.call("DescribeRecordList", req, &res); err != nil {
		return nil, friendlyTencent(err)
	}
	out := make([]dnsHit, 0, len(res.RecordList))
	for _, r := range res.RecordList {
		h := dnsHit{
			ID: strconv.FormatInt(r.RecordID, 10), Zone: zone, RR: r.Name,
			Type: r.Type, Value: r.Value, TTL: r.TTL, Line: r.Line,
		}
		out = append(out, h)
	}
	return out, nil
}

func (c *tencentClient) Create(zone, rr, typ, value string, ttl int) (dnsHit, error) {
	sub := rr
	if sub == "" {
		sub = "@"
	}
	var res struct {
		RecordID int64 `json:"RecordId"`
	}
	err := c.call("CreateRecord", map[string]any{
		"Domain": zone, "SubDomain": sub, "RecordType": typ,
		"RecordLine": "默认", "Value": value, "TTL": ttl,
	}, &res)
	if err != nil {
		return dnsHit{}, friendlyTencent(err)
	}
	return dnsHit{ID: strconv.FormatInt(res.RecordID, 10), Zone: zone, RR: sub, Type: typ, Value: value, TTL: ttl}, nil
}

func (c *tencentClient) Update(h dnsHit, value string, ttl int) error {
	id, _ := strconv.ParseInt(h.ID, 10, 64)
	line := h.Line
	if line == "" {
		line = "默认"
	}
	sub := h.RR
	if sub == "" {
		sub = "@"
	}
	err := c.call("ModifyRecord", map[string]any{
		"Domain": h.Zone, "RecordId": id, "SubDomain": sub, "RecordType": h.Type,
		"RecordLine": line, "Value": value, "TTL": ttl,
	}, nil)
	return friendlyTencent(err)
}

func (c *tencentClient) Test() (int, error) {
	var res struct {
		DomainCountInfo struct {
			AllTotal int `json:"AllTotal"`
		} `json:"DomainCountInfo"`
	}
	err := c.call("DescribeDomainList", map[string]any{"Offset": 0, "Limit": 1}, &res)
	if err != nil {
		return 0, friendlyTencent(err)
	}
	return res.DomainCountInfo.AllTotal, nil
}

func friendlyTencent(err error) error {
	te, ok := err.(*tcError)
	if !ok {
		return err
	}
	switch {
	case strings.Contains(te.Code, "AuthFailure.SignatureFailure"):
		return fmt.Errorf("腾讯云签名校验失败，先确认路由器时间已同步（%s）", te.Message)
	case strings.Contains(te.Code, "AuthFailure.SecretIdNotFound"):
		return fmt.Errorf("SecretId 不存在或已禁用（%s）", te.Message)
	case strings.Contains(te.Code, "UnauthorizedOperation"):
		return fmt.Errorf("密钥权限不足，需要 DNSPod 的读写权限（%s）", te.Message)
	case strings.Contains(te.Code, "ResourceNotFound.NoDataOfDomain"):
		return fmt.Errorf("腾讯云账号里没有这个域名，先把域名接入 DNSPod（%s）", te.Message)
	}
	return err
}
