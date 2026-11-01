package main

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// fakeProvider 用来验证各服务商共用的同步逻辑，不碰网络。
type fakeProvider struct {
	hits      []dnsHit
	created   []dnsHit
	updated   []dnsHit
	createErr error
}

func (f *fakeProvider) Provider() string             { return "fake" }
func (f *fakeProvider) ListZones() ([]string, error) { return []string{"example.com"}, nil }
func (f *fakeProvider) Records(zone, rr, typ string) ([]dnsHit, error) {
	var out []dnsHit
	for _, h := range f.hits {
		if typ != "" && h.Type != typ {
			continue
		}
		if strings.EqualFold(h.RR, rr) && strings.EqualFold(h.Zone, zone) {
			out = append(out, h)
		}
	}
	return out, nil
}
func (f *fakeProvider) Create(zone, rr, typ, value string, ttl int) (dnsHit, error) {
	if f.createErr != nil {
		return dnsHit{}, f.createErr
	}
	h := dnsHit{ID: "new", Zone: zone, RR: rr, Type: typ, Value: value, TTL: ttl}
	f.created = append(f.created, h)
	return h, nil
}
func (f *fakeProvider) Update(h dnsHit, value string, ttl int) error {
	f.updated = append(f.updated, dnsHit{ID: h.ID, Zone: h.Zone, RR: h.RR, Type: h.Type, Value: value, TTL: ttl})
	return nil
}
func (f *fakeProvider) Test() (int, error) { return 1, nil }

func newTestManager(t *testing.T) *DDNSManager {
	t.Helper()
	return NewDDNSManager(DDNSConfig{Enable: true, TTL: 600, Interval: 300, Provider: "aliyun",
		Records: []DNSRecord{{Domain: "example.com", RR: "@", Type: "A"}}},
		NewLogBuffer(50, ""))
}

func TestSyncRecordCreatesWhenMissing(t *testing.T) {
	m := newTestManager(t)
	f := &fakeProvider{}
	r := DNSRecord{Domain: "example.com", RR: "home", Type: "A"}
	if err := m.syncRecord(f, r, "example.com", "home", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if len(f.created) != 1 || f.created[0].Value != "1.2.3.4" || f.created[0].TTL != 600 {
		t.Fatalf("期望新增一条 TTL=600 的记录，实际 %+v", f.created)
	}
	if s := m.Snapshot().Records; len(s) != 1 || s[0].State != "added" {
		t.Fatalf("状态应为 added，实际 %+v", s)
	}
}

func TestSyncRecordUpdatesChangedValue(t *testing.T) {
	m := newTestManager(t)
	f := &fakeProvider{hits: []dnsHit{{ID: "r1", Zone: "example.com", RR: "home", Type: "A", Value: "9.9.9.9", TTL: 120}}}
	r := DNSRecord{Domain: "example.com", RR: "home", Type: "A"}
	if err := m.syncRecord(f, r, "example.com", "home", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if len(f.updated) != 1 || f.updated[0].Value != "1.2.3.4" || f.updated[0].TTL != 120 {
		t.Fatalf("期望用原 TTL 更新，实际 %+v", f.updated)
	}
	if len(f.created) != 0 {
		t.Fatal("不应该新建记录")
	}
	if s := m.Snapshot().Records; s[0].State != "updated" {
		t.Fatalf("状态应为 updated，实际 %+v", s)
	}
}

func TestSyncRecordNoopWhenSame(t *testing.T) {
	m := newTestManager(t)
	f := &fakeProvider{hits: []dnsHit{{ID: "r1", Zone: "example.com", RR: "@", Type: "A", Value: "1.2.3.4", TTL: 600}}}
	r := DNSRecord{Domain: "example.com", RR: "@", Type: "A"}
	if err := m.syncRecord(f, r, "example.com", "@", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if len(f.created)+len(f.updated) != 0 {
		t.Fatalf("值没变不应写接口，实际 created=%v updated=%v", f.created, f.updated)
	}
	if s := m.Snapshot().Records; s[0].State != "ok" {
		t.Fatalf("状态应为 ok，实际 %+v", s)
	}
}

// 创建失败（多半是并发导致的重复）时应回查一次并转为更新。
func TestSyncRecordFallsBackToUpdateOnCreateError(t *testing.T) {
	m := newTestManager(t)
	f := &fakeProvider{
		createErr: fmt.Errorf("DomainRecordDuplicate"),
		hits:      []dnsHit{{ID: "r1", Zone: "example.com", RR: "@", Type: "A", Value: "9.9.9.9", TTL: 600}},
	}
	r := DNSRecord{Domain: "example.com", RR: "@", Type: "A"}
	if err := m.syncRecord(f, r, "example.com", "@", "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	if len(f.updated) != 1 {
		t.Fatalf("应回退到更新，实际 %+v", f.updated)
	}
}

func TestProviderSpecsComplete(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range providerSpecs {
		if s.ID == "" || s.Name == "" || s.KeyLbl == "" {
			t.Fatalf("服务商描述不完整: %+v", s)
		}
		if seen[s.ID] {
			t.Fatalf("服务商 ID 重复: %s", s.ID)
		}
		seen[s.ID] = true
		if s.NeedSec && s.SecLbl == "" {
			t.Fatalf("%s 需要 Secret 但没给标签", s.ID)
		}
		// 每个服务商都必须能构造出客户端
		p, err := newDNSProvider(DDNSConfig{Provider: s.ID, AccessKey: "ak", SecretKey: "sk"})
		if err != nil {
			t.Fatalf("%s 构造失败: %v", s.ID, err)
		}
		if p.Provider() != s.ID {
			t.Fatalf("%s 报告成 %s", s.ID, p.Provider())
		}
	}
}

func TestNormalizeProviderAliases(t *testing.T) {
	cases := map[string]string{
		"":            "aliyun",
		"AliDNS":      "aliyun",
		"dnspod":      "tencent",
		"Tencent":     "tencent",
		"huaweicloud": "huawei",
		"bce":         "baidu",
		"volc":        "volcengine",
		"cf":          "cloudflare",
		"duck":        "duckdns",
		"dynv6":       "dynv6",
	}
	for in, want := range cases {
		if got := normalizeProvider(in); got != want {
			t.Errorf("normalizeProvider(%q)=%q, 期望 %q", in, got, want)
		}
	}
}

func TestJoinSplitRR(t *testing.T) {
	if got := joinRR("example.com", "@"); got != "example.com" {
		t.Errorf("joinRR @ = %q", got)
	}
	if got := joinRR("example.com", "home"); got != "home.example.com" {
		t.Errorf("joinRR home = %q", got)
	}
	if got := splitRR("home.example.com.", "example.com."); got != "home" {
		t.Errorf("splitRR = %q", got)
	}
	if got := splitRR("example.com", "example.com"); got != "@" {
		t.Errorf("splitRR 根域 = %q", got)
	}
}

// 各云厂商的规范查询串必须是 RFC3986 且按字典序。
func TestCanonicalQuery(t *testing.T) {
	v := url.Values{}
	v.Set("b", "2")
	v.Set("a", "1 2")
	v.Set("A", "/")
	got := canonicalQuery(v)
	want := "A=%2F&a=1%202&b=2"
	if got != want {
		t.Fatalf("canonicalQuery=%q, 期望 %q", got, want)
	}
}

func TestHWCanonicalURI(t *testing.T) {
	if got := hwCanonicalURI("/v2/zones"); got != "/v2/zones/" {
		t.Fatalf("华为 CanonicalURI 末尾必须有斜杠: %q", got)
	}
	if got := hwCanonicalURI("/v2/zones/abc/recordsets/"); got != "/v2/zones/abc/recordsets/" {
		t.Fatalf("多段路径: %q", got)
	}
}

func TestDuckSub(t *testing.T) {
	for in, want := range map[string]string{
		"myhome":             "myhome",
		"myhome.duckdns.org": "myhome",
		"MyHome.DuckDNS.org": "myhome",
	} {
		if got := duckSub(in); got != want {
			t.Errorf("duckSub(%q)=%q, 期望 %q", in, got, want)
		}
	}
}
