package main

import "testing"

func TestResolveRecord(t *testing.T) {
	zones := []string{"example.com", "example.com"}

	cases := []struct {
		name       string
		domain, rr string
		wantZone   string
		wantRR     string
	}{
		{"主域名 + @", "example.com", "@", "example.com", "@"},
		{"主域名 + 泛解析", "example.com", "*", "example.com", "*"},
		{"主域名 + 前缀", "example.com", "home", "example.com", "home"},
		{"完整泛域名写在域名栏", "*.example.com", "@", "example.com", "*"},
		{"完整 FQDN 写在域名栏", "home.example.com", "@", "example.com", "home"},
		{"多级前缀", "a.b.example.com", "@", "example.com", "a.b"},
		{"大小写与结尾点", "NAS.Example.COM.", "@", "example.com", "nas"},
	}

	for _, c := range cases {
		gotZone, gotRR := resolveRecord(DNSRecord{Domain: c.domain, RR: c.rr}, zones)
		if gotZone != c.wantZone || gotRR != c.wantRR {
			t.Errorf("%s: 得到 (%s, %s)，期望 (%s, %s)", c.name, gotZone, gotRR, c.wantZone, c.wantRR)
		}
	}
}

func TestResolveRecordWithoutZones(t *testing.T) {
	// 拉不到域名列表时保持用户填写值，交给接口报错
	z, rr := resolveRecord(DNSRecord{Domain: "*.example.com", RR: "@"}, nil)
	if z != "*.example.com" || rr != "@" {
		t.Errorf("无域名列表时应原样返回，得到 (%s, %s)", z, rr)
	}
}

func TestFriendlyAPIError(t *testing.T) {
	err := friendlyAPIError(&APIError{Code: "InvalidDomainName.NoExist", Message: "The specified domain name does not exist."}, "*.example.com")
	msg := err.Error()
	if msg == "InvalidDomainName.NoExist: The specified domain name does not exist." {
		t.Fatal("未翻译成中文提示")
	}
	if !containsAll(msg, "主域名", "主机记录") {
		t.Errorf("提示应告诉用户怎么填，实际: %s", msg)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !contains(s, sub) {
			return false
		}
	}
	return true
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
