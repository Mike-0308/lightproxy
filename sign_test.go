package main

import "testing"

// 基准向量由阿里云官方 Python SDK 的 RpcSignatureComposer 生成，
// 用来确认自实现签名与官方完全一致（避免上机后才发现 SignatureDoesNotMatch）。
func TestAliyunSignatureMatchesOfficialSDK(t *testing.T) {
	c := &aliyunClient{accessKey: "testid", secretKey: "testsecret"}
	params := map[string]string{
		"AccessKeyId":      "testid",
		"Action":           "DescribeDomains",
		"Format":           "JSON",
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   "abc123",
		"SignatureVersion": "1.0",
		"Timestamp":        "2026-01-01T00:00:00Z",
		"Version":          "2015-01-09",
		"PageSize":         "1",
	}
	const want = "8MbwfV3v7k7bBwPeY58RbPRIlOU="
	if got := c.sign(params); got != want {
		t.Fatalf("签名不一致\n got: %s\nwant: %s", got, want)
	}
}

func TestPercentEncode(t *testing.T) {
	cases := map[string]string{
		"abc-_.~":              "abc-_.~",
		"a b":                  "a%20b",
		"a*b":                  "a%2Ab",
		"a+b":                  "a%2Bb",
		"2026-01-01T00:00:00Z": "2026-01-01T00%3A00%3A00Z",
		"中文":                   "%E4%B8%AD%E6%96%87",
	}
	for in, want := range cases {
		if got := percentEncode(in); got != want {
			t.Errorf("percentEncode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHostAndPathMatch(t *testing.T) {
	if !hostMatch([]string{"*.example.com"}, "a.example.com") {
		t.Fatal("泛域名应匹配一级子域")
	}
	if !hostMatch([]string{"*.example.com"}, "a.b.example.com") {
		t.Fatal("泛域名应匹配多级子域")
	}
	if hostMatch([]string{"*.example.com"}, "example.com") {
		t.Fatal("泛域名不应匹配裸域")
	}
	if hostMatch([]string{"example.com"}, "other.com") {
		t.Fatal("不应误匹配")
	}
	if !pathMatch("/api", "/api") || !pathMatch("/api", "/api/users") {
		t.Fatal("前缀应匹配自身与子路径")
	}
	if pathMatch("/api", "/apix") {
		t.Fatal("前缀不应匹配 /apix")
	}
	if !pathMatch("/", "/anything") {
		t.Fatal("根路径应匹配全部")
	}
}
