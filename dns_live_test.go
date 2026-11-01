//go:build live

package main

import (
	"testing"
)

// 用一对假密钥打真实接口，只为确认「请求能到服务端、签名能被解析」。
// 真密钥下返回的是凭证错误，说明协议栈没问题；返回签名错误则说明算法要修。
//	go test -tags live -run TestLiveProviderReach -v
func TestLiveProviderReach(t *testing.T) {
	for _, id := range []string{"aliyun", "tencent", "huawei", "baidu", "volcengine", "cloudflare", "duckdns", "dynv6"} {
		id := id
		t.Run(id, func(t *testing.T) {
			p, err := newDNSProvider(DDNSConfig{Provider: id, AccessKey: "AKIDfakefakefakefakefakefake", SecretKey: "fakefakefakefakefakefakefakefake"})
			if err != nil {
				t.Fatalf("构造失败: %v", err)
			}
			n, err := p.Test()
			t.Logf("%s -> n=%d err=%v", id, n, err)
		})
	}
}
