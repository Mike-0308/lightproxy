package main

import "testing"

// 反代端口和「HTTP 跳转监听」写成同一个端口时，不该再起第二个监听
// （内核会直接 EADDRINUSE），同端口的 http:// 已经由嗅探层跳转了。
func TestSameListenPort(t *testing.T) {
	yes := [][2]string{
		{":8686", ":8686"},
		{":8686", "0.0.0.0:8686"},
		{":8686", "[::]:8686"},
		{"0.0.0.0:8686", "[::]:8686"},
		{"  :8686  ", ":8686"},
	}
	for _, c := range yes {
		if !sameListenPort(c[0], c[1]) {
			t.Errorf("%q 与 %q 应算同一端口", c[0], c[1])
		}
	}

	no := [][2]string{
		{":8686", ":8687"},
		{":8686", ":80"},
		{":8686", ""},
		{"", ""},
		{":8686", "listen"},
	}
	for _, c := range no {
		if sameListenPort(c[0], c[1]) {
			t.Errorf("%q 与 %q 不该算同一端口", c[0], c[1])
		}
	}
}

// 同端口时防火墙只需要放行一次，别重复下发。
func TestLocalForwardPortsDedupSamePort(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Listen = ":8686"
	cfg.TLS.Enable = true
	cfg.TLS.Redirect = true
	cfg.TLS.HTTPListen = ":8686"

	ports := localForwardPorts(cfg)
	count := 0
	for _, p := range ports {
		if p == 8686 {
			count++
		}
	}
	if count != 1 {
		t.Errorf("8686 应只出现一次，实际 %v", ports)
	}
}
