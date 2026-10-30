package main

import "testing"

func TestCheckListenRejectsBadPort(t *testing.T) {
	c := DefaultConfig()
	c.Listen = ":bad host"
	if err := c.Normalize(); err == nil {
		t.Fatal("端口含空格应被拒绝")
	}
	c.Listen = ":0"
	if err := c.Normalize(); err == nil {
		t.Fatal("端口 0 应被拒绝")
	}
	c.Listen = ":99999"
	if err := c.Normalize(); err == nil {
		t.Fatal("端口 99999 应被拒绝")
	}
	// 合法值不应被误伤
	for _, ok := range []string{":8080", "0.0.0.0:8081", "[::]:8443"} {
		c.Listen = ok
		if err := c.Normalize(); err != nil {
			t.Errorf("合法地址 %s 被误拒: %v", ok, err)
		}
	}
}
