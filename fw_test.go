package main

import (
	"strings"
	"testing"
)

func testForwardConfig() ForwardConfig {
	return ForwardConfig{
		Enable:  true,
		Backend: "iptables",
		Rules: []ForwardRule{
			{Name: "NAS", Proto: "tcp", Port: 5000, ToHost: "192.168.10.10", ToPort: 5000},
			{Name: "游戏", Proto: "both", Port: 27015, ToHost: "192.168.10.20", ToPort: 27015},
			{Name: "停用的", Proto: "tcp", Port: 9000, ToHost: "192.168.10.30", ToPort: 80, Disable: true},
		},
	}
}

func TestActiveForwardRules(t *testing.T) {
	got := activeForwardRules(testForwardConfig())
	if len(got) != 2 {
		t.Fatalf("停用的规则应被过滤，剩 2 条，实际 %d 条", len(got))
	}
}

func TestPersistScriptIptables(t *testing.T) {
	fc := testForwardConfig()
	script := renderPersistScript(fwTool{kind: "iptables", bin: "iptables"}, fc)

	must := []string{
		"#!/bin/sh",
		"$IPT -t nat -N LP_FWD",
		"-t nat -A LP_FWD -p tcp --dport 5000 -j DNAT --to-destination 192.168.10.10:5000",
		"-t nat -A LP_FWD -p udp --dport 27015 -j DNAT --to-destination 192.168.10.20:27015",
		"-A LP_ACL -p tcp -d 192.168.10.10 --dport 5000 -j ACCEPT",
		"-t nat -I POSTROUTING 1 -j LP_MASQ",
	}
	for _, m := range must {
		if !strings.Contains(script, m) {
			t.Errorf("持久化脚本缺少：%s", m)
		}
	}
	// 停用规则不能出现在脚本里
	if strings.Contains(script, "9000") {
		t.Error("停用的规则不应写进开机脚本")
	}
	// 没有开 hairpin 时不应生成 MASQUERADE 规则（链本身保留，避免残留）
	if strings.Contains(script, "-j MASQUERADE") {
		t.Error("未开启内网回环时不应生成 MASQUERADE 规则")
	}
}

func TestPersistScriptHairpin(t *testing.T) {
	fc := testForwardConfig()
	fc.Hairpin = true
	script := renderPersistScript(fwTool{kind: "iptables", bin: "iptables"}, fc)
	if !strings.Contains(script, "-A LP_MASQ -p tcp -d 192.168.10.10 --dport 5000 -j MASQUERADE") {
		t.Error("开启内网回环后应生成 MASQUERADE 规则")
	}
}

func TestNftScript(t *testing.T) {
	fc := testForwardConfig()
	fc.Hairpin = true
	s := buildNftScript(fc)

	must := []string{
		"add table inet lp_fwd",
		"delete table inet lp_fwd",
		"type nat hook prerouting priority -110",
		"tcp dport 5000 dnat ip to 192.168.10.10:5000",
		"udp dport 27015 dnat ip to 192.168.10.20:27015",
		"ip daddr 192.168.10.10 tcp dport 5000 accept",
		"type nat hook postrouting priority 100",
	}
	for _, m := range must {
		if !strings.Contains(s, m) {
			t.Errorf("nft 脚本缺少：%s", m)
		}
	}
	if strings.Contains(s, "9000") {
		t.Error("停用规则不应出现在 nft 脚本里")
	}
}

func TestForwardConfigValidation(t *testing.T) {
	base := func() *Config {
		c := DefaultConfig()
		c.TLS.CertDir = "/data/certs"
		c.Forward = testForwardConfig()
		return c
	}

	if err := base().Normalize(); err != nil {
		t.Fatalf("正常配置不该报错: %v", err)
	}

	// 端口冲突（同协议同端口）
	c := base()
	c.Forward.Rules = append(c.Forward.Rules, ForwardRule{Name: "冲突", Proto: "tcp", Port: 5000, ToHost: "192.168.10.99", ToPort: 80})
	if err := c.Normalize(); err == nil || !strings.Contains(err.Error(), "重复占用") {
		t.Errorf("端口冲突应报错，实际: %v", err)
	}

	// tcp 与 udp 同端口不算冲突
	c = base()
	c.Forward.Rules = append(c.Forward.Rules, ForwardRule{Name: "同端口UDP", Proto: "udp", Port: 5000, ToHost: "192.168.10.99", ToPort: 80})
	if err := c.Normalize(); err != nil {
		t.Errorf("tcp 与 udp 用同一端口不应冲突: %v", err)
	}

	// 目标必须是 IP，不能是域名
	c = base()
	c.Forward.Rules[0].ToHost = "nas.local"
	if err := c.Normalize(); err == nil || !strings.Contains(err.Error(), "IP") {
		t.Errorf("目标填域名应报错，实际: %v", err)
	}

	// 暂不支持 IPv6 目标
	c = base()
	c.Forward.Rules[0].ToHost = "fe80::1"
	if err := c.Normalize(); err == nil || !strings.Contains(err.Error(), "IPv4") {
		t.Errorf("IPv6 目标应给出明确提示，实际: %v", err)
	}

	// 端口越界
	c = base()
	c.Forward.Rules[0].Port = 70000
	if err := c.Normalize(); err == nil {
		t.Error("端口越界应报错")
	}

	// 后端取值校验
	c = base()
	c.Forward.Backend = "ufw"
	if err := c.Normalize(); err == nil {
		t.Error("未知后端应报错")
	}
}

func TestACMEConfigValidation(t *testing.T) {
	c := DefaultConfig()
	c.TLS.CertDir = "/data/certs"
	c.ACME.Enable = true
	c.ACME.Email = "me@example.com"
	c.ACME.Domains = []string{"nas.example.com", "*.pan.example.com"}

	// 没填 AccessKey 且 DDNS 也没填 → 报错
	if err := c.Normalize(); err == nil || !strings.Contains(err.Error(), "AccessKey") {
		t.Errorf("缺少 AccessKey 应报错，实际: %v", err)
	}

	// 复用 DDNS 的 AccessKey
	c.DDNS.AccessKey = "LTAI-x"
	c.DDNS.SecretKey = "secret"
	if err := c.Normalize(); err != nil {
		t.Fatalf("应复用 DDNS 的 AccessKey: %v", err)
	}
	// 只做运行时复用，不写回配置——否则之后改 DDNS 密钥，证书这边会一直用旧的
	if c.ACME.AccessKey != "" {
		t.Error("不应把 DDNS 的 AccessKey 写回 ACME 配置")
	}
	if merged := mergeACMECreds(c.ACME, c.DDNS); merged.AccessKey != "LTAI-x" {
		t.Errorf("运行时合并后应拿到 DDNS 的 AccessKey，得到 %q", merged.AccessKey)
	}

	// 证书目录默认继承 TLS.CertDir
	if c.ACME.CertDir != "/data/certs" {
		t.Errorf("ACME 证书目录应继承 TLS 设置，得到 %q", c.ACME.CertDir)
	}

	// IP 不能用来签域名证书
	c2 := DefaultConfig()
	c2.TLS.CertDir = "/data/certs"
	c2.ACME.Domains = []string{"192.168.1.1"}
	if err := c2.Normalize(); err == nil || !strings.Contains(err.Error(), "IP") {
		t.Errorf("用 IP 申请证书应报错，实际: %v", err)
	}
}

func TestPersistScriptOpensLocalPorts(t *testing.T) {
	fc := testForwardConfig()
	fc.LocalPorts = []int{8443, 80}
	script := renderPersistScript(fwTool{kind: "iptables", bin: "iptables"}, fc)

	must := []string{
		"$IPT -N LP_IN",
		"$IPT -I INPUT 1 -j LP_IN",
		"$IPT -A LP_IN -p tcp --dport 8443 -j ACCEPT",
		"$IPT -A LP_IN -p tcp --dport 80 -j ACCEPT",
		"$IPT -A LP_IN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
	}
	for _, m := range must {
		if !strings.Contains(script, m) {
			t.Errorf("开机脚本缺少: %s\n---\n%s", m, script)
		}
	}
	// 管理面板端口绝不能被自动放行
	if strings.Contains(script, "--dport 8081") {
		t.Error("开机脚本不应放行管理面板端口")
	}
}

func TestPersistScriptNoLocalPortsNoInputChain(t *testing.T) {
	script := renderPersistScript(fwTool{kind: "iptables", bin: "iptables"}, testForwardConfig())
	if strings.Contains(script, "LP_IN") {
		t.Error("没有本机端口时不该动 INPUT 链")
	}
}

func TestNftScriptOpensLocalPorts(t *testing.T) {
	fc := testForwardConfig()
	fc.LocalPorts = []int{8443, 80}
	s := buildNftScript(fc)
	if !strings.Contains(s, "chain input") {
		t.Fatalf("nft 脚本缺少 input 链:\n%s", s)
	}
	if !strings.Contains(s, "tcp dport { 8443, 80 } accept") {
		t.Errorf("nft 脚本未放行端口:\n%s", s)
	}
	if strings.Contains(buildNftScript(testForwardConfig()), "chain input") {
		t.Error("没有本机端口时不该生成 input 链")
	}
}

func TestLocalForwardPorts(t *testing.T) {
	c := DefaultConfig()
	c.Listen = ":8080"
	c.TLS.Enable = true
	c.TLS.CertDir = "/tmp/certs" // 启用 HTTPS 必须有证书来源
	c.TLS.Redirect = true
	c.TLS.HTTPListen = ""
	if err := c.Normalize(); err != nil { // 勾了跳转但没填地址 → 默认 :80
		t.Fatalf("配置校验失败: %v", err)
	}
	if c.TLS.HTTPListen != ":80" {
		t.Fatalf("勾选跳转后应默认 :80，得到 %q", c.TLS.HTTPListen)
	}
	got := localForwardPorts(c)
	want := []int{8080, 80}
	if len(got) != len(want) {
		t.Fatalf("期望 %v，得到 %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("期望 %v，得到 %v", want, got)
		}
	}

	// 没开跳转时，HTTP 端口不该被放行
	c.TLS.Redirect = false
	if got := localForwardPorts(c); len(got) != 1 || got[0] != 8080 {
		t.Errorf("未开跳转时只应放行反代端口，得到 %v", got)
	}
}
