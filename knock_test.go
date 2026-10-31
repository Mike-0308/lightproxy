package main

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestKnockKey(t *testing.T) {
	cases := []struct {
		addr string
		want string
	}{
		{"[2408:8274:219:1610:ad19:354d:4004:8d53]:8686", "2408:8274:219:1610::/64"},
		{"[2408:8274:219:1610:1111:2222:3333:4444]:12345", "2408:8274:219:1610::/64"},
		{"[2408:8274:219:1611:1111:2222:3333:4444]:1", "2408:8274:219:1611::/64"},
		{"192.168.31.5:3389", "192.168.31.5/32"},
		{"127.0.0.1:5000", "127.0.0.1/32"},
		{"bogus", ""},
	}
	for _, c := range cases {
		if got := knockKey(c.addr); got != c.want {
			t.Errorf("knockKey(%q) = %q，期望 %q", c.addr, got, c.want)
		}
	}
	// 隐私扩展模拟：同一 /64 内不同接口 ID 必须落进同一个键
	a := knockKey("[2408:8274:219:1610:aaaa:bbbb:cccc:1]:10")
	b := knockKey("[2408:8274:219:1610:dddd:eeee:ffff:2]:20")
	if a != b {
		t.Errorf("同一 /64 的两个地址键不同：%q vs %q", a, b)
	}
}

func TestKnockRecordAllow(t *testing.T) {
	tb := &knockTable{ok: map[string]time.Time{}, denied: map[string]time.Time{}}
	if tb.allowed("[2408::1]:100") {
		t.Error("未记录的来源不应放行")
	}
	tb.record("[2408:8274:219:1610:1:2:3:4]:5678")
	if !tb.allowed("[2408:8274:219:1610:aa:bb:cc:dd]:9999") {
		t.Error("同 /64 的另一地址应放行")
	}
	if tb.allowed("[2408:8274:219:1611:1:2:3:4]:10") {
		t.Error("不同 /64 不应放行")
	}
	tb.record("10.1.2.3:80")
	if !tb.allowed("10.1.2.3:81") {
		t.Error("同 IPv4 地址应放行")
	}
	if tb.allowed("10.1.2.4:81") {
		t.Error("其他 IPv4 不应放行")
	}
	// 过期
	tb.ok["2408:8274:219:1610::/64"] = time.Now().Add(-time.Second)
	if tb.allowed("[2408:8274:219:1610:1:2:3:4]:5") {
		t.Error("过期条目不应放行")
	}
	if _, still := tb.ok["2408:8274:219:1610::/64"]; still {
		t.Error("过期条目应被清除")
	}
}

func TestKnockDisabled(t *testing.T) {
	defer SetKnockEnabled(false)
	SetKnockEnabled(false)
	if !knockOK("8.8.8.8:1") {
		t.Error("敲门未启用时应全部放行")
	}
	SetKnockEnabled(true)
	if knockOK("8.8.8.8:1") {
		t.Error("启用后未敲门的来源不应放行")
	}
	knocks.record("8.8.8.8:1")
	if !knockOK("8.8.8.8:2") {
		t.Error("启用后已敲门的来源应放行")
	}
}

func TestKnockDenyLogCooldown(t *testing.T) {
	tb := &knockTable{ok: map[string]time.Time{}, denied: map[string]time.Time{}}
	if !tb.denyLoggable("1.2.3.4:10") {
		t.Error("首次应允许记日志")
	}
	if tb.denyLoggable("1.2.3.4:10") {
		t.Error("冷却期内不应重复记日志")
	}
	if !tb.denyLoggable("5.6.7.8:10") {
		t.Error("不同来源应允许记日志")
	}
}

func TestKnockRequiredDependsOnEntry(t *testing.T) {
	c := DefaultConfig()
	c.Security.KnockForward = true
	c.Security.EntryPath = ""
	if c.knockRequired() {
		t.Error("没有安全入口时敲门不应生效")
	}
	c.Security.EntryPath = "/x7k2m"
	if !c.knockRequired() {
		t.Error("入口 + 开关都齐时应生效")
	}
	c.Security.KnockForward = false
	if c.knockRequired() {
		t.Error("开关关掉后不应生效")
	}
}

// relay 收发都要过敲门检查：TCP 未敲门立即断开，敲了门才正常转发
func TestRelayKnockGate(t *testing.T) {
	defer SetKnockEnabled(false)
	be, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer be.Close()
	go func() {
		for {
			c, err := be.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(c, c)
				c.Close()
			}(c)
		}
	}()
	bePort := be.Addr().(*net.TCPAddr).Port

	r := NewRelay(nil)
	port := freePort(t)
	r.Apply([]ForwardRule{{Name: "测试", Proto: "tcp", Port: port, ToHost: "127.0.0.1", ToPort: bePort}})
	defer r.Stop()

	dial := func() net.Conn {
		var conn net.Conn
		for i := 0; i < 50; i++ {
			c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
			if err == nil {
				conn = c
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		return conn
	}

	SetKnockEnabled(true)
	conn := dial()
	if conn == nil {
		t.Fatal("转发监听未就绪")
	}
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	one := make([]byte, 1)
	if _, err := conn.Read(one); err == nil {
		t.Error("未敲门来源应被立即断开，不应有回包")
	}
	conn.Close()

	knocks.record("127.0.0.1:12345")
	conn = dial()
	if conn == nil {
		t.Fatal("第二次连接未就绪")
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	msg := "knock-ok"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("敲门后回读失败: %v", err)
	}
	if string(buf) != msg {
		t.Errorf("期望 %q，得到 %q", msg, buf)
	}
	conn.Close()
}
