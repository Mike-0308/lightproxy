package main

import (
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ---------------- 规则过滤 ----------------

func TestUsableForwardRules(t *testing.T) {
	fc := testForwardConfig()
	fc.Occupied = []int{8686, 18080}
	fc.Rules = append(fc.Rules,
		ForwardRule{Name: "撞反代", Proto: "tcp", Port: 8686, ToHost: "192.168.10.10", ToPort: 3389},
		ForwardRule{Name: "撞面板", Proto: "tcp", Port: 18080, ToHost: "192.168.10.10", ToPort: 80},
		ForwardRule{Name: "坏目标", Proto: "tcp", Port: 6000, ToHost: "", ToPort: 0},
	)

	usable, conflicts := usableForwardRules(fc)
	if len(usable) != 2 {
		t.Fatalf("应剩 2 条可用规则，实际 %d 条: %v", len(usable), usable)
	}
	if len(conflicts) != 2 || conflicts[0] != 8686 || conflicts[1] != 18080 {
		t.Errorf("冲突端口应为 [8686 18080]，实际 %v", conflicts)
	}
}

func TestMergePorts(t *testing.T) {
	got := mergePorts([]int{8686, 100}, []int{100, 23323, 0, -1})
	want := []int{100, 8686, 23323}
	if len(got) != len(want) {
		t.Fatalf("期望 %v，实际 %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("期望 %v，实际 %v", want, got)
		}
	}
}

// ---------------- 持久化脚本 ----------------

func TestPersistScriptOpensForwardPortsIPv6(t *testing.T) {
	fc := testForwardConfig()
	fc.LocalPorts = []int{8686}
	fc.Occupied = []int{8686, 18080}
	// 模拟 Apply 合并后的放行列表：反代端口 + 映射端口
	fc.LocalPorts = mergePorts(fc.LocalPorts, relayPorts(mustUsable(t, fc)))

	script := renderPersistScript(fwTool{kind: "iptables", bin: "iptables"}, fc)
	for _, m := range []string{
		"$IP6 -A LP_IN6 -p tcp --dport 8686 -j ACCEPT",
		"$IP6 -A LP_IN6 -p tcp --dport 5000 -j ACCEPT",
		"$IP6 -A LP_IN6 -p tcp --dport 27015 -j ACCEPT",
	} {
		if !strings.Contains(script, m) {
			t.Errorf("开机脚本缺少 IPv6 放行: %s\n---\n%s", m, script)
		}
	}
	// 冲突端口不能进 DNAT（这里 8686 已被反代占用，但不在规则里；换一条验证）
	fc2 := testForwardConfig()
	fc2.Occupied = []int{5000}
	script2 := renderPersistScript(fwTool{kind: "iptables", bin: "iptables"}, fc2)
	if strings.Contains(script2, "--dport 5000 -j DNAT") {
		t.Error("与反代端口冲突的规则不应下发 DNAT")
	}
	if !strings.Contains(script2, "--dport 27015 -j DNAT") {
		t.Error("正常规则应保留 DNAT")
	}
}

func TestForwardStateValidation(t *testing.T) {
	fc := testForwardConfig()
	fc.Occupied = []int{27015}
	if _, conflicts := usableForwardRules(fc); len(conflicts) != 1 {
		t.Errorf("27015 应被识别为冲突端口，实际 %v", conflicts)
	}
	if fc.V6On() != true {
		t.Error("未设置 v6Forward 时应默认开启")
	}
	off := false
	fc.V6Forward = &off
	if fc.V6On() {
		t.Error("v6Forward=false 时应关闭")
	}
}

func mustUsable(t *testing.T, fc ForwardConfig) []ForwardRule {
	t.Helper()
	usable, _ := usableForwardRules(fc)
	return usable
}

// ---------------- 用户态转发 ----------------

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func TestRelayTCPForward(t *testing.T) {
	// 后端：echo 服务
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

	// 给监听一点启动时间
	var conn net.Conn
	for i := 0; i < 50; i++ {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), time.Second)
		if err == nil {
			conn = c
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if conn == nil {
		t.Fatal("转发监听未就绪")
	}
	msg := "hello-relay-tcp"
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("回读失败: %v", err)
	}
	if string(buf) != msg {
		t.Errorf("期望 %q，得到 %q", msg, buf)
	}
	conn.Close()

	// 后端不通时连接应立即被关掉
	bad := NewRelay(nil)
	badPort := freePort(t)
	bad.Apply([]ForwardRule{{Name: "不通", Proto: "tcp", Port: badPort, ToHost: "127.0.0.1", ToPort: 1}})
	defer bad.Stop()
	var c2 net.Conn
	for i := 0; i < 50; i++ {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(badPort), time.Second)
		if err == nil {
			c2 = c
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if c2 == nil {
		t.Fatal("第二个监听未就绪")
	}
	c2.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c2.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	one := make([]byte, 1)
	if _, err := c2.Read(one); err == nil {
		t.Error("后端不通时应直接断开而不是有数据")
	}
}

func TestRelayUDPEcho(t *testing.T) {
	// 后端 UDP echo
	be, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer be.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := be.ReadFrom(buf)
			if err != nil {
				return
			}
			be.WriteTo(buf[:n], from)
		}
	}()
	beAddr := be.LocalAddr().String()
	host, portStr, _ := net.SplitHostPort(beAddr)

	r := NewRelay(nil)
	port := freePort(t)
	r.Apply([]ForwardRule{{Name: "UDP", Proto: "udp", Port: port, ToHost: host, ToPort: mustAtoi(portStr)}})
	defer r.Stop()

	front, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	defer front.Close()
	msg := []byte("udp-echo")
	var got []byte
	for i := 0; i < 20 && got == nil; i++ {
		if _, err := front.Write(msg); err != nil {
			t.Fatal(err)
		}
		front.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		buf := make([]byte, 2048)
		n, err := front.Read(buf)
		if err == nil {
			got = buf[:n]
		}
	}
	if got == nil {
		t.Fatal("UDP 回包超时")
	}
	if string(got) != string(msg) {
		t.Errorf("期望 %q，得到 %q", msg, got)
	}
}

func TestRelaySigNoop(t *testing.T) {
	r := NewRelay(nil)
	rules := []ForwardRule{{Name: "a", Proto: "tcp", Port: 23456, ToHost: "127.0.0.1", ToPort: 80}}
	r.Apply(rules)
	ports := r.Ports()
	if len(ports) != 1 || ports[0] != 23456 {
		t.Fatalf("应监听 23456，实际 %v", ports)
	}
	r.Apply(rules) // 相同规则集：不应重建
	if p := r.Ports(); len(p) != 1 || p[0] != 23456 {
		t.Errorf("相同规则集不应改变监听，实际 %v", p)
	}
	r.Stop()
	if p := r.Ports(); len(p) != 0 {
		t.Errorf("Stop 后不应有监听，实际 %v", p)
	}
	// 端口已释放，能重新绑定
	ln, err := net.Listen("tcp", ":23456")
	if err != nil {
		t.Fatalf("端口未释放: %v", err)
	}
	ln.Close()
}

func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}
