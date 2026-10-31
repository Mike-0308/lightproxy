package main

import (
	"net"
	"testing"
	"time"
)

// 同一个端口上，TLS 握手要走到 TLS 侧，明文 http:// 要走到跳转侧。
func TestConnSnifferSplitsTLSAndPlain(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()

	sn := newConnSniffer(ln)
	tlsLn, plainLn := sn.tlsListener(), sn.plainListener()
	addr := ln.Addr().String()

	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x02, 0x01, 0x00}
	plainReq := []byte("GET /entry HTTP/1.1\r\nHost: x\r\n\r\n")

	dial := func(payload []byte) {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		defer c.Close()
		c.Write(payload)
		time.Sleep(400 * time.Millisecond)
	}
	go dial(hello)
	go dial(plainReq)

	type result struct {
		conn net.Conn
		err  error
	}
	tlsCh := make(chan result, 1)
	plainCh := make(chan result, 1)
	go func() { c, e := tlsLn.Accept(); tlsCh <- result{c, e} }()
	go func() { c, e := plainLn.Accept(); plainCh <- result{c, e} }()

	read := func(ch chan result, name string, want int) []byte {
		select {
		case r := <-ch:
			if r.err != nil {
				t.Fatalf("%s 侧 accept 失败: %v", name, r.err)
			}
			defer r.conn.Close()
			r.conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, want)
			n := 0
			for n < want {
				m, err := r.conn.Read(buf[n:])
				if err != nil {
					break
				}
				n += m
			}
			return buf[:n]
		case <-time.After(3 * time.Second):
			t.Fatalf("%s 侧没有收到连接", name)
			return nil
		}
	}

	gotTLS := read(tlsCh, "TLS", len(hello))
	if len(gotTLS) != len(hello) || gotTLS[0] != 0x16 {
		t.Errorf("TLS 侧收到的数据不对: %v", gotTLS)
	}
	gotPlain := read(plainCh, "明文", len(plainReq))
	if string(gotPlain) != string(plainReq) {
		t.Errorf("明文侧应收到完整请求，实际 %q", gotPlain)
	}
}

// 连上不发数据的连接不能被当成 TLS 或明文塞给下游，超时后直接丢掉。
func TestConnSnifferDropsSilentConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()

	sn := newConnSniffer(ln)
	tlsLn, plainLn := sn.tlsListener(), sn.plainListener()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	defer c.Close()

	// 关闭底层监听后两个 listener 都应该立刻返回错误，而不是永远阻塞
	ln.Close()
	done := make(chan struct{}, 2)
	go func() {
		if _, err := tlsLn.Accept(); err == nil {
			t.Errorf("TLS 侧应返回错误")
		}
		done <- struct{}{}
	}()
	go func() {
		if _, err := plainLn.Accept(); err == nil {
			t.Errorf("明文侧应返回错误")
		}
		done <- struct{}{}
	}()
	for i := 0; i < 2; i++ {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("关闭监听后 Accept 没有返回")
		}
	}
}
