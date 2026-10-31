package main

import (
	"bytes"
	"io"
	"net"
	"sync"
	"time"
)

// 同一个端口上既要收 HTTPS，也要照顾「手抖写了 http://」的访问。
//
// 以前直接把监听交给 ListenAndServeTLS：明文请求进来，TLS 握手失败，
// 浏览器只看到一句 Client sent an HTTP request to an HTTPS server.，
// 用户还得自己把地址改成 https:// 才能进。
//
// 这里在 accept 之后先偷看一个字节：
//   - 0x16 是 TLS 握手记录（ClientHello），交给 TLS 侧照常握手；
//   - 其它一律当明文 HTTP，交给另一个 http.Server 回 301/307 跳转到 https。
// 端口还是同一个，不用多开监听，也不影响 HTTP/2（ALPN 仍然由 TLS 协商决定）。

const tlsHandshakeRecord = 0x16

type connSniffer struct {
	inner  net.Listener
	tlsCh  chan net.Conn
	httpCh chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newConnSniffer(inner net.Listener) *connSniffer {
	s := &connSniffer{
		inner:  inner,
		tlsCh:  make(chan net.Conn, 64),
		httpCh: make(chan net.Conn, 64),
		closed: make(chan struct{}),
	}
	go s.loop()
	return s
}

func (s *connSniffer) loop() {
	var delay time.Duration
	for {
		c, err := s.inner.Accept()
		if err != nil {
			// 偶发的 EMFILE / ECONNABORTED 不该把整个监听带崩（路由器上文件描述符紧张时很常见）
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if delay == 0 {
					delay = 5 * time.Millisecond
				} else if delay *= 2; delay > time.Second {
					delay = time.Second
				}
				time.Sleep(delay)
				continue
			}
			s.shutdown()
			return
		}
		delay = 0
		go s.classify(c)
	}
}

func (s *connSniffer) classify(c net.Conn) {
	// 连上却一直不发数据的（端口扫描、健康检查）10 秒后直接丢掉，免得堆积
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var first [1]byte
	n, err := io.ReadFull(c, first[:])
	_ = c.SetReadDeadline(time.Time{})
	if err != nil {
		c.Close()
		return
	}
	pc := &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(first[:n]), c)}

	ch := s.httpCh
	if first[0] == tlsHandshakeRecord {
		ch = s.tlsCh
	}
	select {
	case ch <- pc:
	case <-s.closed:
		c.Close()
	}
}

func (s *connSniffer) shutdown() {
	s.once.Do(func() { close(s.closed) })
}

// tlsListener 交给 tls.NewListener / http.Server.Serve。
func (s *connSniffer) tlsListener() net.Listener {
	return &chanListener{ch: s.tlsCh, done: s.closed, addr: s.inner.Addr(), own: make(chan struct{})}
}

// plainListener 交给明文 HTTP 侧（只做跳转）。
func (s *connSniffer) plainListener() net.Listener {
	return &chanListener{ch: s.httpCh, done: s.closed, addr: s.inner.Addr(), own: make(chan struct{})}
}

// prefixConn 把偷看掉的那一个字节拼回读流，其余方法原样委托。
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// chanListener 把信道包装成 net.Listener，供 http.Server 使用。
type chanListener struct {
	ch   <-chan net.Conn
	done <-chan struct{} // 底层监听已关闭
	own  chan struct{}   // 本 listener 自己关了
	addr net.Addr
	once sync.Once
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	case <-l.own:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.own) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }
