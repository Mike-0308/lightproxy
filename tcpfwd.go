package main

// 用户态裸 TCP/UDP 转发（IPv6 → 内网）。
//
// 内核 DNAT（fw.go 的 LP_FWD 链）只对 IPv4 生效：无公网 IPv4 的家宽域名只解析出
// AAAA，外网流量走 IPv6 打到路由器自身，而 Linux 的 netfilter 没法用 ip6tables
// 把 IPv6 流量 DNAT 到 IPv4 内网主机（跨协议族 NAT 不支持）。这里的做法是在用户
// 态监听 [::]:端口（双栈），把收到的字节原样转发给内网目标——和 Lucky 的端口转
// 发是同一类实现，RDP、SSH 这类任意 TCP/UDP 服务都能走域名 + 端口访问。
//
// 与内核 DNAT 并存：IPv4 流量在 PREROUTING 就被 DNAT 走了，到不了这里的监听；
// 只有 IPv6（以及防火墙后端不可用时本机的 IPv4）会落到用户态转发上。
// 端口被反代/面板占用时整条规则跳过（DNAT 与监听都不做），避免劫持自己的服务。

import (
	"context"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	relayDialTimeout  = 5 * time.Second
	relayKeepalive    = 30 * time.Second
	udpIdleGCInterval = 30 * time.Second
	udpIdleTimeout    = 90 * time.Second
	relayMaxConns     = 512 // 单个监听端口的最大并发连接
)

// Relay 管理用户态转发监听。Apply 的规则集签名没变时不做任何事，
// 避免保存无关配置时打断正在进行的 RDP 会话。
type Relay struct {
	logs *LogBuffer

	mu     sync.Mutex
	sig    string
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	ports  []int // 当前监听中的端口（供状态展示）
}

func NewRelay(logs *LogBuffer) *Relay {
	ctx, cancel := context.WithCancel(context.Background())
	return &Relay{logs: logs, ctx: ctx, cancel: cancel}
}

// Ports 返回当前监听的端口快照。
func (r *Relay) Ports() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]int, len(r.ports))
	copy(out, r.ports)
	return out
}

func relaySig(rules []ForwardRule) string {
	var b strings.Builder
	for _, r := range rules {
		b.WriteString(strconv.Itoa(r.Port))
		b.WriteByte('|')
		b.WriteString(r.Proto)
		b.WriteByte('|')
		b.WriteString(r.ToHost)
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(r.ToPort))
		b.WriteByte(';')
	}
	return b.String()
}

// Apply 重建全部转发监听；规则集与当前一致时是空操作。
func (r *Relay) Apply(rules []ForwardRule) {
	sig := relaySig(rules)
	r.mu.Lock()
	if sig == r.sig {
		r.mu.Unlock()
		return
	}
	r.stopLocked()

	r.sig = sig
	r.ctx, r.cancel = context.WithCancel(context.Background())
	ctx := r.ctx
	ports := make([]int, 0, len(rules))
	for _, rule := range rules {
		ports = append(ports, rule.Port)
		for _, proto := range protoList(rule.Proto) {
			switch proto {
			case "tcp":
				r.wg.Add(1)
				go r.serveTCP(ctx, rule)
			case "udp":
				r.wg.Add(1)
				go r.serveUDP(ctx, rule)
			}
		}
	}
	r.ports = ports
	r.mu.Unlock()
	if r.logs != nil && len(rules) > 0 {
		r.logs.Infof("用户态转发已启动：%s", relayDesc(rules))
	}
}

// Stop 关闭全部监听并等待退出。
func (r *Relay) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopLocked()
	r.sig = ""
	r.ports = nil
}

func (r *Relay) stopLocked() {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
}

func relayDesc(rules []ForwardRule) string {
	parts := make([]string, 0, len(rules))
	for _, r := range rules {
		for _, p := range protoList(r.Proto) {
			parts = append(parts, p+"/"+strconv.Itoa(r.Port)+"→"+destOf(r))
		}
	}
	return strings.Join(parts, ", ")
}

func (r *Relay) warnf(format string, args ...any) {
	if r.logs != nil {
		r.logs.Warnf(format, args...)
	}
}

// ---------------- TCP ----------------

func (r *Relay) serveTCP(ctx context.Context, rule ForwardRule) {
	defer r.wg.Done()
	addr := ":" + strconv.Itoa(rule.Port)
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		r.warnf("用户态转发 %s 监听失败: %v", addr, err)
		return
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		front, err := ln.Accept()
		if err != nil {
			if ctx.Err() == nil {
				r.warnf("用户态转发 %s accept 失败: %v", addr, err)
			}
			return
		}
		// 敲门放行：名单外的来源接受后立即断开，不回任何字节，
		// 扫描器因此识别不出端口后面的服务。
		if !knockOK(front.RemoteAddr().String()) {
			if knocks.denyLoggable(front.RemoteAddr().String()) {
				r.warnf("转发 :%d 拒绝未敲门来源 %s（先访问安全入口即可放行）", rule.Port, knockKey(front.RemoteAddr().String()))
			}
			front.Close()
			continue
		}
		go r.pipeTCP(ctx, front, rule)
	}
}

func (r *Relay) pipeTCP(ctx context.Context, front net.Conn, rule ForwardRule) {
	dest := destOf(rule)
	back, err := net.DialTimeout("tcp", dest, relayDialTimeout)
	if err != nil {
		r.warnf("转发 :%d→%s 拨号失败: %v", rule.Port, dest, err)
		front.Close()
		return
	}
	// 配置变更时立即断开存量连接，避免会话挂在旧规则上
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		case <-done:
		}
		front.Close()
		back.Close()
	}()
	defer close(done)
	defer front.Close()
	defer back.Close()
	setKeepalive(front)
	setKeepalive(back)

	go func() { _, _ = io.Copy(back, front) }()
	_, _ = io.Copy(front, back)
}

func setKeepalive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(relayKeepalive)
	}
}

// ---------------- UDP ----------------

// serveUDP 按客户端地址维护一条到目标的后端 UDP 通道，闲置 90 秒回收。
func (r *Relay) serveUDP(ctx context.Context, rule ForwardRule) {
	defer r.wg.Done()
	addr := ":" + strconv.Itoa(rule.Port)
	pc, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", addr)
	if err != nil {
		r.warnf("用户态 UDP 转发 %s 监听失败: %v", addr, err)
		return
	}
	uc := pc.(*net.UDPConn)
	dest := destOf(rule)

	type pipe struct {
		conn net.Conn
		last time.Time
	}
	var mu sync.Mutex
	pipes := make(map[string]*pipe)

	go func() {
		<-ctx.Done()
		uc.Close()
	}()
	go func() {
		tick := time.NewTicker(udpIdleGCInterval)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				mu.Lock()
				now := time.Now()
				for k, p := range pipes {
					if now.Sub(p.last) > udpIdleTimeout {
						p.conn.Close()
						delete(pipes, k)
					}
				}
				mu.Unlock()
			}
		}
	}()

	buf := make([]byte, 65535)
	for {
		n, from, err := uc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() == nil {
				r.warnf("用户态 UDP 转发 %s 读取失败: %v", addr, err)
			}
			mu.Lock()
			for _, p := range pipes {
				p.conn.Close()
			}
			mu.Unlock()
			return
		}
		// 敲门放行：名单外的来源直接丢弃数据包，不建后端通道
		if !knockOK(from.String()) {
			if knocks.denyLoggable(from.String()) {
				r.warnf("转发 udp :%d 拒绝未敲门来源 %s", rule.Port, knockKey(from.String()))
			}
			continue
		}
		key := from.String()
		mu.Lock()
		p := pipes[key]
		if p == nil {
			if len(pipes) >= relayMaxConns {
				mu.Unlock()
				continue
			}
			conn, derr := net.Dial("udp", dest)
			if derr != nil {
				mu.Unlock()
				r.warnf("转发 udp :%d→%s 拨号失败: %v", rule.Port, dest, derr)
				continue
			}
			p = &pipe{conn: conn, last: time.Now()}
			pipes[key] = p
			go func(p *pipe, from net.Addr) {
				b := make([]byte, 65535)
				for {
					n, err := p.conn.Read(b)
					if err != nil {
						return
					}
					_, _ = uc.WriteTo(b[:n], from)
				}
			}(p, from)
		}
		p.last = time.Now()
		conn := p.conn
		mu.Unlock()
		if n > 0 {
			_, _ = conn.Write(buf[:n])
		}
	}
}
