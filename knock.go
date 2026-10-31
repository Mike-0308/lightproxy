package main

// 转发端口的「敲门」放行名单。
//
// 用户态转发（tcpfwd.go）是原样搬运字节的裸转发，扫描器连上转发的端口
// 能直接和后端服务对话，从而识别出端口后面是什么（比如 RDP）。
// 这里的做法：浏览器只要通过了一次安全入口（知道域名 + 知道入口路径），
// 就把来源公网 IP 记进放行名单；转发收到连接时先查名单——
// 名单外的来源接受后立即断开、一个字节不回，扫描器拿不到任何协议指纹。
//
// 名单按「网络前缀」记录：IPv4 精确到单个地址（/32），IPv6 精确到 /64——
// Windows 的隐私扩展会轮换接口 ID，但临时地址始终落在同一个 /64 里，
// 用浏览器敲一次门，同一网络下的 mstsc 就能连。
//
// 有效期与安全入口票据一致（7 天），过期或换了网络后重新打开一次入口页面即可。

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	knockTTL        = 7 * 24 * time.Hour // 与安全入口票据同有效期
	knockMaxEntries = 4096               // 名单上限，超出时先清过期、再挤掉最旧的
	knockDenyLogGap = time.Minute        // 同一来源的拒绝日志最多一分钟记一条
)

// knockEnabled 由 applyForward 按配置开关设置；关闭时转发不查名单。
var knockEnabled atomic.Bool

func SetKnockEnabled(v bool) { knockEnabled.Store(v) }

// knockOK 是转发放行的统一入口：未启用敲门时全部放行。
func knockOK(remoteAddr string) bool {
	return !knockEnabled.Load() || knocks.allowed(remoteAddr)
}

type knockTable struct {
	mu     sync.Mutex
	ok     map[string]time.Time // 前缀 -> 过期时间
	denied map[string]time.Time // 拒绝日志的去重（上次记录时间）
}

var knocks = &knockTable{ok: map[string]time.Time{}, denied: map[string]time.Time{}}

// knockKey 取来源的放行键：IPv4 /32、IPv6 /64。解析失败返回空串（一律拒绝）。
func knockKey(remoteAddr string) string {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(host), "[]"))
	if ip == nil {
		return ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String() + "/32"
	}
	return fmt.Sprintf("%s/64", ip.Mask(net.CIDRMask(64, 128)))
}

func (t *knockTable) record(remoteAddr string) {
	key := knockKey(remoteAddr)
	if key == "" {
		return
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.ok) >= knockMaxEntries {
		t.pruneLocked(now)
		if len(t.ok) >= knockMaxEntries {
			// 还是满：挤掉过期时间最早的
			var oldKey string
			var oldExp time.Time
			for k, exp := range t.ok {
				if oldKey == "" || exp.Before(oldExp) {
					oldKey, oldExp = k, exp
				}
			}
			delete(t.ok, oldKey)
		}
	}
	t.ok[key] = now.Add(knockTTL)
}

func (t *knockTable) allowed(remoteAddr string) bool {
	key := knockKey(remoteAddr)
	if key == "" {
		return false
	}
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	exp, hit := t.ok[key]
	if !hit {
		return false
	}
	if now.After(exp) {
		delete(t.ok, key)
		return false
	}
	return true
}

// denyLoggable 限制拒绝日志的频率：同一来源一分钟最多记一条，返回是否该记。
func (t *knockTable) denyLoggable(remoteAddr string) bool {
	key := knockKey(remoteAddr)
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if now.Sub(t.denied[key]) < knockDenyLogGap {
		return false
	}
	t.denied[key] = now
	return true
}

// snapshot 返回名单快照（前缀 + 剩余有效期），供面板状态展示。
func (t *knockTable) snapshot() []string {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]string, 0, len(t.ok))
	for k, exp := range t.ok {
		if now.After(exp) {
			continue
		}
		out = append(out, fmt.Sprintf("%s（剩 %s）", k, knockDur(exp.Sub(now))))
	}
	sort.Strings(out)
	return out
}

func (t *knockTable) pruneLocked(now time.Time) {
	for k, exp := range t.ok {
		if now.After(exp) {
			delete(t.ok, k)
		}
	}
}

func knockDur(d time.Duration) string {
	h := int(d.Hours())
	switch {
	case h >= 48:
		return fmt.Sprintf("%d 天", h/24)
	case h >= 1:
		return fmt.Sprintf("%d 小时", h)
	default:
		return "不足 1 小时"
	}
}
