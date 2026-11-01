package main

// Web 终端：浏览器 ↔ WebSocket ↔ 会话 ↔ PTY（或 SSH）。
//
// 关键点是「会话保持」：WebSocket 断掉（关页面、手机锁屏、切网络、Wi-Fi 掉线）
// 不销毁 shell，只把连接解绑；重新打开页面时按 id 接回去，先补发最近的输出，
// 再接着实时推。断开超过 keepMin 分钟才真正回收。
//
// 这里不做屏幕状态同步（那是 tmux 的活儿），只保证「进程还活着 + 最近的输出还在」，
// 所以重连后看到的是最后 128KB 原始字节，前面的滚屏内容不保留。

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const termScrollback = 128 << 10 // 每个会话保留的最近输出

type termSession struct {
	id      string
	kind    string // local | ssh
	title   string
	created time.Time

	mu       sync.Mutex
	lastUsed time.Time
	rows     uint16
	cols     uint16
	buf      []byte
	in       io.Writer
	ws       *wsConn
	exited   bool
	exitMsg  string

	resizeFn func(rows, cols uint16)
	onExit   func() // 关 pty、杀进程、断开 ssh；只会执行一次
	exitOnce sync.Once
}

type termHub struct {
	mu   sync.Mutex
	list map[string]*termSession
	logs *LogBuffer
}

func newTermHub(logs *LogBuffer) *termHub {
	return &termHub{list: map[string]*termSession{}, logs: logs}
}

func newTermID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b[:])
}

/* ---------- 会话本体 ---------- */

// appendOut 把终端输出追加进回放缓冲，顺带推给当前连接。
// 写连接放在锁内，保证「回放快照 + 后续实时数据」不会乱序。
func (s *termSession) appendOut(p []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = append(s.buf, p...)
	if len(s.buf) > termScrollback {
		drop := len(s.buf) - termScrollback
		s.buf = append(s.buf[:0], s.buf[drop:]...)
	}
	if s.ws != nil {
		s.ws.setWriteDeadline(10 * time.Second)
		if err := s.ws.WriteMessage(wsBinary, p); err != nil {
			s.dropWS()
		}
	}
}

// dropWS 在持锁状态下调用。
func (s *termSession) dropWS() {
	if s.ws != nil {
		_ = s.ws.Close()
		s.ws = nil
		s.lastUsed = time.Now()
	}
}

// attach 把连接接到会话上，返回需要补发的历史输出。
func (s *termSession) attach(ws *wsConn, rows, cols uint16) {
	s.mu.Lock()
	if s.ws != nil {
		_ = s.ws.Close()
	}
	s.ws = ws
	s.lastUsed = time.Now()
	// 客户端窗口尺寸比会话原来大，就跟着改，否则重连后 vi/top 会画歪
	if rows > 0 && cols > 0 {
		if rows != s.rows || cols != s.cols {
			s.rows, s.cols = rows, cols
			if s.resizeFn != nil {
				s.resizeFn(rows, cols)
			}
		}
	}
	replay := append([]byte(nil), s.buf...)
	exited, msg := s.exited, s.exitMsg
	s.mu.Unlock()

	if len(replay) > 0 {
		_ = ws.WriteMessage(wsBinary, replay)
	}
	if exited {
		sendExit(ws, msg)
	}
}

func (s *termSession) detach(ws *wsConn) {
	s.mu.Lock()
	if s.ws == ws {
		s.ws = nil
		s.lastUsed = time.Now()
	}
	s.mu.Unlock()
}

func (s *termSession) write(p []byte) {
	s.mu.Lock()
	in := s.in
	s.mu.Unlock()
	if in == nil {
		return
	}
	if _, err := in.Write(p); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		// shell 已经退出，等 pump 收尾，这里不重复报错
	}
}

func (s *termSession) resize(rows, cols uint16) {
	if rows == 0 || cols == 0 || rows > 500 || cols > 1000 {
		return
	}
	s.mu.Lock()
	s.rows, s.cols = rows, cols
	fn := s.resizeFn
	s.mu.Unlock()
	if fn != nil {
		fn(rows, cols)
	}
}

func (s *termSession) finish(msg string) {
	s.mu.Lock()
	if s.exited {
		s.mu.Unlock()
		return
	}
	s.exited = true
	s.exitMsg = msg
	ws := s.ws
	s.ws = nil
	s.mu.Unlock()
	if ws != nil {
		sendExit(ws, msg)
		_ = ws.Close()
	}
}

func (s *termSession) close() {
	s.exitOnce.Do(func() {
		if s.onExit != nil {
			s.onExit()
		}
	})
	s.mu.Lock()
	ws := s.ws
	s.ws = nil
	s.mu.Unlock()
	if ws != nil {
		_ = ws.Close()
	}
}

func (s *termSession) info(detachedAllowed bool) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{
		"id":       s.id,
		"kind":     s.kind,
		"title":    s.title,
		"created":  s.created,
		"lastUsed": s.lastUsed,
		"attached": s.ws != nil,
		"exited":   s.exited,
		"rows":     s.rows,
		"cols":     s.cols,
	}
}

/* ---------- 会话管理 ---------- */

func (h *termHub) get(id string) *termSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.list[id]
}

func (h *termHub) add(s *termSession) {
	h.mu.Lock()
	h.list[s.id] = s
	h.mu.Unlock()
}

func (h *termHub) remove(id string) {
	h.mu.Lock()
	s := h.list[id]
	delete(h.list, id)
	h.mu.Unlock()
	if s != nil {
		s.close()
	}
}

func (h *termHub) snapshot() []map[string]any {
	h.mu.Lock()
	items := make([]*termSession, 0, len(h.list))
	for _, s := range h.list {
		items = append(items, s)
	}
	h.mu.Unlock()
	sort.Slice(items, func(i, j int) bool { return items[i].created.Before(items[j].created) })
	out := make([]map[string]any, 0, len(items))
	for _, s := range items {
		out = append(out, s.info(true))
	}
	return out
}

func (h *termHub) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.list)
}

// closeAll 在进程退出时关掉所有终端，避免 shell 子进程变成孤儿。
func (h *termHub) closeAll() {
	h.mu.Lock()
	ids := make([]string, 0, len(h.list))
	for id := range h.list {
		ids = append(ids, id)
	}
	h.mu.Unlock()
	for _, id := range ids {
		h.remove(id)
	}
}

// reapIdle 回收长时间没人接的会话，以及已经退出的会话。
func (h *termHub) reapIdle(keep time.Duration) {
	now := time.Now()
	type victim struct {
		id  string
		why string
	}
	var dead []victim
	h.mu.Lock()
	for id, s := range h.list {
		s.mu.Lock()
		idle := s.ws == nil && now.Sub(s.lastUsed) > keep
		exited := s.exited && s.ws == nil
		s.mu.Unlock()
		if exited {
			dead = append(dead, victim{id, "已退出"})
		} else if idle {
			dead = append(dead, victim{id, "空闲超时"})
		}
	}
	h.mu.Unlock()
	for _, v := range dead {
		h.remove(v.id)
		h.logs.Infof("终端会话已回收（%s）：%s", v.why, v.id)
	}
}

// evictOldest 在会话数到达上限时腾一个位置：只回收最老的、没人接的会话，
// 已经在用的连接不动。没有可回收的就返回 false。
func (h *termHub) evictOldest() bool {
	h.mu.Lock()
	var oldest *termSession
	for _, s := range h.list {
		s.mu.Lock()
		free := s.ws == nil
		s.mu.Unlock()
		if !free {
			continue
		}
		if oldest == nil || s.created.Before(oldest.created) {
			oldest = s
		}
	}
	h.mu.Unlock()
	if oldest == nil {
		return false
	}
	h.remove(oldest.id)
	h.logs.Infof("终端会话数已满，回收最早的空闲会话：%s（%s）", oldest.title, oldest.id)
	return true
}

// pump 把会话输出搬进缓冲，读到 EOF 就收尾。
func (h *termHub) pump(s *termSession, src io.Reader, label string) {
	buf := make([]byte, 8192)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			s.appendOut(buf[:n])
		}
		if err != nil {
			break
		}
	}
	s.finish("会话已结束")
	h.logs.Infof("终端会话结束：%s（%s）", label, s.id)
}

func (h *termHub) createLocal(shell string, rows, cols uint16) (s *termSession, err error) {
	if shell == "" {
		shell = "/bin/sh"
	}
	cmd, ptmx, err := startShell(shell, rows, cols)
	if err != nil {
		return nil, err
	}
	s = &termSession{
		id: newTermID(), kind: "local", title: shell, created: time.Now(),
		lastUsed: time.Now(), rows: rows, cols: cols, in: ptmx,
		resizeFn: func(r, c uint16) { resizePTY(ptmx, r, c) },
		onExit: func() {
			_ = ptmx.Close()
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			_ = cmd.Wait()
		},
	}
	h.add(s)
	go h.pump(s, ptmx, shell)
	return s, nil
}

func (h *termHub) createSSH(c SSHConn, rows, cols uint16) (s *termSession, err error) {
	st, err := startSSH(c, rows, cols)
	if err != nil {
		return nil, err
	}
	title := fmt.Sprintf("%s@%s", c.User, c.Host)
	if c.Name != "" {
		title = c.Name
	}
	s = &termSession{
		id: newTermID(), kind: "ssh", title: title, created: time.Now(),
		lastUsed: time.Now(), rows: rows, cols: cols, in: st.stdin,
		resizeFn: st.resize,
		onExit:   st.close,
	}
	h.add(s)
	go h.pump(s, st.stdout, "ssh "+title)
	return s, nil
}

/* ---------- HTTP 接口 ---------- */

type termMsg struct {
	Type string `json:"type"`
	Rows uint16 `json:"rows,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
}

func sendExit(ws *wsConn, msg string) {
	b, _ := json.Marshal(map[string]any{"type": "exit", "msg": msg})
	ws.setWriteDeadline(5 * time.Second)
	_ = ws.WriteMessage(wsText, b)
}

// termAllowed 检查总开关与来源限制。终端等于面板后的 root shell，
// 默认只允许内网来源打开，公网来源一律 403。
func (a *App) termAllowed(w http.ResponseWriter, r *http.Request) bool {
	cfg := a.Config()
	if !cfg.Term.Enable {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "终端功能已关闭，请在设置里打开"})
		return false
	}
	if cfg.Term.LANOnly && !isLANAddr(r.RemoteAddr) {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "终端只允许内网访问；要在公网用请关掉「仅内网」"})
		return false
	}
	return true
}

// handleTermInfo 返回前端渲染界面需要的静态信息。
func (a *App) handleTermInfo(w http.ResponseWriter, r *http.Request) {
	cfg := a.Config()
	type sshBrief struct {
		Name string `json:"name"`
		Host string `json:"host"`
		User string `json:"user"`
	}
	list := make([]sshBrief, 0, len(cfg.Term.SSH))
	for _, c := range cfg.Term.SSH {
		list = append(list, sshBrief{Name: c.Name, Host: c.Host, User: c.User})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enable":       cfg.Term.Enable,
		"lanOnly":      cfg.Term.LANOnly,
		"keepMin":      cfg.Term.KeepMin,
		"maxSessions":  cfg.Term.MaxSessions,
		"defaultShell": cfg.Term.Shell,
		"shells":       detectShells(),
		"ssh":          list,
		"lan":          isLANAddr(r.RemoteAddr),
	})
}

// handleTermSessions：GET 列表 / POST 新建 / DELETE 关闭。
func (a *App) handleTermSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, http.StatusOK, map[string]any{"sessions": a.term.snapshot()})
		return
	}
	if !a.termAllowed(w, r) {
		return
	}
	cfg := a.Config()

	switch r.Method {
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		if a.term.get(id) == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "会话不存在"})
			return
		}
		a.term.remove(id)
		a.logs.Infof("终端会话已手动关闭：%s", id)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})

	case http.MethodPost:
		var req struct {
			Kind  string `json:"kind"`
			Shell string `json:"shell"`
			Name  string `json:"name"`
			Rows  uint16 `json:"rows"`
			Cols  uint16 `json:"cols"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<14)).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求体不是合法 JSON"})
			return
		}
		rows, cols := req.Rows, req.Cols
		if rows == 0 {
			rows = 30
		}
		if cols == 0 {
			cols = 100
		}
		if max := cfg.Term.MaxSessions; max > 0 && a.term.count() >= max {
			// 先腾一个空闲会话出来，还满就拒绝
			a.term.evictOldest()
			if a.term.count() >= max {
				writeJSON(w, http.StatusTooManyRequests,
					map[string]any{"error": fmt.Sprintf("会话数已达上限 %d，先关掉不用的会话", max)})
				return
			}
		}

		var (
			s   *termSession
			err error
		)
		switch req.Kind {
		case "local":
			shell := req.Shell
			if shell == "" {
				shell = cfg.Term.Shell
			}
			if shell == "" {
				sh := detectShells()
				if len(sh) == 0 {
					writeJSON(w, http.StatusBadRequest, map[string]any{"error": "本机找不到可用的 shell"})
					return
				}
				shell = sh[0]
			}
			s, err = a.term.createLocal(shell, rows, cols)
		case "ssh":
			var conn *SSHConn
			for i := range cfg.Term.SSH {
				if cfg.Term.SSH[i].Name == req.Name {
					conn = &cfg.Term.SSH[i]
					break
				}
			}
			if conn == nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"error": "没有这条 SSH 连接: " + req.Name})
				return
			}
			s, err = a.term.createSSH(*conn, rows, cols)
		default:
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "kind 只能是 local 或 ssh"})
			return
		}
		if err != nil {
			a.logs.Errorf("终端会话创建失败: %v", err)
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
			return
		}
		a.logs.Infof("终端会话已创建：%s（%s）", s.title, s.id)
		writeJSON(w, http.StatusOK, map[string]any{"id": s.id, "title": s.title})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
	}
}

// handleTermWS 接管连接：先补历史输出，然后双向转发。
func (a *App) handleTermWS(w http.ResponseWriter, r *http.Request) {
	if !a.termAllowed(w, r) {
		return
	}
	s := a.term.get(r.URL.Query().Get("id"))
	if s == nil {
		http.Error(w, "会话不存在或已回收", http.StatusNotFound)
		return
	}
	var rows, cols uint16
	if v, err := strconv.Atoi(r.URL.Query().Get("rows")); err == nil && v > 0 && v < 500 {
		rows = uint16(v)
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("cols")); err == nil && v > 0 && v < 1000 {
		cols = uint16(v)
	}
	ws, err := upgradeWS(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer ws.Close()

	s.attach(ws, rows, cols)
	defer s.detach(ws)

	// 断线后要不要销毁，看 keepMin：0 表示断开即回收
	defer func() {
		if cfg := a.Config(); cfg.Term.KeepMin <= 0 {
			a.term.remove(s.id)
			a.logs.Infof("终端会话已关闭（不保活）：%s", s.id)
			return
		}
	}()

	for {
		op, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		switch op {
		case wsBinary:
			s.write(data)
		case wsText:
			var m termMsg
			if json.Unmarshal(data, &m) != nil {
				continue
			}
			switch m.Type {
			case "resize":
				s.resize(m.Rows, m.Cols)
			case "ping":
				ws.setWriteDeadline(5 * time.Second)
				_ = ws.WriteMessage(wsText, []byte(`{"type":"pong"}`))
			}
		}
	}
}

// normalizeTerm 校验终端与唤醒配置。放在 config.go 的 Normalize 里调用。
func (c *Config) normalizeTerm() error {
	if c.Term.KeepMin < 0 {
		c.Term.KeepMin = 0
	}
	if c.Term.KeepMin > 24*60 {
		c.Term.KeepMin = 24 * 60
	}
	if c.Term.MaxSessions <= 0 {
		c.Term.MaxSessions = 4
	}
	if c.Term.MaxSessions > 16 {
		c.Term.MaxSessions = 16
	}
	c.Term.Shell = strings.TrimSpace(c.Term.Shell)
	seen := map[string]bool{}
	for i := range c.Term.SSH {
		s := &c.Term.SSH[i]
		s.Name = strings.TrimSpace(s.Name)
		s.Host = strings.TrimSpace(s.Host)
		s.User = strings.TrimSpace(s.User)
		s.KeyPath = strings.TrimSpace(s.KeyPath)
		s.Auth = strings.TrimSpace(s.Auth)
		if s.Name == "" {
			s.Name = s.Host
		}
		if s.Host == "" {
			return fmt.Errorf("第 %d 条 SSH 连接没有填主机", i+1)
		}
		if seen[s.Name] {
			return fmt.Errorf("SSH 连接名称重复: %s", s.Name)
		}
		seen[s.Name] = true
		if s.Port <= 0 || s.Port > 65535 {
			s.Port = 22
		}
		if s.User == "" {
			s.User = "root"
		}
		if s.Auth != "key" {
			s.Auth = "password"
		}
		if s.Auth == "key" && s.KeyPath == "" {
			return fmt.Errorf("SSH 连接「%s」选了私钥认证但没填私钥路径", s.Name)
		}
	}
	for i := range c.WOL.Devices {
		d := &c.WOL.Devices[i]
		d.Name = strings.TrimSpace(d.Name)
		d.Broadcast = strings.TrimSpace(d.Broadcast)
		d.ProbeIP = strings.TrimSpace(d.ProbeIP)
		if d.Name == "" {
			d.Name = fmt.Sprintf("设备 %d", i+1)
		}
		var macs []string
		for _, m := range d.MACs {
			if m = strings.TrimSpace(m); m != "" {
				if _, err := net.ParseMAC(m); err != nil {
					return fmt.Errorf("设备「%s」的 MAC 无效: %s", d.Name, m)
				}
				macs = append(macs, m)
			}
		}
		if len(macs) == 0 {
			return fmt.Errorf("设备「%s」没有填 MAC", d.Name)
		}
		d.MACs = macs
	}
	return nil
}
