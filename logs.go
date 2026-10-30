package main

import (
	"fmt"
	"os"
	"sync"
	"time"
)

type LogLine struct {
	Time  time.Time `json:"time"`
	Level string    `json:"level"`
	Msg   string    `json:"msg"`
}

// LogBuffer 是固定容量的环形日志：内存可控，且能通过管理面板回看。
type LogBuffer struct {
	mu       sync.RWMutex
	lines    []LogLine
	max      int
	file     *os.File
	path     string
	maxBytes int64
}

func NewLogBuffer(max int, path string) *LogBuffer {
	if max <= 0 {
		max = 500
	}
	l := &LogBuffer{max: max, path: path, maxBytes: 512 << 10}
	if path != "" {
		if f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err == nil {
			l.file = f
		}
	}
	return l
}

// rotate 在写满 512KB 时滚动一次，只保留一个备份。
// 路由器闪存很小，日志绝不能无限增长。
func (l *LogBuffer) rotate() {
	if l.file == nil {
		return
	}
	st, err := l.file.Stat()
	if err != nil || st.Size() < l.maxBytes {
		return
	}
	l.file.Close()
	os.Rename(l.path, l.path+".1")
	if f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640); err == nil {
		l.file = f
	} else {
		l.file = nil
	}
}

func (l *LogBuffer) add(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	ln := LogLine{Time: time.Now(), Level: level, Msg: msg}

	l.mu.Lock()
	l.lines = append(l.lines, ln)
	if len(l.lines) > l.max {
		copy(l.lines, l.lines[len(l.lines)-l.max:])
		l.lines = l.lines[:l.max]
	}
	l.rotate()
	f := l.file
	l.mu.Unlock()

	// 路由器上 stderr 通常被 init 脚本重定向到文件，这里同时保留一份
	fmt.Fprintf(os.Stderr, "%s [%s] %s\n", ln.Time.Format("2006-01-02 15:04:05"), level, msg)
	if f != nil {
		fmt.Fprintf(f, "%s [%s] %s\n", ln.Time.Format("2006-01-02 15:04:05"), level, msg)
	}
}

func (l *LogBuffer) Infof(format string, args ...any)  { l.add("INFO", format, args...) }
func (l *LogBuffer) Warnf(format string, args ...any)  { l.add("WARN", format, args...) }
func (l *LogBuffer) Errorf(format string, args ...any) { l.add("ERROR", format, args...) }

// Tail 返回最近 n 条（n<=0 表示全部）。
func (l *LogBuffer) Tail(n int) []LogLine {
	l.mu.RLock()
	defer l.mu.RUnlock()
	if n <= 0 || n > len(l.lines) {
		n = len(l.lines)
	}
	out := make([]LogLine, n)
	copy(out, l.lines[len(l.lines)-n:])
	return out
}

func (l *LogBuffer) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}
}
