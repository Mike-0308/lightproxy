package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"syscall"
	"time"
)

func main() {
	var cfgPath, listenOverride, adminOverride string
	var check, showVersion bool

	flag.StringVar(&cfgPath, "c", "", "配置文件路径（默认与程序同目录的 config.json）")
	flag.StringVar(&listenOverride, "listen", "", "临时覆盖反向代理监听地址，如 :16666")
	flag.StringVar(&adminOverride, "admin", "", "临时覆盖管理面板监听地址，如 0.0.0.0:18080")
	flag.BoolVar(&check, "check", false, "只检查配置是否合法，然后退出")
	flag.BoolVar(&showVersion, "v", false, "显示版本")
	flag.Parse()

	if showVersion {
		fmt.Printf("lightproxy %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		return
	}

	if cfgPath == "" {
		cfgPath = defaultConfigPath()
	}
	cfg, firstRun, err := LoadConfig(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置错误: %v\n", err)
		os.Exit(2)
	}
	if listenOverride != "" {
		cfg.Listen = listenOverride
	}
	if adminOverride != "" {
		cfg.Admin.Listen = adminOverride
	}
	if firstRun {
		fmt.Printf("首次启动，已生成配置：%s\n管理面板账号：%s / %s\n", cfgPath, cfg.Admin.User, cfg.Admin.Pass)
	}
	if check {
		fmt.Printf("配置正常：反代规则 %d 条，DDNS %v，监听 %s，面板 %s\n",
			len(cfg.Proxy), cfg.DDNS.Enable, cfg.Listen, cfg.Admin.Listen)
		return
	}

	// 内存调优：路由器上宁可多花点 CPU，也不要吃满内存
	gcPct := cfg.Runtime.GCPercent
	if gcPct <= 0 {
		gcPct = 40
	}
	if v := os.Getenv("LP_GC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			gcPct = n
		}
	}
	debug.SetGCPercent(gcPct)
	if cfg.Runtime.MemLimitMB > 0 {
		debug.SetMemoryLimit(int64(cfg.Runtime.MemLimitMB) << 20)
	}

	// 低负载时把空闲堆还给内核。Go 默认只在堆增长时才向 OS 要内存，
	// 而缩容要走 scavenger 的慢路径，RSS 会长时间停在峰值。
	// 路由器内存小、流量又断续，定期 FreeOSMemory 让 RSS 回落到真实需求。
	go func() {
		time.Sleep(45 * time.Second)
		debug.FreeOSMemory()
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			debug.FreeOSMemory()
		}
	}()

	logPath := cfg.Runtime.LogFile
	if logPath == "" {
		logPath = os.Getenv("LP_LOG")
	}
	logs := NewLogBuffer(600, logPath)
	defer logs.Close()

	logs.Infof("轻代理 v%s 启动（%s/%s），配置 %s", version, runtime.GOOS, runtime.GOARCH, cfgPath)
	if firstRun {
		logs.Infof("首次启动，已生成管理密码：%s", cfg.Admin.Pass)
	}

	app := NewApp(cfgPath, cfg, logs)
	if err := app.Start(); err != nil {
		logs.Errorf("启动失败: %v", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	for s := range sig {
		if s == syscall.SIGHUP {
			logs.Infof("收到 SIGHUP，重新加载配置与证书")
			if next, _, err := LoadConfig(cfgPath); err == nil {
				next.Listen = cfg.Listen
				next.Admin.Listen = cfg.Admin.Listen
				if err := app.ApplyConfig(next, false); err != nil {
					logs.Errorf("重载配置失败: %v", err)
				}
			} else {
				logs.Errorf("重载配置失败: %v", err)
			}
			if app.certs != nil {
				if err := app.certs.reload(); err != nil {
					logs.Errorf("重载证书失败: %v", err)
				}
			}
			continue
		}
		logs.Infof("收到信号 %v，正在退出", s)
		app.Shutdown()
		return
	}
}

func (a *App) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if m := a.ddns.Load(); m != nil {
		m.Stop()
	}
	a.mu.Lock()
	servers := a.servers
	a.mu.Unlock()
	for _, s := range servers {
		s.Shutdown(ctx)
	}
	if a.term != nil {
		a.term.closeAll()
	}
	a.logs.Close()
}
