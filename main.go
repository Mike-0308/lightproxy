package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"
)

func main() {
	var cfgPath, listenOverride, adminOverride string
	var check, showVersion bool

	flag.StringVar(&cfgPath, "c", "", "配置文件路径（默认与程序同目录的 config.json）")
	flag.StringVar(&listenOverride, "listen", "", "临时覆盖反向代理监听地址，如 :18080")
	flag.StringVar(&adminOverride, "admin", "", "临时覆盖管理面板监听地址，如 0.0.0.0:8081")
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
	debug.SetGCPercent(40)
	if cfg.Runtime.MemLimitMB > 0 {
		debug.SetMemoryLimit(int64(cfg.Runtime.MemLimitMB) << 20)
	}

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
	a.logs.Close()
}
