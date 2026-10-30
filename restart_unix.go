//go:build !windows

package main

import (
	"os"
	"syscall"
	"time"
)

// restartProcess 优先让 init/procd 拉起新进程；没有守护时直接 exec 自身，
// 这样 PID 不变、端口不会短暂失联。
func restartProcess() {
	go func() {
		time.Sleep(300 * time.Millisecond)
		if os.Getenv("LP_SUPERVISED") == "1" {
			os.Exit(1)
		}
		exe, err := os.Executable()
		if err != nil {
			os.Exit(1)
		}
		if err := syscall.Exec(exe, os.Args, os.Environ()); err != nil {
			os.Exit(1)
		}
	}()
}
