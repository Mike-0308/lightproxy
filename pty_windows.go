//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
)

// Windows 上没有 /dev/ptmx，终端功能不提供；路由会直接回 501。
func startShell(shell string, rows, cols uint16) (*exec.Cmd, *os.File, error) {
	return nil, nil, errors.New("当前系统不支持 Web 终端")
}

func resizePTY(f *os.File, rows, cols uint16) {}

func detectShells() []string { return nil }
