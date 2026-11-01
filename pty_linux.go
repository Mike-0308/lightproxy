//go:build linux

package main

// Linux 伪终端：直接对 /dev/ptmx 做 ioctl，不依赖 x/sys。
// 只用 syscall + unsafe，保持「零第三方依赖」。

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

const (
	ioctlSPTLCK = 0x40045431 // TIOCSPTLCK
	ioctlGPTN   = 0x80045430 // TIOCGPTN
	ioctlSWINSZ = 0x5414     // TIOCSWINSZ
)

type winSize struct {
	Row, Col, Xpixel, Ypixel uint16
}

func ioctl(fd uintptr, req uintptr, arg unsafe.Pointer) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}

// openPTY 返回主端和从端。主端读写就是终端的输入输出。
func openPTY() (*os.File, *os.File, error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	var unlock int32
	if err := ioctl(m.Fd(), ioctlSPTLCK, unsafe.Pointer(&unlock)); err != nil {
		m.Close()
		return nil, nil, err
	}
	var n uint32
	if err := ioctl(m.Fd(), ioctlGPTN, unsafe.Pointer(&n)); err != nil {
		m.Close()
		return nil, nil, err
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, s, nil
}

// startShell 起一个 shell 挂到新 PTY 上，返回主端用于收发。
func startShell(shell string, rows, cols uint16) (*exec.Cmd, *os.File, error) {
	if shell == "" {
		shell = "/bin/sh"
	}
	m, s, err := openPTY()
	if err != nil {
		return nil, nil, err
	}
	resizePTY(m, rows, cols)

	cmd := exec.Command(shell, "-i")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = s, s, s
	cmd.Env = append(os.Environ(), "TERM=xterm-256color", "COLORTERM=truecolor")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		Ctty:    int(s.Fd()),
	}
	if err := cmd.Start(); err != nil {
		m.Close()
		s.Close()
		return nil, nil, err
	}
	s.Close()
	return cmd, m, nil
}

func resizePTY(f *os.File, rows, cols uint16) {
	if rows == 0 || cols == 0 {
		return
	}
	ws := winSize{Row: rows, Col: cols}
	_ = ioctl(f.Fd(), ioctlSWINSZ, unsafe.Pointer(&ws))
}

// 常用 shell 探测：路由器上一般只有 ash / sh。
func detectShells() []string {
	cand := []string{"/bin/sh", "/bin/ash", "/bin/bash", "/usr/bin/bash", "/bin/zsh"}
	var out []string
	for _, c := range cand {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		out = []string{"/bin/sh"}
	}
	return out
}
