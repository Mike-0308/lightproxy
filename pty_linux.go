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

	cmd, err := spawnShell(shell, s)
	if err != nil {
		s.Close()
		m.Close()
		return nil, nil, err
	}
	// 从端已经在子进程里 dup 走了，父进程这边只留主端。
	s.Close()
	return cmd, m, nil
}

// spawnShell 在新会话里 exec shell，并把 PTY 从端设成它的控制终端。
//
// SysProcAttr.Ctty 的语义必须注意：它是**子进程里的 fd 编号**（ProcAttr.Files 的下标，
// 也就是 0/1/2），而不是父进程里的 fd 号。以前写成 int(s.Fd()) 时，只要从端在父进程里
// 的 fd 号 >= 3，就会被 os/exec 在 fork 前拦下来：
//
//	"Setctty set but Ctty not valid in child"
//
// 表现为本机终端一律打不开（路由器上进程常开几张表，fd 号基本都大于 2）。
func spawnShell(shell string, tty *os.File) (*exec.Cmd, error) {
	env := append(os.Environ(), "TERM=xterm-256color", "COLORTERM=truecolor")
	var last error

	// 优先带控制终端（Ctrl+C、fg/bg 这类作业控制要它）；失败再退一步不设。
	for _, setctty := range []bool{true, false} {
		cmd := exec.Command(shell, "-i")
		cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
		cmd.Env = env
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: setctty, Ctty: 0}
		if err := cmd.Start(); err == nil {
			return cmd, nil
		} else {
			// 命令可能先 fork 成功了、在子进程里才出错（比如 TIOCSCTTY 被拒），
			// 这时要把残留的子进程收干净再重试。
			last = err
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
				_, _ = cmd.Process.Wait()
			}
		}
	}
	return nil, last
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
