package main

// SSH 终端：用 golang.org/x/crypto/ssh 建一条真正的 SSH 会话。
// 这是项目里唯一的第三方依赖（约 345KB），换来的是不回显、能跑 vim/top 的真终端。
//
// 会话保持和本机终端一致：连接由 ssh.Client 持有，浏览器断开只是解绑 WebSocket，
// 远端 shell 继续活着，重连接回去还能看到原来的输出。

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type sshStream struct {
	client *ssh.Client
	sess   *ssh.Session
	stdin  io.WriteCloser
	stdout io.Reader
	once   sync.Once
}

func (s *sshStream) resize(rows, cols uint16) {
	if s.sess != nil && rows > 0 && cols > 0 {
		_ = s.sess.WindowChange(int(rows), int(cols))
	}
}

func (s *sshStream) close() {
	s.once.Do(func() {
		if s.sess != nil {
			_ = s.sess.Close()
		}
		if s.client != nil {
			_ = s.client.Close()
		}
	})
}

// startSSH 连接并开一个交互式 shell。
func startSSH(c SSHConn, rows, cols uint16) (*sshStream, error) {
	var auths []ssh.AuthMethod
	switch c.Auth {
	case "key":
		raw, err := os.ReadFile(c.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("读私钥失败: %w", err)
		}
		var signer ssh.Signer
		if c.KeyPass != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(raw, []byte(c.KeyPass))
		} else {
			signer, err = ssh.ParsePrivateKey(raw)
		}
		if err != nil {
			return nil, fmt.Errorf("私钥无法解析（口令错了？）: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	default:
		auths = append(auths, ssh.Password(c.Password))
	}

	port := c.Port
	if port <= 0 {
		port = 22
	}
	addr := net.JoinHostPort(c.Host, strconv.Itoa(port))
	cfg := &ssh.ClientConfig{
		User:            c.User,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return nil, fmt.Errorf("连接 %s 失败: %w", addr, err)
	}
	sess, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("打开会话失败: %w", err)
	}
	if rows == 0 {
		rows = 30
	}
	if cols == 0 {
		cols = 100
	}
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := sess.RequestPty("xterm-256color", int(rows), int(cols), modes); err != nil {
		sess.Close()
		client.Close()
		return nil, fmt.Errorf("申请伪终端失败: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		sess.Close()
		client.Close()
		return nil, err
	}
	// stdout 与 stderr 合并成一路：终端里本来就不区分，分开反而会串行错乱
	pr, pw := io.Pipe()
	sess.Stdout = pw
	sess.Stderr = pw
	if err := sess.Shell(); err != nil {
		sess.Close()
		client.Close()
		return nil, fmt.Errorf("启动 shell 失败: %w", err)
	}

	go func() {
		err := sess.Wait()
		_ = pw.CloseWithError(err)
	}()

	// keepalive：家用 NAT 上空闲连接容易被踢，30 秒打一次心跳
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		fails := 0
		for range t.C {
			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				fails++
				if fails >= 3 {
					_ = client.Close()
					return
				}
				continue
			}
			fails = 0
		}
	}()

	return &sshStream{client: client, sess: sess, stdin: stdin, stdout: pr}, nil
}
