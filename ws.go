package main

// 最小 WebSocket 服务端：只为终端通道服务。
// 标准库没有 WS，握手和帧编解码都自己写，不额外引依赖。

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

const (
	wsText   = 0x1
	wsBinary = 0x2
	wsClose  = 0x8
	wsPing   = 0x9
	wsPong   = 0xA
)

type wsConn struct {
	c  net.Conn
	br *bufio.Reader
	wm sync.Mutex // 帧不能交错写
}

func upgradeWS(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("不是 WebSocket 请求")
	}
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" {
		return nil, errors.New("缺少 Sec-WebSocket-Key")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("连接不支持接管")
	}
	c, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	h := sha1.New()
	h.Write([]byte(key + wsGUID))
	accept := base64.StdEncoding.EncodeToString(h.Sum(nil))
	resp := "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n\r\n"
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(resp)); err != nil {
		c.Close()
		return nil, err
	}
	_ = c.SetWriteDeadline(time.Time{})
	return &wsConn{c: c, br: brw.Reader}, nil
}

func (w *wsConn) Close() error { return w.c.Close() }

// ReadMessage 读一整帧载荷。控制帧就地处理，只把数据帧交给调用方。
func (w *wsConn) ReadMessage() (byte, []byte, error) {
	for {
		var head [2]byte
		if _, err := io.ReadFull(w.br, head[:]); err != nil {
			return 0, nil, err
		}
		opcode := head[0] & 0x0f
		masked := head[1]&0x80 != 0
		n := int(head[1] & 0x7f)
		switch n {
		case 126:
			var ext [2]byte
			if _, err := io.ReadFull(w.br, ext[:]); err != nil {
				return 0, nil, err
			}
			n = int(binary.BigEndian.Uint16(ext[:]))
		case 127:
			var ext [8]byte
			if _, err := io.ReadFull(w.br, ext[:]); err != nil {
				return 0, nil, err
			}
			n = int(binary.BigEndian.Uint64(ext[:]))
		}
		if n < 0 || n > 1<<20 {
			return 0, nil, errors.New("帧过大")
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(w.br, mask[:]); err != nil {
				return 0, nil, err
			}
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(w.br, payload); err != nil {
			return 0, nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i&3]
			}
		}
		switch opcode {
		case wsPing:
			_ = w.WriteMessage(wsPong, payload)
			continue
		case wsPong:
			continue
		case wsClose:
			return wsClose, payload, io.EOF
		}
		return opcode, payload, nil
	}
}

// WriteMessage 发一帧。服务端发的东西不加掩码。
func (w *wsConn) WriteMessage(opcode byte, data []byte) error {
	var head [10]byte
	head[0] = 0x80 | opcode
	var hlen int
	switch n := len(data); {
	case n < 126:
		head[1] = byte(n)
		hlen = 2
	case n <= 0xffff:
		head[1] = 126
		binary.BigEndian.PutUint16(head[2:], uint16(n))
		hlen = 4
	default:
		head[1] = 127
		binary.BigEndian.PutUint64(head[2:], uint64(n))
		hlen = 10
	}
	w.wm.Lock()
	defer w.wm.Unlock()
	if _, err := w.c.Write(head[:hlen]); err != nil {
		return err
	}
	_, err := w.c.Write(data)
	return err
}

func (w *wsConn) setWriteDeadline(d time.Duration) {
	_ = w.c.SetWriteDeadline(time.Now().Add(d))
}
