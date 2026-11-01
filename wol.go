package main

// 网络唤醒（WOL）：纯 UDP 魔术包，不引入任何依赖。
// 设备表存在 config.wol.devices，接口只按名称/下标取，不接受前端传任意广播地址。

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// WOLDevice 是一台待唤醒设备。字段尽量少，够用就行。
type WOLDevice struct {
	Name      string   `json:"name"`
	MACs      []string `json:"macs"`
	Broadcast string   `json:"broadcast,omitempty"` // 空则用 255.255.255.255
	Port      int      `json:"port,omitempty"`      // 空则 9
	Repeat    int      `json:"repeat,omitempty"`    // 空则 3
	ProbeIP   string   `json:"probeIP,omitempty"`   // 预留：唤醒后探活的目标
	Disable   bool     `json:"disable,omitempty"`
}

// magicPacket 拼 6 字节 0xFF + 16 遍 MAC。
func magicPacket(mac string) ([]byte, error) {
	hw, err := net.ParseMAC(strings.TrimSpace(mac))
	if err != nil {
		return nil, fmt.Errorf("MAC 无效: %s", mac)
	}
	if len(hw) != 6 {
		return nil, fmt.Errorf("只支持 6 字节 MAC: %s", mac)
	}
	pkt := make([]byte, 6+16*6)
	for i := 0; i < 6; i++ {
		pkt[i] = 0xff
	}
	for i := 1; i <= 16; i++ {
		copy(pkt[6*i:], hw)
	}
	return pkt, nil
}

// wakeDevice 给一台设备的全部 MAC 发魔术包。
// 广播地址写 255.255.255.255 时由内核按路由表挑出口，
// 跨网段要填该网段的广播地址（如 192.168.31.255）。
func wakeDevice(d WOLDevice, logs *LogBuffer) (int, error) {
	if len(d.MACs) == 0 {
		return 0, fmt.Errorf("没有配置 MAC")
	}
	addr := strings.TrimSpace(d.Broadcast)
	if addr == "" {
		addr = "255.255.255.255"
	}
	port := d.Port
	if port <= 0 {
		port = 9
	}
	repeat := d.Repeat
	if repeat <= 0 {
		repeat = 3
	}
	if repeat > 20 {
		repeat = 20
	}

	conn, err := net.Dial("udp4", net.JoinHostPort(addr, fmt.Sprint(port)))
	if err != nil {
		return 0, fmt.Errorf("打开 UDP 失败: %w", err)
	}
	defer conn.Close()

	sent := 0
	for _, mac := range d.MACs {
		pkt, err := magicPacket(mac)
		if err != nil {
			return sent, err
		}
		for i := 0; i < repeat; i++ {
			if _, err := conn.Write(pkt); err != nil {
				return sent, fmt.Errorf("发送到 %s 失败: %w", addr, err)
			}
			sent++
			if i != repeat-1 {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
	if logs != nil {
		logs.Infof("WOL 已发送「%s」→ %s:%d，%d 个包（%s）",
			d.Name, addr, port, sent, strings.Join(d.MACs, ", "))
	}
	return sent, nil
}

// handleWOLWake 唤醒一台已配置的设备。body: {"name":"群晖"} 或 {"index":0}
func (a *App) handleWOLWake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "只支持 POST"})
		return
	}
	var req struct {
		Name  string `json:"name"`
		Index int    `json:"index"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<13)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "请求体不是合法 JSON"})
		return
	}
	cfg := a.Config()
	if len(cfg.WOL.Devices) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "还没有配置唤醒设备"})
		return
	}
	var dev *WOLDevice
	for i := range cfg.WOL.Devices {
		if req.Name != "" && cfg.WOL.Devices[i].Name == req.Name {
			dev = &cfg.WOL.Devices[i]
			break
		}
		if req.Name == "" && req.Index == i {
			dev = &cfg.WOL.Devices[i]
			break
		}
	}
	if dev == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "没有这台设备"})
		return
	}
	n, err := wakeDevice(*dev, a.logs)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "sent": n})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sent": n, "name": dev.Name})
}
