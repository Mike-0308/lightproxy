package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 端口转发（内核 DNAT）与防火墙自动放行。
//
// 四条设计原则，都是为了"改错了也不会把路由器搞断网"：
//  1. 所有规则收在自家链里（LP_FWD / LP_ACL / LP_IN / LP_MASQ），只 flush 自己的链，
//     绝不碰系统已有规则，出问题清空即可回滚；
//  2. 转发在内核完成，进程退出规则依然生效，也不占用用户态内存；
//  3. INPUT 只放行反代端口（不含管理面板端口），配合路由器自带防火墙使用；
//  4. 应用成功后落一份开机脚本挂到 OpenWrt 的 firewall include 上，
//     重启路由不用再手动点一次。

const (
	fwNatChain  = "LP_FWD"
	fwAclChain  = "LP_ACL"
	fwInChain   = "LP_IN"
	fwIn6Chain  = "LP_IN6"
	fwMasqChain = "LP_MASQ"
	fwNftTable  = "lp_fwd"
	fwScript    = "firewall.sh"
)

type FirewallState struct {
	Backend   string `json:"backend"`
	Ready     bool   `json:"ready"`
	Applied   int    `json:"applied"`
	Hairpin   bool   `json:"hairpin"`
	OpenPorts []int  `json:"openPorts,omitempty"`
	// RelayPorts 是 IPv6 用户态转发正在监听的端口。
	RelayPorts []int `json:"relayPorts,omitempty"`
	// Knocks 是「敲门放行」名单快照（前缀 + 剩余有效期）。
	Knocks    []string  `json:"knocks,omitempty"`
	Updated   time.Time `json:"updated"`
	Persist    string    `json:"persist,omitempty"`
	Message    string    `json:"message,omitempty"`
	Err        string    `json:"error,omitempty"`
}

type fwTool struct {
	kind string // iptables / nftables / none
	bin  string
}

func findBin(name string, candidates ...string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	return ""
}

func execCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := strings.TrimSpace(buf.String())
	if err != nil {
		if out != "" {
			return out, fmt.Errorf("%s", firstLine(out))
		}
		return "", err
	}
	return out, nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

// detectFirewall 按偏好挑选后端。iptables 在 fw3 与 fw4 上都能跑
// （fw4 环境里 iptables 是 nft 的兼容层），所以默认优先它。
func detectFirewall(prefer string) (fwTool, error) {
	if prefer == "off" {
		return fwTool{kind: "none"}, nil
	}

	var firstErr error
	tryIptables := func() (fwTool, bool) {
		bin := findBin("iptables", "/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables")
		if bin == "" {
			return fwTool{}, false
		}
		if _, err := execCmd(bin, "-t", "nat", "-L", "-n"); err != nil {
			firstErr = fmt.Errorf("iptables 不可用（多半是权限不足，请用 root 运行）: %v", err)
			return fwTool{}, false
		}
		return fwTool{kind: "iptables", bin: bin}, true
	}
	tryNftables := func() (fwTool, bool) {
		bin := findBin("nft", "/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft")
		if bin == "" {
			return fwTool{}, false
		}
		if _, err := execCmd(bin, "list", "tables"); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("nft 不可用（多半是权限不足，请用 root 运行）: %v", err)
			}
			return fwTool{}, false
		}
		return fwTool{kind: "nftables", bin: bin}, true
	}

	switch prefer {
	case "iptables":
		if t, ok := tryIptables(); ok {
			return t, nil
		}
	case "nftables":
		if t, ok := tryNftables(); ok {
			return t, nil
		}
	default: // auto
		if t, ok := tryIptables(); ok {
			return t, nil
		}
		if t, ok := tryNftables(); ok {
			return t, nil
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("系统里既没有 iptables 也没有 nft，无法下发端口转发")
	}
	return fwTool{kind: "none"}, firstErr
}

// ---------------- iptables 查询辅助 ----------------

func iptArgs(table string, rest ...string) []string {
	out := make([]string, 0, len(rest)+4)
	// fw3/fw4 重载时会持有 xtables 锁，此时直接下发会报 "Another app is currently
	// holding the xtables lock" 并触发整体回滚（开机时程序正是被 fw3 拉起的，
	// 撞锁概率极高）。-w 5 表示最多等 5 秒，拿不到锁才失败。
	out = append(out, "-w", "5")
	if table != "" {
		out = append(out, "-t", table)
	}
	return append(out, rest...)
}

func (t fwTool) hasChain(table, chain string) bool {
	_, err := execCmd(t.bin, iptArgs(table, "-S", chain)...)
	return err == nil
}

func (t fwTool) hasJump(table, parent, chain string) bool {
	out, err := execCmd(t.bin, iptArgs(table, "-S", parent)...)
	if err != nil {
		return false
	}
	return strings.Contains(out, "-j "+chain)
}

// ---------------- 应用规则 ----------------

func activeForwardRules(fc ForwardConfig) []ForwardRule {
	out := make([]ForwardRule, 0, len(fc.Rules))
	for _, r := range fc.Rules {
		if !r.Disable {
			out = append(out, r)
		}
	}
	return out
}

// usableForwardRules 返回可以真正下发的转发规则：目标合法、外网端口不与本机
// 已占用端口（反代监听、HTTP 跳转、管理面板）冲突。冲突规则跳过内核 DNAT 和
// 用户态转发，否则外网打到 :8686 这类端口会被劫持到内网目标，反代直接失效。
func usableForwardRules(fc ForwardConfig) (usable []ForwardRule, conflicts []int) {
	occ := make(map[int]bool, len(fc.Occupied))
	for _, p := range fc.Occupied {
		occ[p] = true
	}
	usable = make([]ForwardRule, 0, len(fc.Rules))
	for _, r := range activeForwardRules(fc) {
		if r.Port <= 0 || r.Port > 65535 || r.ToHost == "" || r.ToPort <= 0 {
			continue
		}
		if occ[r.Port] {
			conflicts = append(conflicts, r.Port)
			continue
		}
		usable = append(usable, r)
	}
	return usable, conflicts
}

// relayPorts 返回需要用户态转发的端口去重列表。
func relayPorts(rules []ForwardRule) []int {
	seen := map[int]bool{}
	var out []int
	for _, r := range rules {
		if !seen[r.Port] {
			seen[r.Port] = true
			out = append(out, r.Port)
		}
	}
	return out
}

// mergePorts 合并端口列表并去重升序，供防火墙放行列表使用。
func mergePorts(lists ...[]int) []int {
	seen := map[int]bool{}
	var out []int
	for _, l := range lists {
		for _, p := range l {
			if p > 0 && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Ints(out)
	return out
}

func destOf(r ForwardRule) string {
	return r.ToHost + ":" + strconv.Itoa(r.ToPort)
}

func (t fwTool) apply(fc ForwardConfig) error {
	switch t.kind {
	case "iptables":
		return t.applyIptables(fc)
	case "nftables":
		return t.applyNftables(fc)
	}
	return fmt.Errorf("没有可用的防火墙后端")
}

func (t fwTool) applyIptables(fc ForwardConfig) error {
	usable, _ := usableForwardRules(fc)
	run := func(args ...string) error {
		if _, err := execCmd(t.bin, args...); err != nil {
			return fmt.Errorf("iptables %s 失败: %v", strings.Join(args, " "), err)
		}
		return nil
	}

	// --- nat：DNAT 入口 ---
	if !t.hasChain("nat", fwNatChain) {
		if err := run("-t", "nat", "-N", fwNatChain); err != nil {
			return err
		}
	}
	if !t.hasJump("nat", "PREROUTING", fwNatChain) {
		if err := run("-t", "nat", "-I", "PREROUTING", "1", "-j", fwNatChain); err != nil {
			return err
		}
	}
	if err := run("-t", "nat", "-F", fwNatChain); err != nil {
		return err
	}
	for _, r := range usable {
		for _, p := range protoList(r.Proto) {
			if err := run("-t", "nat", "-A", fwNatChain,
				"-p", p, "--dport", strconv.Itoa(r.Port),
				"-j", "DNAT", "--to-destination", destOf(r)); err != nil {
				return err
			}
		}
	}

	// --- filter：放行转发与回程 ---
	if !t.hasChain("", fwAclChain) {
		if err := run("-N", fwAclChain); err != nil {
			return err
		}
	}
	if !t.hasJump("", "FORWARD", fwAclChain) {
		if err := run("-I", "FORWARD", "1", "-j", fwAclChain); err != nil {
			return err
		}
	}
	if err := run("-F", fwAclChain); err != nil {
		return err
	}
	for _, r := range usable {
		for _, p := range protoList(r.Proto) {
			dp := strconv.Itoa(r.ToPort)
			if err := run("-A", fwAclChain, "-p", p, "-d", r.ToHost, "--dport", dp, "-j", "ACCEPT"); err != nil {
				return err
			}
			if err := run("-A", fwAclChain, "-p", p, "-s", r.ToHost, "--sport", dp,
				"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
				return err
			}
		}
	}

	// --- filter：放行「到路由器自身」的反代端口 ---
	// 路由器自带防火墙（尤其 IPv6）默认拒绝入站，反代端口必须显式放行；
	// 管理面板端口不在 LocalPorts 里，永远不对外开。
	// IPv4 与 IPv6 都要开：公网没有 IPv4 时域名只解析出 AAAA，流量走 v6，
	// 而 fw3 的 zone_wan_input 末尾对 v6 是 REJECT，不开就会表现为「域名能解析但打不开」。
	if err := t.openLocalPorts(fwInChain, fc.LocalPorts); err != nil {
		return err
	}
	if len(fc.LocalPorts) > 0 {
		if t6, ok := ip6Tool(); ok {
			if err := t6.openLocalPorts(fwIn6Chain, fc.LocalPorts); err != nil {
				return err
			}
		}
	}

	// --- nat：内网回环（hairpin）---
	if !t.hasChain("nat", fwMasqChain) {
		if err := run("-t", "nat", "-N", fwMasqChain); err != nil {
			return err
		}
	}
	if !t.hasJump("nat", "POSTROUTING", fwMasqChain) {
		if err := run("-t", "nat", "-I", "POSTROUTING", "1", "-j", fwMasqChain); err != nil {
			return err
		}
	}
	if err := run("-t", "nat", "-F", fwMasqChain); err != nil {
		return err
	}
	if fc.Hairpin {
		for _, r := range usable {
			for _, p := range protoList(r.Proto) {
				if err := run("-t", "nat", "-A", fwMasqChain,
					"-p", p, "-d", r.ToHost, "--dport", strconv.Itoa(r.ToPort),
					"-j", "MASQUERADE"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ip6Tool 返回可用的 ip6tables。老固件可能没装，没装就跳过 IPv6 放行。
func ip6Tool() (fwTool, bool) {
	bin := findBin("ip6tables", "/usr/sbin/ip6tables", "/sbin/ip6tables", "/usr/bin/ip6tables")
	if bin == "" {
		return fwTool{}, false
	}
	if _, err := execCmd(bin, "-S", "INPUT"); err != nil {
		return fwTool{}, false
	}
	return fwTool{kind: "iptables", bin: bin}, true
}

// openLocalPorts 在 INPUT 链前面挂一条自有链，放行本机监听端口。
// 只放行 tcp 且精确到端口，管理面板端口不在 ports 里。
func (t fwTool) openLocalPorts(chain string, ports []int) error {
	if len(ports) == 0 {
		return nil
	}
	run := func(args ...string) error {
		if _, err := execCmd(t.bin, args...); err != nil {
			return fmt.Errorf("%s %s 失败: %v", filepath.Base(t.bin), strings.Join(args, " "), err)
		}
		return nil
	}
	if !t.hasChain("", chain) {
		if err := run("-N", chain); err != nil {
			return err
		}
	}
	if !t.hasJump("", "INPUT", chain) {
		if err := run("-I", "INPUT", "1", "-j", chain); err != nil {
			return err
		}
	}
	if err := run("-F", chain); err != nil {
		return err
	}
	if err := run("-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}
	for _, p := range ports {
		if err := run("-A", chain, "-p", "tcp", "--dport", strconv.Itoa(p), "-j", "ACCEPT"); err != nil {
			return err
		}
	}
	return nil
}

// buildNftScript 一次性渲染整张表，交给 nft -f 加载，
// 避免把含分号的语句塞进 shell 导致转义问题。
func buildNftScript(fc ForwardConfig) string {
	usable, _ := usableForwardRules(fc)
	var b strings.Builder
	b.WriteString("add table inet " + fwNftTable + "\n")
	b.WriteString("delete table inet " + fwNftTable + "\n")
	b.WriteString("table inet " + fwNftTable + " {\n")
	b.WriteString("\tchain prerouting {\n\t\ttype nat hook prerouting priority -110; policy accept;\n")
	for _, r := range usable {
		for _, p := range protoList(r.Proto) {
			fmt.Fprintf(&b, "\t\t%s dport %d dnat ip to %s\n", p, r.Port, destOf(r))
		}
	}
	b.WriteString("\t}\n")
	b.WriteString("\tchain forward {\n\t\ttype filter hook forward priority -10; policy accept;\n")
	for _, r := range usable {
		for _, p := range protoList(r.Proto) {
			dp := strconv.Itoa(r.ToPort)
			fmt.Fprintf(&b, "\t\tip daddr %s %s dport %s accept\n", r.ToHost, p, dp)
			fmt.Fprintf(&b, "\t\tip saddr %s %s sport %s ct state established,related accept\n", r.ToHost, p, dp)
		}
	}
	b.WriteString("\t}\n")
	if len(fc.LocalPorts) > 0 {
		b.WriteString("\tchain input {\n\t\ttype filter hook input priority -10; policy accept;\n")
		b.WriteString("\t\tct state established,related accept\n")
		var ports []string
		for _, p := range fc.LocalPorts {
			ports = append(ports, strconv.Itoa(p))
		}
		fmt.Fprintf(&b, "\t\ttcp dport { %s } accept\n", strings.Join(ports, ", "))
		b.WriteString("\t}\n")
	}
	if fc.Hairpin {
		b.WriteString("\tchain postrouting {\n\t\ttype nat hook postrouting priority 100; policy accept;\n")
		for _, r := range usable {
			for _, p := range protoList(r.Proto) {
				fmt.Fprintf(&b, "\t\tip daddr %s %s dport %s masquerade\n", r.ToHost, p, strconv.Itoa(r.ToPort))
			}
		}
		b.WriteString("\t}\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func (t fwTool) applyNftables(fc ForwardConfig) error {
	f, err := os.CreateTemp("", "lp-nft-*.rules")
	if err != nil {
		return err
	}
	path := f.Name()
	defer os.Remove(path)
	script := buildNftScript(fc)
	if _, err := f.WriteString(script); err != nil {
		f.Close()
		return err
	}
	f.Close()
	if _, err := execCmd(t.bin, "-f", path); err != nil {
		return fmt.Errorf("nft 加载规则失败: %v", err)
	}
	return nil
}

func (t fwTool) clear() error {
	switch t.kind {
	case "iptables":
		var firstErr error
		note := func(err error) {
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if t.hasChain("nat", fwNatChain) {
			_, e := execCmd(t.bin, iptArgs("nat", "-F", fwNatChain)...)
			note(e)
		}
		if t.hasChain("", fwAclChain) {
			_, e := execCmd(t.bin, "-F", fwAclChain)
			note(e)
		}
		if t.hasChain("", fwInChain) {
			_, e := execCmd(t.bin, "-F", fwInChain)
			note(e)
		}
		if t6, ok := ip6Tool(); ok && t6.hasChain("", fwIn6Chain) {
			_, e := execCmd(t6.bin, "-F", fwIn6Chain)
			note(e)
		}
		if t.hasChain("nat", fwMasqChain) {
			_, e := execCmd(t.bin, iptArgs("nat", "-F", fwMasqChain)...)
			note(e)
		}
		return firstErr
	case "nftables":
		// 表不存在时返回错误，属正常
		execCmd(t.bin, "delete", "table", "inet", fwNftTable)
		return nil
	}
	return nil
}

// ---------------- 开机持久化 ----------------

func renderPersistScript(t fwTool, fc ForwardConfig) string {
	usable, _ := usableForwardRules(fc)
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# 由轻代理自动生成，请勿手工修改；改规则请在面板操作。\n")
	if t.kind == "nftables" {
		b.WriteString("NFT=" + t.bin + "\n")
		b.WriteString("[ -x \"$NFT\" ] || NFT=nft\n")
		b.WriteString("cat <<'LPEOF' >/tmp/lp-nft.rules\n")
		b.WriteString(buildNftScript(fc))
		b.WriteString("LPEOF\n")
		b.WriteString("$NFT -f /tmp/lp-nft.rules\n")
		return b.String()
	}

	b.WriteString("IPT=" + t.bin + "\n")
	b.WriteString("[ -x \"$IPT\" ] || IPT=iptables\n")
	fmt.Fprintf(&b, "$IPT -t nat -N %s 2>/dev/null\n", fwNatChain)
	fmt.Fprintf(&b, "$IPT -t nat -C PREROUTING -j %s 2>/dev/null || $IPT -t nat -I PREROUTING 1 -j %s\n", fwNatChain, fwNatChain)
	fmt.Fprintf(&b, "$IPT -t nat -F %s\n", fwNatChain)
	b.WriteString("$IPT -N " + fwAclChain + " 2>/dev/null\n")
	b.WriteString("$IPT -C FORWARD -j " + fwAclChain + " 2>/dev/null || $IPT -I FORWARD 1 -j " + fwAclChain + "\n")
	b.WriteString("$IPT -F " + fwAclChain + "\n")
	if len(fc.LocalPorts) > 0 {
		b.WriteString("$IPT -N " + fwInChain + " 2>/dev/null\n")
		b.WriteString("$IPT -C INPUT -j " + fwInChain + " 2>/dev/null || $IPT -I INPUT 1 -j " + fwInChain + "\n")
		b.WriteString("$IPT -F " + fwInChain + "\n")
		b.WriteString("$IPT -A " + fwInChain + " -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n")
		for _, p := range fc.LocalPorts {
			fmt.Fprintf(&b, "$IPT -A %s -p tcp --dport %d -j ACCEPT\n", fwInChain, p)
		}
		// IPv6 没有 NAT，外网直接打到路由器自身，fw3 的 zone_wan_input 末尾是 REJECT
		b.WriteString("IP6=$(command -v ip6tables 2>/dev/null)\n")
		b.WriteString("if [ -n \"$IP6\" ]; then\n")
		fmt.Fprintf(&b, "  $IP6 -N %s 2>/dev/null\n", fwIn6Chain)
		fmt.Fprintf(&b, "  $IP6 -C INPUT -j %s 2>/dev/null || $IP6 -I INPUT 1 -j %s\n", fwIn6Chain, fwIn6Chain)
		fmt.Fprintf(&b, "  $IP6 -F %s\n", fwIn6Chain)
		fmt.Fprintf(&b, "  $IP6 -A %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n", fwIn6Chain)
		for _, p := range fc.LocalPorts {
			fmt.Fprintf(&b, "  $IP6 -A %s -p tcp --dport %d -j ACCEPT\n", fwIn6Chain, p)
		}
		b.WriteString("fi\n")
	}
	fmt.Fprintf(&b, "$IPT -t nat -N %s 2>/dev/null\n", fwMasqChain)
	fmt.Fprintf(&b, "$IPT -t nat -C POSTROUTING -j %s 2>/dev/null || $IPT -t nat -I POSTROUTING 1 -j %s\n", fwMasqChain, fwMasqChain)
	fmt.Fprintf(&b, "$IPT -t nat -F %s\n", fwMasqChain)

	for _, r := range usable {
		for _, p := range protoList(r.Proto) {
			dp := strconv.Itoa(r.ToPort)
			fmt.Fprintf(&b, "$IPT -t nat -A %s -p %s --dport %d -j DNAT --to-destination %s\n",
				fwNatChain, p, r.Port, destOf(r))
			fmt.Fprintf(&b, "$IPT -A %s -p %s -d %s --dport %s -j ACCEPT\n", fwAclChain, p, r.ToHost, dp)
			fmt.Fprintf(&b, "$IPT -A %s -p %s -s %s --sport %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n",
				fwAclChain, p, r.ToHost, dp)
			if fc.Hairpin {
				fmt.Fprintf(&b, "$IPT -t nat -A %s -p %s -d %s --dport %s -j MASQUERADE\n",
					fwMasqChain, p, r.ToHost, dp)
			}
		}
	}
	return b.String()
}

// ensureFirewallInclude 把脚本挂到 OpenWrt 的开机流程上。
// 优先用 uci 写 include 段（标准方式，格式不会坏），
// 没有 uci 时退而求其次改 /etc/rc.local。
// 段名用 lightproxy_fw，与 install.sh 挂启动项用的 lightproxy 段区分开，
// 否则两个同名 section 会被 uci 合并出诡异行为。
func ensureFirewallInclude(scriptPath string) string {
	const fwCfg = "/etc/config/firewall"
	if _, err := os.Stat(fwCfg); err == nil {
		if uci, lookErr := exec.LookPath("uci"); lookErr == nil {
			out, _ := execCmd(uci, "-q", "show", "firewall.lightproxy_fw")
			if strings.Contains(out, scriptPath) {
				return "已挂在 /etc/config/firewall（uci include）"
			}
			execCmd(uci, "set", "firewall.lightproxy_fw=include")
			execCmd(uci, "set", "firewall.lightproxy_fw.type=script")
			execCmd(uci, "set", "firewall.lightproxy_fw.path="+scriptPath)
			execCmd(uci, "set", "firewall.lightproxy_fw.enabled=1")
			if _, err := execCmd(uci, "commit", "firewall"); err != nil {
				return "uci 写入失败：" + err.Error()
			}
			return "已挂在 /etc/config/firewall（uci include），重启自动恢复"
		}

		// 没有 uci 的老固件：直接追加文本，段名同样错开
		data, _ := os.ReadFile(fwCfg)
		if strings.Contains(string(data), scriptPath) {
			return "已挂在 /etc/config/firewall"
		}
		block := "\nconfig include 'lightproxy_fw'\n\toption type 'script'\n\toption path '" + scriptPath + "'\n\toption enabled '1'\n"
		f, err := os.OpenFile(fwCfg, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return "无法写入 /etc/config/firewall：" + err.Error()
		}
		defer f.Close()
		if _, err := f.WriteString(block); err != nil {
			return "无法写入 /etc/config/firewall：" + err.Error()
		}
		return "已挂在 /etc/config/firewall，重启自动恢复"
	}

	const rcLocal = "/etc/rc.local"
	if data, err := os.ReadFile(rcLocal); err == nil {
		s := string(data)
		if strings.Contains(s, scriptPath) {
			return "已挂在 /etc/rc.local"
		}
		line := "[ -x " + scriptPath + " ] && " + scriptPath + "\n"
		if i := strings.Index(s, "exit 0"); i >= 0 {
			s = s[:i] + line + s[i:]
		} else {
			s += line
		}
		if err := os.WriteFile(rcLocal, []byte(s), 0o755); err != nil {
			return "无法写入 /etc/rc.local：" + err.Error()
		}
		return "已挂在 /etc/rc.local，重启自动恢复"
	}
	return "未找到 OpenWrt 防火墙配置，重启后需手动执行 " + scriptPath
}

// ---------------- 管理器 ----------------

type ForwardManager struct {
	mu      sync.Mutex
	logs    *LogBuffer
	cfgPath string
	relay   *Relay
	state   FirewallState
}

func NewForwardManager(logs *LogBuffer, cfgPath string) *ForwardManager {
	return &ForwardManager{logs: logs, cfgPath: cfgPath, relay: NewRelay(logs)}
}

// Close 停掉用户态转发，进程退出前调用。
func (m *ForwardManager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.relay != nil {
		m.relay.Stop()
	}
}

func (m *ForwardManager) Snapshot() FirewallState {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.state
	// 名单随时在变（不经过 Apply），取快照时顺带带上当前状态
	if st.Knocks = knocks.snapshot(); len(st.Knocks) == 0 {
		st.Knocks = nil
	}
	return st
}

// Apply 是幂等的：重复调用只会 flush 并重写自己的链。
//
// 注意：端口放行（LP_IN）与端口转发规则是解耦的——即使用户没启用端口转发，
// 反代自己的监听端口也要在路由器防火墙上放行。外网映射进来的流量 DNAT 到
// 路由器自身后走 INPUT 链，会被默认的 WAN 入站策略拦掉（小米等固件只对
// 映射时的原始外网端口放行，不放行转换后的本机端口）。
func (m *ForwardManager) Apply(fc ForwardConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	usable, conflicts := usableForwardRules(fc)
	if len(conflicts) > 0 && m.logs != nil {
		m.logs.Warnf("转发规则的外网端口 %v 与反代/面板端口冲突，已整条跳过（换一个外网端口即可）", conflicts)
	}

	// 用户态转发（IPv6 → 内网）与防火墙完全解耦：防火墙不可用（Windows、
	// 缺 iptables）也能工作；IPv4 流量已被 DNAT 接管，这里的监听只吃 IPv6。
	var rports []int
	if fc.Enable && fc.V6On() && len(usable) > 0 {
		m.relay.Apply(usable)
		rports = relayPorts(usable)
		// 映射端口也要写进 INPUT 放行（v4/v6 都开）：IPv6 流量要打到路由器
		// 自身才能被用户态转发接住，防火墙不开就表现为「域名能解析但连不上」。
		fc.LocalPorts = mergePorts(fc.LocalPorts, rports)
	} else {
		m.relay.Apply(nil)
	}

	// 什么都没有：尽力清理内核残留，环境里没有防火墙工具不算错误
	if !fc.Enable && len(fc.LocalPorts) == 0 {
		st := FirewallState{Backend: "off", Updated: time.Now(), RelayPorts: rports}
		if t, derr := detectFirewall(fc.Backend); derr == nil && t.kind != "none" {
			if err := t.clear(); err != nil {
				st.Err = err.Error()
			} else {
				st.Message = "已关闭，内核规则已清除"
			}
		}
		m.state = st
		return nil
	}

	t, derr := detectFirewall(fc.Backend)
	st := FirewallState{Backend: t.kind, Updated: time.Now(), RelayPorts: rports}
	if derr != nil {
		st.Err = derr.Error()
		m.state = st
		// 只放行监听端口属于尽力而为（比如 Windows 上没有 iptables），不作为错误
		if fc.Enable {
			if m.logs != nil {
				m.logs.Errorf("端口转发不可用: %v", derr)
			}
			return derr
		}
		if m.logs != nil {
			m.logs.Warnf("防火墙工具不可用，未能自动放行反代端口: %v", derr)
		}
		return nil
	}

	// 端口转发未启用：不下发转发规则，只放行本机监听端口
	if !fc.Enable {
		fc.Rules = nil
		fc.Hairpin = false
	}

	if err := t.apply(fc); err != nil {
		t.clear()
		st.Err = err.Error()
		m.state = st
		if m.logs != nil {
			m.logs.Errorf("防火墙规则下发失败，已回滚: %v", err)
		}
		return err
	}

	st.Ready = true
	st.Applied = len(usable)
	st.Hairpin = fc.Hairpin
	st.OpenPorts = fc.LocalPorts
	st.Persist = m.persist(t, fc)

	m.state = st
	if m.logs != nil {
		if fc.Enable {
			m.logs.Infof("端口转发已生效：%d 条规则（%s，IPv6 用户态转发 %v），%s",
				st.Applied, t.kind, rports, st.Persist)
		} else {
			m.logs.Infof("端口转发未启用；已自动放行本机端口 %v（%s），%s", fc.LocalPorts, t.kind, st.Persist)
		}
	}
	return nil
}

func (m *ForwardManager) persist(t fwTool, fc ForwardConfig) string {
	dir := filepath.Dir(m.cfgPath)
	if dir == "" || dir == "." {
		return "配置目录不可写，未做开机持久化"
	}
	path := filepath.Join(dir, fwScript)
	if err := os.WriteFile(path, []byte(renderPersistScript(t, fc)), 0o755); err != nil {
		return "写入开机脚本失败：" + err.Error()
	}
	return ensureFirewallInclude(path)
}
