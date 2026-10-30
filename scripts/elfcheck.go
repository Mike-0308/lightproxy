//go:build ignore

// elfcheck 核对 ELF 产物的真实架构（e_machine），防止交叉编译配置漂移。
// 用法: go run scripts/elfcheck.go <file>:<e_machine> ...
// 常见值: armv7=40, arm64=183, amd64=62, mipsle=8（按文件字节序解析）
package main

import (
	"encoding/binary"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "用法: go run scripts/elfcheck.go <file>:<e_machine> ...")
		os.Exit(2)
	}
	bad := false
	for _, arg := range os.Args[1:] {
		var name string
		var want uint16
		if _, err := fmt.Sscanf(arg, "%s", &name); err != nil {
			fmt.Fprintln(os.Stderr, "参数无效:", arg)
			bad = true
			continue
		}
		// 拆 "file:machine"，file 里允许冒号之后的才算，取最后一个冒号
		i := len(arg) - 1
		for i >= 0 && arg[i] != ':' {
			i--
		}
		if i <= 0 {
			fmt.Fprintln(os.Stderr, "参数应为 <file>:<e_machine>:", arg)
			bad = true
			continue
		}
		name = arg[:i]
		if _, err := fmt.Sscanf(arg[i+1:], "%d", &want); err != nil {
			fmt.Fprintln(os.Stderr, "e_machine 应为数字:", arg)
			bad = true
			continue
		}
		hdr, err := os.ReadFile(name)
		if err != nil {
			fmt.Fprintln(os.Stderr, "读不到产物:", err)
			bad = true
			continue
		}
		if len(hdr) < 20 || string(hdr[:4]) != "\x7fELF" {
			fmt.Fprintf(os.Stderr, "%s 不是 ELF 文件\n", name)
			bad = true
			continue
		}
		var endian binary.ByteOrder = binary.LittleEndian
		if hdr[5] == 2 {
			endian = binary.BigEndian
		}
		mach := endian.Uint16(hdr[18:20])
		if mach != want {
			fmt.Fprintf(os.Stderr, "%s 架构不符: e_machine=%d 期望 %d\n", name, mach, want)
			bad = true
			continue
		}
		fmt.Printf("%-40s e_machine=%d OK\n", name, mach)
	}
	if bad {
		os.Exit(1)
	}
}
