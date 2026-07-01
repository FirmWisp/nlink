package main

import (
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// attachBySpec 根据程序在 ELF 中的 SEC 名称决定挂载方式
// iface 仅 XDP 程序需要，其他类型忽略
func attachBySpec(prog *ebpf.Program, sectionName string, iface string) (link.Link, error) {
	sec := sectionName
	switch {
	// kprobe/funcname
	case strings.HasPrefix(sec, "kprobe/"):
		fn := strings.TrimPrefix(sec, "kprobe/")
		return link.Kprobe(fn, prog, nil)

	// kretprobe/funcname
	case strings.HasPrefix(sec, "kretprobe/"):
		fn := strings.TrimPrefix(sec, "kretprobe/")
		return link.Kretprobe(fn, prog, nil)

	// tp/syscalls/sys_enter_getdents64 → group=syscalls, name=sys_enter_getdents64
	case strings.HasPrefix(sec, "tp/"):
		parts := strings.SplitN(strings.TrimPrefix(sec, "tp/"), "/", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("无效 tracepoint SEC: %s", sec)
		}
		return link.Tracepoint(parts[0], parts[1], prog, nil)

	// xdp → 需要指定网卡
	case sec == "xdp":
		if iface == "" {
			return nil, fmt.Errorf("XDP 程序需要指定 --iface <网卡名>")
		}
		netIf, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, fmt.Errorf("找不到网卡 %s: %w", iface, err)
		}
		return link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: netIf.Index,
		})

	default:
		return nil, fmt.Errorf("不支持的 SEC 类型: %s", sec)
	}
}
