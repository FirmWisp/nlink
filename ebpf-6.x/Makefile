# eBPF 隐身程序 Makefile
#
# 目录结构：
#   ebpf-6.x/
#   ├── Makefile
#   ├── main.go          ← Go 交互式控制台
#   ├── probe_attach.go
#   ├── go.mod / go.sum
#   └── ebpf/
#       ├── stealth.bpf.h  ← 公共 map/常量定义
#       ├── stealth.bpf.c  ← eBPF 内核态程序入口
#       └── stealth.bpf.o  ← 编译产物

CLANG  ?= clang
CC     ?= gcc
GO     ?= go

# stealth.bpf.c 里写的是 #include "../vmlinux.h"，相对于 ebpf/ 子目录
# 所以 vmlinux.h 要放在 ebpf-6.x/ 根目录
VMLINUX_H := vmlinux.h

BPF_SRC  := ebpf/stealth.bpf.c
BPF_HDR  := ebpf/stealth.bpf.h
BPF_OBJ  := ebpf/stealth.bpf.o
CTL_BIN  := stealth_ctl

# eBPF 编译参数
# 调试模式：make bpf DEBUG=1  （开启 bpf_printk 日志）
# 查看日志：cat /sys/kernel/debug/tracing/trace_pipe
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86
ifdef DEBUG
BPF_CFLAGS += -DDEBUG
endif

.PHONY: all clean vmlinux bpf ctl

all: $(VMLINUX_H) bpf ctl

# ── vmlinux.h ──────────────────────────────────────────────
# 从内核 BTF 信息生成，包含所有内核结构体定义
$(VMLINUX_H):
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H); \
		echo "[ok] 生成 $(VMLINUX_H)"; \
	else \
		echo "[err] /sys/kernel/btf/vmlinux 不存在，无法生成 vmlinux.h"; \
		exit 1; \
	fi

# 强制重新生成 vmlinux.h
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)
	@echo "[ok] 重新生成 $(VMLINUX_H)"

# ── eBPF 内核态程序 ──────────────────────────────────────────
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) $(BPF_HDR) $(VMLINUX_H)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "[ok] 编译 $(BPF_OBJ)"

# ── Go 交互式控制台 ──────────────────────────────────────────
ctl: $(CTL_BIN)

$(CTL_BIN): main.go probe_attach.go go.mod
	GOPROXY=https://goproxy.cn,direct $(GO) build -o $(CTL_BIN) .
	@echo "[ok] 编译 $(CTL_BIN)"

# ── 清理 ────────────────────────────────────────────────────
clean:
	rm -f $(BPF_OBJ) $(CTL_BIN)

# 连 vmlinux.h 一起清理
distclean: clean
	rm -f $(VMLINUX_H)
