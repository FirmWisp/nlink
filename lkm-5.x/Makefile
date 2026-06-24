# VL Stealth LKM Makefile for Linux 5.x
# Target: Ubuntu 20.04/22.04, Debian 11, Rocky/AlmaLinux 9

obj-m := vl_stealth_5x.o

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build

GO ?= /usr/local/go/bin/go
GO_CONTROL := vl_control_go

ccflags-y := -w

all: module control

module:
	@make -C $(KDIR) M=$(PWD) modules 2>/dev/null || make -C $(KDIR) M=$(PWD) modules

control: $(GO_CONTROL)

$(GO_CONTROL): vl_control.go
	$(GO) build -o $(GO_CONTROL) vl_control.go

clean:
	@cp go.mod /tmp/vl_control_go.mod.bak 2>/dev/null || true
	@make -C $(KDIR) M=$(PWD) clean 2>/dev/null || rm -f *.o *.ko *.mod.c *.mod *.symvers *.order
	@cp /tmp/vl_control_go.mod.bak go.mod 2>/dev/null || true
	rm -f $(GO_CONTROL)

.PHONY: all module control clean
