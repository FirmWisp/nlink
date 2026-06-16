# VL Stealth LKM Makefile for Linux 5.x
# Target: Ubuntu 20.04/22.04, Debian 11, Rocky/AlmaLinux 9

obj-m := vl_stealth_5x.o

KVER ?= $(shell uname -r)
KDIR ?= /lib/modules/$(KVER)/build

ccflags-y := -w

all:
	@make -C $(KDIR) M=$(PWD) modules 2>/dev/null || make -C $(KDIR) M=$(PWD) modules

clean:
	@make -C $(KDIR) M=$(PWD) clean 2>/dev/null || rm -f *.o *.ko *.mod.c *.mod *.symvers *.order

.PHONY: all clean
