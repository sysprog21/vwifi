TARGET_MODULE := vwifi
obj-m := $(TARGET_MODULE).o

ccflags-y := -std=gnu99 -Wno-declaration-after-statement
KDIR ?= /lib/modules/$(shell uname -r)/build
GIT_HOOKS := .git/hooks/applied

all: kmod vwifi-tool

kmod:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules

vwifi-tool: vwifi-tool.c
	$(CC) $(ccflags-y) -o $@ $<

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) clean
	$(RM) vwifi-tool

check: all
	@scripts/verify.sh