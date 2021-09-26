TARGET_MODULE := vwifi
obj-m := $(TARGET_MODULE).o

ccflags-y := -std=gnu99 -Wno-declaration-after-statement
KDIR := /lib/modules/$(shell uname -r)/build
GIT_HOOKS := .git/hooks/applied

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	modprobe cfg80211
	sudo insmod $(TARGET_MODULE).ko
unload:
	sudo rmmod $(TARGET_MODULE) || true >/dev/null

check: all
	$(MAKE) unload
	$(MAKE) load
	@scripts/verify.sh
	@$(MAKE) unload