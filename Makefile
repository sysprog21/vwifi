TARGET_MODULE := vwifi
obj-m := $(TARGET_MODULE).o

ccflags-y := -std=gnu99 -Wno-declaration-after-statement
KDIR ?= /lib/modules/$(shell uname -r)/build
GIT_HOOKS := .git/hooks/applied

all:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KDIR) M=$(shell pwd) clean

check: all
	@scripts/verify.sh
