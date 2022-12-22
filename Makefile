ifneq ($(KERNELRELEASE),)
include Kbuild
else
KDIR ?= /lib/modules/`uname -r`/build

default:
	./scripts/format.sh && bear -- $(MAKE) -C $(KDIR) M=$$PWD

modules:
	$(MAKE) CONFIG_DEBUG_WRITABLE_FUNCTION_POINTERS_VERBOSE=y -C $(KDIR) M=$$PWD modules

modules_install:
	$(MAKE) -C $(KDIR) M=$$PWD modules_install

clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean

.PHONY: modules modules_install clean

endif
