#
# Make file for kjackal module creating kjackal.ko
#

SRCDIR := src
KERNELDIR := "/lib/modules/$(shell uname -r)/build"
SYSMAP := "/boot/System.map-$(shell uname -r)"
PWD := $(shell pwd)

obj-m += kjackal.o
kjackal-objs := $(SRCDIR)/common.o $(SRCDIR)/module.o $(SRCDIR)/syscall.o \
				$(SRCDIR)/proc_fs.o $(SRCDIR)/init.o $(SRCDIR)/tcp4.o

SYM_MOD_KSET=$(shell grep ' module_kset' $(SYSMAP) | awk '{print $$1}')
SYM_SYSCALL_TABLE=$(shell grep ' sys_call_table' $(SYSMAP) | awk '{print $$1}')
SYM_KTEXT=$(shell grep ' core_kernel_text' $(SYSMAP) | awk '{print $$1}')

default:
	@echo "Replacing MARKER_SYS_CALL_TABLE symbol by $(SYM_SYSCALL_TABLE) in source"
	@echo "Replacing MARKER_MODULE_KSET symbol $(SYM_MOD_KSET) in source"
	@echo "Replacing MARKER_CORE_KERNEL_TEXT symbol $(SYM_KTEXT) in source"
	@echo
	@sed -i 's/MARKER_SYS_CALL_TABLE/$(SYM_SYSCALL_TABLE)/g' $(SRCDIR)/common.c
	@sed -i 's/MARKER_MODULE_KSET/$(SYM_MOD_KSET)/g' $(SRCDIR)/common.c
	@sed -i 's/MARKER_CORE_KERNEL_TEXT/$(SYM_KTEXT)/g' $(SRCDIR)/common.c
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules
	@echo
	# Restoring symbol in source code
	@sed -i 's/$(SYM_SYSCALL_TABLE)/MARKER_SYS_CALL_TABLE/g' $(SRCDIR)/common.c
	@sed -i 's/$(SYM_MOD_KSET)/MARKER_MODULE_KSET/g' $(SRCDIR)/common.c
	@sed -i 's/$(SYM_KTEXT)/MARKER_CORE_KERNEL_TEXT/g' $(SRCDIR)/common.c

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

%.i: %.c
	$(MAKE) -C $(KERNELDIR) M=$(PWD) $@
