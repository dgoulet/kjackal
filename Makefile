obj-m += kjackal.o
kjackal-objs := src/common.o src/module.o src/syscall.o src/tcp4.o src/proc_fs.o src/init.o

MOD_KSET=$(shell grep ' module_kset' /boot/System.map-$(shell uname -r) | awk '{print $$1}')
TABLE=$(shell grep ' sys_call_table' /boot/System.map-$(shell uname -r) | awk '{print $$1}')
KERN_TEXT=$(shell grep ' core_kernel_text' /boot/System.map-$(shell uname -r) | awk '{print $$1}')

all:
	@echo "Replacing sys call table address $(TABLE) in source"
	@echo "Replacing module_kset address $(MOD_KSET) in source"
	@echo "Replacing core_kernel_text address $(KERN_TEXT) in source"
	@echo
	@sed -i 's/SYS_CALL_TABLE/$(TABLE)/g' src/common.c
	@sed -i 's/MODULE_KSET/$(MOD_KSET)/g' src/common.c
	@sed -i 's/CORE_KERNEL_TEXT/$(KERN_TEXT)/g' src/common.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	@echo
	# Restoring symbol in source code
	@sed -i 's/$(TABLE)/SYS_CALL_TABLE/g' src/common.c
	@sed -i 's/$(MOD_KSET)/MODULE_KSET/g' src/common.c
	@sed -i 's/$(KERN_TEXT)/CORE_KERNEL_TEXT/g' src/common.c

clean:
	rm -f *.o *.ko *.mod.c *.cmd *.mod Module.symvers modules.order
