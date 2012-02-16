obj-m += open-hijack.o

TABLE=$(shell grep ' sys_call_table' /boot/System.map-$(shell uname -r) | awk '{print $$1}')

all:
	@echo "Replacing sys call table addresse $(TABLE) in source"
	@echo
	@sed -i 's/SYS_CALL_TABLE/$(TABLE)/g' open-hijack.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	# Removing addresse in source
	@sed -i 's/$(TABLE)/SYS_CALL_TABLE/g' open-hijack.c
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

