obj-m += kjackal.o
kjackal-objs := src/common.o src/module.o src/syscall.o src/tcp4.o src/proc_fs.o src/init.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

