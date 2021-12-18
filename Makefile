KDIR = /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

obj-m += sl_module.o
sl_module-objs := skiplist_module.o fast_mblock.o fc_memory.o multi_skiplist.o skiplist_api.o common_define.o

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean