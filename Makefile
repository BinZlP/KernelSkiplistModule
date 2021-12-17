KDIR = /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

obj-m += skiplist_module.o
skiplist_module-objs := fast_mblock.o fc_memory.o multi_skiplist.o skiplist_api.o

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean