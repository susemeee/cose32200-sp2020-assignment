
obj-m += lkm_proc_firewall.o
KDIR = /home/susemeee/linux
ccflags-y := -std=gnu99

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order

