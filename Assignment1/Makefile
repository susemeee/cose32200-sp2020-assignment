
obj-m += lkm_proc_inspection.o
KDIR = /home/susemeee/linux

all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order

