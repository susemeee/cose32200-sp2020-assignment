
obj-m += src/lkm_proc_example.o

all:
	$(MAKE) -C src
clean:
	rm -rf *.o *.ko *.mod.* *.symvers *.order

