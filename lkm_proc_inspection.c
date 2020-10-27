#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#include "src/circular_queue.h"

#define PROC_FILENAME "inspectfs"

#define BUFFER_SIZE 1000

extern circular_queue blk_inspection_queue;

static struct proc_dir_entry* proc_file;

static int my_open(struct inode* inode, struct file* file) {
  printk(KERN_INFO "Simple Module Open!!\n");
  return 0;
}

static ssize_t my_write(struct file* file, const char __user* user_buffer, size_t count, loff_t* ppos) {
  printk(KERN_INFO "Simple Module Write!!\n");
  return -1;
}

static ssize_t my_read(struct file* file, char __user* user_buffer, size_t count, loff_t* ppos) {

    int buffer_length = 0;
    char buffer[BUFFER_SIZE];
	printk(KERN_INFO "procfile_read (/proc/%s) called\n", PROC_FILENAME);
	
	if (*ppos > 0 || count < BUFFER_SIZE) {
		return 0;
	} else {

        sector_info* si;
        while ((si = dequeue(&blk_inspection_queue)) != NULL) {

            buffer_length += sprintf(buffer + buffer_length, "[QUEUE] name=%s dev=%s sector_index=%llu at=%d\n", si->procname, si->devname, si->number, si->at);

        }

        if (buffer_length > 0 && copy_to_user(user_buffer, buffer, buffer_length)) {
            return -EFAULT;
        }

        *ppos = buffer_length;
        return buffer_length;
	}
}

static const struct file_operations myproc_fops = {
  .owner = THIS_MODULE,
  .open = my_open,
  .write = my_write,
  .read = my_read,
};

static int __init simple_init(void) {
  printk(KERN_INFO "Simple Module Init!!\n");

  proc_file = proc_create(PROC_FILENAME, 0600, NULL, &myproc_fops);

  return 0;
}

static void __exit simple_exit(void) {
  printk(KERN_INFO "Simple Module Exit!!\n");

  remove_proc_entry(PROC_FILENAME, NULL);
  return;
}

module_init(simple_init);
module_exit(simple_exit);

MODULE_AUTHOR("Korea University");
MODULE_DESCRIPTION("It's simple!!");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");

