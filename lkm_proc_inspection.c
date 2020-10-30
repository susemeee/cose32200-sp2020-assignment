#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#include "src/circular_queue.h"

#define PROC_FILENAME "inspectfs"
#define BUFFER_SIZE 10000

char buffer[BUFFER_SIZE];

/**
 * 커널 코드 / 커널 스페이스에 정의되어있는 blk_inspection_queue (EXPORT_SYMBOL이 적용되어있음)
 */
extern circular_queue blk_inspection_queue;

static struct proc_dir_entry* proc_file;

static int proc_open(struct inode* inode, struct file* file) {
  printk(KERN_INFO "FSInspect Module Open!!\n");
  return 0;
}

static ssize_t proc_write(struct file* file, const char __user* user_buffer, size_t count, loff_t* ppos) {
  printk(KERN_INFO "FSInspect Module Write!!\n");
  return -1;
}

/**
 * proc 파일이 read (e.g. cat /proc/PROC_FILENAME) 될 때 실행되는 부분.
 * user space에서는 리턴값(buffer_length)만큼 user_buffer를 읽음.
 */
static ssize_t proc_read(struct file* file, char __user* user_buffer, size_t count, loff_t* ppos) {

  int buffer_length = 0;
  printk(KERN_INFO "procfile_read (/proc/%s) called\n", PROC_FILENAME);

  if (*ppos > 0 || count < BUFFER_SIZE) {
    // user가 처음 read를 한 케이스가 아니거나(ppos > 0), read count가 buffer size보다 작을 경우, EOF(0)를 리턴한다.
    return 0;
  } else {

    sector_info si;
    // 커널 스페이스에 있는 blk_inspection_queue에서 sector_info를 dequeue 해온다.
    while ((si = dequeue(&blk_inspection_queue)).is_valid != 0) {
      // sector_info가 커널 코드에서 잘 채워졌다면(is_valid == 1), sector_info에 저장되어있던 값을 string으로 기록한다.
      buffer_length += sprintf(buffer + buffer_length, "[QUEUE] pid=%d fs=%s sector_index=%Lu at=%lld\n", si.pid, si.fsname, si.number, si.at);

    }
    // kernel -> user space로 buffer를 복사한다. 실패할 경우 segfault
    if (buffer_length > 0 && copy_to_user(user_buffer, buffer, buffer_length)) {
      return -EFAULT;
    }

    // read seek position을 buffer_length만큼 이동
    *ppos = buffer_length;
    return buffer_length;
  }
}

static const struct file_operations myproc_fops = {
  .owner = THIS_MODULE,
  /** proc 파일이 open될 때 실행 */
  .open = proc_open,
  /** proc 파일이 write될 때 실행 */
  .write = proc_write,
  /** proc 파일이 read될 때 실행 */
  .read = proc_read,
};

static int __init simple_init(void) {
  printk(KERN_INFO "FSInspect Module Init!!\n");

  /** /proc 디렉터리에 PROC_FILENAME 이름으로 proc 파일 생성 */
  proc_file = proc_create(PROC_FILENAME, 0600, NULL, &myproc_fops);

  return 0;
}

static void __exit simple_exit(void) {
  printk(KERN_INFO "FSInspect Module Exit!!\n");

  /** 모듈이 비활성화될 때 proc 파일 삭제 */
  proc_remove(proc_file);
}

/** 이 모듈이 활성화될 때(insmod) 실행 */
module_init(simple_init);
/** 이 모듈이 비활성화될 때(rmmod) 실행 */
module_exit(simple_exit);

MODULE_DESCRIPTION("File System Inspector");
MODULE_AUTHOR("Suho Lee");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0.0");
