
#ifndef CIRCULAR_QUEUE_H_
#define CIRCULAR_QUEUE_H_

#include <linux/kernel.h>
#include <linux/types.h>

#define QUEUE_SIZE 100

#ifndef sector_t
#define sector_t int
#endif

#ifndef printk
#define printk printf
#define KERN_WARNING
#endif

typedef struct {
  sector_t q[QUEUE_SIZE];
  int rear;
  int front;
} circular_queue;


int _is_queue_full(circular_queue* queue);

void enqueue_sector(circular_queue* queue, sector_t sector);

sector_t dequeue_sector(circular_queue* queue);

#endif

