
#ifndef CIRCULAR_QUEUE_H_
#define CIRCULAR_QUEUE_H_

#include <linux/kernel.h>
#include <linux/types.h>

#define QUEUE_SIZE 100

typedef struct {
  int is_valid;
  unsigned long long number;
  const char* fsname;
  int pid;
  int at;
} sector_info;

typedef struct {
  sector_info q[QUEUE_SIZE];
  int rear;
  int front;
} circular_queue;


void enqueue(circular_queue* queue, sector_info sector);

sector_info dequeue(circular_queue* queue);

#endif

