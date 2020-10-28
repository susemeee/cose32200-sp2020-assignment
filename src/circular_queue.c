
#include "circular_queue.h"

int _is_queue_full(circular_queue* queue) {
  if (queue->rear + 1 == queue->front) return 1;
  if (queue->rear == QUEUE_SIZE - 1 && queue->front == 0) return 1;
  return 0;
}

void enqueue(circular_queue* queue, sector_info sector) {
  if (_is_queue_full(queue) != 1) {
    
    if (queue->front == -1) {
      queue->front = 0;
      queue->rear = 0;
    } else if (queue->front != 0 && queue->rear == QUEUE_SIZE - 1) {
      queue->rear = 0;
    } else {
      queue->rear++;
    }

    queue->q[queue->rear] = sector;
  }
}

sector_info dequeue(circular_queue* queue) {
  if (queue->front == -1) {
    printk(KERN_WARNING "Circular queue is empty\n");
    sector_info dummy_info;
    dummy_info.is_valid = 0;
    return dummy_info;
  } else {

    sector_info element = queue->q[queue->front];

    if (queue->front == queue->rear) {
      queue->front = -1;
      queue->rear = -1;
    } else if (queue->front == QUEUE_SIZE - 1) {
      queue->front = 0;
    } else {
      queue->front++;
    }

    return element;
  }
}
