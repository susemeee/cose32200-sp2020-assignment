#include <stdio.h>
#include "circular_queue.h"


int main() {
  circular_queue queue = {
    .rear = -1,
    .front = -1,
  };

  enqueue_sector(&queue, 1);
  enqueue_sector(&queue, 2);
  enqueue_sector(&queue, 3);
  printf("%d\n", dequeue_sector(&queue));
  enqueue_sector(&queue, 4);
  printf("%d\n", dequeue_sector(&queue));
  printf("%d\n", dequeue_sector(&queue));
  printf("%d\n", dequeue_sector(&queue));

  return 0;
}
