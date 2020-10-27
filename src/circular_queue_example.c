#include <stdio.h>
#include "circular_queue.h"


int main() {
  circular_queue queue = {
    .rear = -1,
    .front = -1,
  };

  enqueue(&queue, 1);
  enqueue(&queue, 2);
  enqueue(&queue, 3);
  printf("%d\n", dequeue(&queue));
  enqueue(&queue, 4);
  printf("%d\n", dequeue(&queue));
  printf("%d\n", dequeue(&queue));
  printf("%d\n", dequeue(&queue));

  return 0;
}
