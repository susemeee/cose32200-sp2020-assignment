
#ifndef CIRCULAR_QUEUE_H_
#define CIRCULAR_QUEUE_H_

#include <linux/kernel.h>
#include <linux/types.h>

#define QUEUE_SIZE 100

/**
 * sector_info: write 작업을 했을 때의 작업에 대한 정보를 정의하는 구조체
 */
typedef struct {
  /** circular queue가 커널 코드로부터 잘 채워졌는지? 1 혹은 0 */
  int is_valid;
  /** write가 이루어진 sector 번호 */
  unsigned long long number;
  /** write가 이루어진 block device의 file system 이름 */
  const char* fsname;
  /** write를 한 process pid */
  int pid;
  /** write가 이루어진 시각의 timestamp */
  s64 at;
} sector_info;

/**
 * sector_info를 저장하는 circular queue 자료구조 선언
 */
typedef struct {
  sector_info q[QUEUE_SIZE];
  int rear;
  int front;
} circular_queue;

/** circular_queue에 sector_info 구조체를 삽입하는 코드 */
void enqueue(circular_queue* queue, sector_info sector);

/** circular_queue에서 sector_info 구조체를 dequeue하는 코드 */
sector_info dequeue(circular_queue* queue);

#endif

