# sp2020-assignment

## 소스코드에 대한 설명

### 1. Circular queue 구현사항 (circular_queue.h, circular_queue.c)

1. circular queue에 선언한 실험 데이터를 위한 자료구조 sector_info

실험 데이터는 다음과 같이 정의하였습니다. 실험 데이터가 정상적으로 커널단에서 채워졌는지를 나타내는 is_valid(정상적으로 담긴 데이터라면, 1을 담고 있어야 함을 가정), 디스크 섹터 번호를 나타내는 number, write가 이루어진 디스크의 파일 시스템 이름을 나타내는 fsname, write를 한 process의 pid, write가 이루어진 시점의 시각을 nanosecond 단위로 담고있는 at을 정의하여 실험에서 사용할 데이터를 담고 있습니다.

sector_info 구조체를 담을 수 있는 circular_queue 자료구조를 구조체 형식으로 선언하였습니다. enqueue 함수와 dequeue 함수 또한 선언하였고, 두 함수에는 여러 circular queue에서 enqueue, dequeue할 수 있도록 circular_queue 형식의 변수를 call-by-reference 형식으로 argument를 선언했습니다.

```c
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
```

### 2. 커널 소스코드 수정사항 (linux-4.4_kernel-mod.patch)

> 커널 소스코드 수정사항은 Linux 커널 버전 4.4 레포지토리에서 patch를 통해 적용할 수 있도록 patch 파일을 만들어 두었습니다.
> 커널 소스코드로 cd한 후, `patch -p1 < ./linux-4.4_kernel-mod.patch` 명령어를 실행하여 patch 파일을 적용할 수 있습니다.

커널 소스코드의 변경사항은 다음과 같습니다.

1. block 디렉토리의 Makefile에 circular queue 소스코드를 함께 컴파일하도록 세팅
```c
obj-$(CONFIG_BLOCK) += circular_queue.o
```


2. block/blk-core.c 소스코드 수정사항

blk-core.c 소스코드에는 실험 데이터를 담을 수 있는 circular queue 자료구조를 blk_inspection_queue라는 변수명으로 선언하였습니다. blk_inspection_queue와 dequeue 함수는 LKM에서 참조하여 사용하기 때문에, EXPORT_SYMBOL 함수를 통하여 symbol을 사용할 수 있도록 export 해주었습니다.

```c
// 필요한 헤더 include
#include <linux/time.h>
#include "circular_queue.h"

circular_queue blk_inspection_queue = {
	.front = -1,
	.rear = -1,
};

// blk_inspection_queue를 lkm에서 쓸 수 있도록 symbol export
EXPORT_SYMBOL(blk_inspection_queue);
EXPORT_SYMBOL(dequeue);
```

write가 이루어지는 submit_bio 부분의 수정사항입니다. circular queue에 선언한 자료구조인 sector_info 구조체 변수를 선언하여, 이 구조체 변수에 값을 채워준 후 구조체를 circular queue에 enqueue하는 부분입니다. is_valid는 1로 할당해 주었고, 각각 다음과 같은 방식으로 sector_info에서 요구하는 정보를 채워줍니다.
- pid: task_pid_nr() 함수를 통해 현재 process의 pid를 가져옴
- number: bio 구조체의 bi_iter 멤버를 통해 bvec_iter 구조체를 가져온 후, 이의 bi_sector를 가져옴
- at: ktime_get()을 통해 nanosecond 단위의 ktime_t 변수를 가져온 후, 이를 ktime_to_ns() 함수를 통해 signed 64bit 형식의 정수로 변환

```c
sector_info info;
// 현재 시각 정보를 초 단위로 반환 (tv_sec에 저장)
ktime_t ktime = ktime_get();
// write가 이루어진 device의 file system 이름을 가져오기 위해, bio device의 superblock을 참조
struct super_block* superblock = bio->bi_bdev->bd_super;

info.is_valid = 1;
info.number = (unsigned long long)bio->bi_iter.bi_sector;
info.pid = task_pid_nr(current);
info.at = ktime_to_ns(ktime);
// bd_super가 없는 경우 (null pointer) 에 대한 예외처리
if (superblock != NULL) {
	info.fsname = superblock->s_type->name;
} else {
	info.fsname = "???";
}
enqueue(&blk_inspection_queue, info);
```

### 3. LKM 코드 (lkm_proc_inspection.c)

WIP

## 빌드하기

1. Makefile 내의 KDIR 수정
2. `make` 실행

## 커널 빌드하기

1. 커널 소스에 패치 파일 적용 ([여기](https://twpower.github.io/195-how-to-apply-patch-file) 참고)
2. circular_queue 코드를 (src 폴더 내의) 커널 소스 내에 /block 안에 넣어두기
3. 커널 빌드
```
make bzImage -j4 && make modules -j4
sudo make modules_install -j4 && sudo make install
```
3. 재부팅 후 빌드된 커널로 부팅

## 모듈 올리기

1. insmod 실행
2. proc 파일 읽어보기 (root로 실행)
```
cat /proc/inspectfs
```
