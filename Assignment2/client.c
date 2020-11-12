#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/timeb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <unistd.h>

#define SUCCESS (void*)1
#define READ_BUFFER_SIZE 1024
// 최대 쓰레드(접속 가능한 커넥션)의 갯수
#define MAX_THREADS 10
// server의 IP 주소
#define IP_ADDRESS "127.0.0.1"

int atsign_counting(const char* buf, size_t len) {
  int i;
  int n = 0;
  for (i = 0; i < len; i++) {
    if (buf[i] == '@') n++;
  }
  return n;
}

/** pthread가 실행할 함수 */
void* socket_client_routine(void* data) {

  // data로부터 port 번호를 가져옴
  int port = *(int*)data;
  // socket 생성
  int sock = 0;
  struct sockaddr_in serv_addr;
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);
  // socket 생성 실패시 예외처리
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("Socket creation error\n");
    return NULL;
  }

  // address가 올바르지 않은 경우 예외처리
  if (inet_pton(AF_INET, IP_ADDRESS, &serv_addr.sin_addr) <= 0) {
    printf("Invalid address\n");
    return NULL;
  }

  // 해당 포트번호로 client가 접속 실패시 예외처리
  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("%d: Connection Failed\n", port);
    return NULL;
  }


  // read()를 수행할 문자열 버퍼
  char buffer[READ_BUFFER_SIZE] = {0};
  // read() 수행 후 읽은만큼을 전달
  int read_count = 0;
  // '@'의 발생 빈도
  int atsign_count = 0;

  // 현재시간 측정을 위한 구조체
  struct timeb timebuffer;
  struct tm *now;
  time_t ltime;
  int milisec;


  FILE *fp;

  // 로그 텍스트파일 제목
  char textT[20] = {};
  sprintf(textT, "%d-%d.txt", port, sock);

  while (1) {
    // read 수행
    read_count = read(sock, buffer, READ_BUFFER_SIZE);
    // '@' 빈도 카운트
    atsign_count += atsign_counting(buffer, read_count);

    // 현재 밀리초 측정
    ftime(&timebuffer);
    ltime = timebuffer.time;
    milisec = timebuffer.millitm;
    now = localtime(&ltime);

    // 과제결과 출력 형식
    fp = fopen(textT,"a");
    fprintf(fp, "%02d:%02d:%02d.%03d|%ld|%s\n", now->tm_hour, now->tm_min, now->tm_sec, milisec, strlen(buffer), buffer);
    fclose(fp);

    // '@'가 5개 이상이면 루프 종료
    if (atsign_count >= 5) {
      break;
    } else {
      atsign_count = 0;
    }
  }

  return 0;
}


int main(int argc, const char* argv[]) {

  // pthread들을 담는 배열 변수
  pthread_t p_threads[MAX_THREADS] = {0,};
  // pthread_join에서 사용하는 변수. 사용되지는 않음.
  int status;

  if (argc < 2) {
    // 포트번호를 입력하지 않았을 경우 예외처리
    printf("[Usage] %s {port1 [port2 ... port10]}\n", argv[0]);
    return 1;
  }

  if (argc > MAX_THREADS + 1) {
    // 포트번호의 갯수가 MAX_THREADS보다 많은 경우 예외처리
    printf("too many port number! must be less than %d\n", MAX_THREADS);
    return 1;
  }

  for (int i = 1; i < argc; i++) {
    // 포트번호 파싱
    int port = atoi(argv[i]);

    // 포트번호가 server 프로그램의 유효 포트번호 범위를 넘은경우 예외처리
    if (port < 1025 || port > 65535) {
      printf("Port number %d must be between 1025, 65535\n", port);
      continue;
    }

    // thread 생성
    int th_id = pthread_create(&p_threads[i - 1], NULL, socket_client_routine, (void *)&port);
    // thread 생성 실패시 예외처리
    if (th_id < 0) {
      perror("thread create error\n");
      return -1;
    }
  }

  // thread가 모두 끝날때까지 대기
  for (int i = 1; i < argc; i++) {
    // 해당 인덱스의 pthread가 없을수도 있어 예외처리
    if (p_threads[i - 1] != 0) {
      pthread_join(p_threads[i - 1], (void **)&status);
    }
  }

  return 0;
}
