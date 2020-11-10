#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#include <arpa/inet.h>
#include <unistd.h>

#define READ_BUFFER_SIZE 1024
#define MAX_THREADS 10
#define IP_ADDRESS "127.0.0.1"


typedef struct {
  int port;
  int socket;
} socket_client;


int atsign_counting(const char* buf, size_t len) {
  int i;
  int n = 0;
  for (i = 0; i < len; i++) {
    if (buf[i] == '@') n++;
  }
  return n;
}


void* socket_client_routine(void* data) {

  socket_client* client = (socket_client*)data;
  char buffer[READ_BUFFER_SIZE] = {0};
  int read_count = 0;
  int atsign_count = 0;

  int socket = client->socket;
  int port = client->port;

  while (1) {
    read_count = read(socket, buffer, 1024);
    atsign_count = atsign_counting(buffer, read_count);

    // fprintf(fp, "%02d:%02d:%02d.%03d|%d|%d|%s\n", hour, minute, second, millisec, len, buffer)
    printf("%s (from %d)\n", buffer, port);

    if (atsign_count >= 5) {
      break;
    }
  }
  printf("%s\n",buffer);
  return 0;
}

int main(int argc, const char* argv[]) {

  pthread_t p_threads[MAX_THREADS];
  int status;

  if (argc < 2) {
    printf("[Usage] %s {port1 [port2 ... port10]}\n", argv[0]);
    return 1;
  }

  if (argc > MAX_THREADS + 1) {
    printf("too many port number! must be less than %d\n", MAX_THREADS);
    return 1;
  }

  for (int i = 1; i < argc; i++) {
    int port = atoi(argv[i]);

    if (port < 1025 || port > 65535) {
      printf("Port number %d must be between 1025, 65535\n", port);
      continue;
    }

    int sock = 0;
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
      printf("Socket creation error\n");
      return -1;
    }

    if (inet_pton(AF_INET, IP_ADDRESS, &serv_addr.sin_addr) <= 0) {
      printf("Invalid address\n");
      return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
      printf("%d: Connection Failed\n", port);
      return -1;
    }

    socket_client client = {
      .port = port,
      .socket = sock,
    };

    int th_id = pthread_create(&p_threads[i - 1], NULL, socket_client_routine, (void *)&client);
    if (th_id < 0)
    {
      perror("thread create error\n");
      return -1;
    }
  }

  for (int i = 1; i < argc; i++) {
    pthread_join(p_threads[i - 1], (void **)&status);
  }

  return 0;
}
