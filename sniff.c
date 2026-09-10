#include "sniff.h"
#include "find_packet.h"
#include "queue.h"

#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>


const int PORT = 5733; // Port to sniff on,

// Main sniffing loop
void sniff(int flag, int verbose) {

  int socket_descriptor = socket(AF_INET, SOCK_STREAM, 0);
  if (socket_descriptor < 0) {
    perror("socket"); // Error creating raw socket
    exit(EXIT_FAILURE);
  }
  
  int opt = 1;
  int setsockopt_result = setsockopt(socket_descriptor, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
  if (setsockopt_result < 0) {
    perror("setsockopt"); // Another check
    exit(EXIT_FAILURE);
  }

  // sockaddr_in chosen for TCP
  struct sockaddr_in servaddr;
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(PORT);
  servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
  socklen_t addrlen = sizeof(servaddr);

  int bind_result = bind(socket_descriptor, (struct sockaddr *)&servaddr, sizeof(servaddr)); // Casting is good practice
  if (bind_result < 0) {
    perror("bind"); // Error binding
    exit(EXIT_FAILURE);
  }

  int listen_result = listen(socket_descriptor, 5);
  if (listen_result < 0) {
    perror("listen"); // More checks
    exit(EXIT_FAILURE);
  }

  // Creates a dedicated peer socket for the client connection
  int client_sock = accept(socket_descriptor, (struct sockaddr *)&servaddr, &addrlen);
  if (client_sock < 0) {
    perror("accept");
    exit(EXIT_FAILURE);
  }

  Queue *queue = create_queue(100);

  struct Task task;

  task.offset = 0;
  task.length = 0;
  
  unsigned char buffer[65536]; // Buffer to hold incoming packets
  unsigned char packet_buffer[8192]; // Buffer to hold individual packets
  ssize_t bytes_read;
  int buffer_index = 0;
  int sum_filtered = 0;

  struct args_find_packet args = {
    .buffer = buffer,
    .bytes_read = 0,
    .flag = flag,
    .queue = queue,
  };

  pthread_t thread;
  pthread_create(&thread, NULL, find_packet_thread, &args);

  while ((bytes_read = recv(client_sock, packet_buffer, sizeof(packet_buffer), 0)) > 0) {
    
    task.offset = buffer_index;
    task.length = bytes_read;
    enqueue(queue, task);

    dump(packet_buffer, bytes_read, verbose);
    buffer_index += bytes_read; // Type conversion should be safe for this task
  }

  if (bytes_read < 0) {
    perror("Error reading from socket");
  }

  // Cleanup
  close(socket_descriptor);
  close(client_sock);
  printf("\nTotal packets filtered: %d\n", sum_filtered);
  printf("\nCapture stopped\n");
}

// Utility/Debugging method for dumping raw packet data
void dump(unsigned char *data, int length, int dumpvb) {
  static unsigned long pcount = 0;
  
  printf("\n=== PACKET %lu (%d bytes) ===\n", pcount++, length);
  
  if (dumpvb){
    for (int i = 0; i < length; i++) {
      printf("%02x ", data[i]);
      if ((i + 1) % 16 == 0) printf("\n");
    }
  }

  printf("\n");
}