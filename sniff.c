#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>

#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>

#include <string.h>
#include <unistd.h>

const int PORT = 5733; // Port to sniff on,

// Main sniffing loop
void sniff(int verbose) {

  int raw_socket = socket(AF_INET, SOCK_STREAM, 0);
  if (raw_socket < 0) {
    perror("socket"); // Error creating raw socket
    exit(EXIT_FAILURE);
  }
  
  int opt = 1;
  int setsockopt_result = setsockopt(raw_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
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

  int bind_result = bind(raw_socket, (struct sockaddr *)&servaddr, sizeof(servaddr)); // Casting is good practice
  if (bind_result < 0) {
    perror("bind"); // Error binding
    exit(EXIT_FAILURE);
  }

  int listen_result = listen(raw_socket, 5);
  if (listen_result < 0) {
    perror("listen"); // More checks
    exit(EXIT_FAILURE);
  }

  // Creates a dedicated peer socket for the client connection
  int client_sock = accept(raw_socket, (struct sockaddr *)&servaddr, &addrlen);
  if (client_sock < 0) {
    perror("accept");
    exit(EXIT_FAILURE);
  }
  
  unsigned char buffer[65536]; // Buffer to hold incoming packets
  ssize_t bytes_read;

  while ((bytes_read = recv(client_sock, buffer, sizeof(buffer), 0)) > 0) {
    dump(buffer, bytes_read, verbose);
  }

  // Cleanup
  close(raw_socket);
  close(client_sock);
  printf("\nCapture stopped\n");
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length, int dumpvb) {
  static unsigned long pcount = 0;
  if (dumpvb){
    printf("\n=== PACKET %lu (%d bytes) ===\n", pcount++, length);
  }
  
  for (int i = 0; i < length; i++) {
    printf("%02x ", data[i]);
    if ((i + 1) % 16 == 0) printf("\n");
  }
  printf("\n");
}