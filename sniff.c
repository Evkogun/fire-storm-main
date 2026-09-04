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

pcap_t *pcap_handle = NULL;

void handle_sigint(int sig) {
  if (pcap_handle != NULL) {
    pcap_breakloop(pcap_handle);
  }
}


// Method for receiving shutdown signal from sigint in dispatch
void sub_handle_sigint() {
    if (pcap_handle != NULL) {
        pcap_breakloop(pcap_handle);  // Interrupt pcap_loop
    }
}

// Function that is called in the pcap loop, based of off original while loop
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *header, const unsigned char *packet) {
  dump(packet, header->len);
}

// Main sniffing loop
void sniff(char *interface, int verbose) {
  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
      fprintf(stderr, "Unable to open interface %s\n", errbuf);
      exit(EXIT_FAILURE);
  } else {
      printf("SUCCESS! Opened %s for capture\n", interface);
  }

  char filter_exp[] = "tcp port 5733";

  struct bpf_program fp;
  pcap_compile(pcap_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN); // Must be filtered before pcap_loop is called
  pcap_setfilter(pcap_handle, &fp);
  pcap_freecode(&fp);

  signal(SIGINT, handle_sigint);

  // Begin capturing packets
  pcap_loop(pcap_handle, 0, packet_handler, NULL);

  // Cleanup for when pcap stops
  pcap_close(pcap_handle);
  printf("\nCapture stopped\n");
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}