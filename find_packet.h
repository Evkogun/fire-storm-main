#include <stdio.h>
#include <stdlib.h>

struct packet {
  uint16_t sequence_number; // Stored as ints to prevent later conversion
  uint16_t length_data; // SPECIFICALLY NOT INCLUDING THE HEADER
  unsigned char *data;
  int index;

  UT_hash_handle hh; // breaks without it
};
// Defined here so I don't have to call sniff.h

int matches_pattern(const unsigned char *buffer, int i);
struct packet *create_packet(unsigned char *data, uint16_t sequence_number, int index, uint16_t data_length);
int find_packet(unsigned char *buffer, int bytes_read, struct packet **packet_map);

