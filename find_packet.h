#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "queue.h"

struct args_find_packet {
  unsigned char *buffer;
  int flag;
  Queue *r_queue;
  Queue *n_op_queue;
  Queue *op_queue;
};

void *find_packet_thread(void *arg);
int matches_pattern(const unsigned char *buffer, size_t i);
struct Task *create_task(uint16_t sequence_int, size_t buffer_index, size_t data_length);
int find_packet(unsigned char *buffer, Queue *r_queue, Queue *n_op_queue, Queue *op_queue);

