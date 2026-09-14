#include "find_packet.h"
#include "queue.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int matches_pattern(const unsigned char *buffer, size_t i) {
    static const unsigned char pattern[] = "CTFS"; // CTFS, also prevents re-creation

    for (int j = 0; j < 4; j++) {
        if (buffer[i + j] != pattern[j])
            return 0;
    }
    return 1;
}

// Creates a new packet structure
struct Task *create_task(uint16_t sequence_int, size_t buffer_index, size_t length) {
    struct Task *new_task = malloc(sizeof(Task));

    if (!new_task) {
        perror("Failed to allocate memory for new packet");
        exit(EXIT_FAILURE);
    }

    new_task->sequence_number = sequence_int;
    new_task->offset = buffer_index;
    new_task->length = length;
    
    return new_task;
}


// wrapper made to satify pthread_create's function signature
void *find_packet_thread(void *arg) {
    struct args_find_packet *args = arg;
    int sum_filtered = find_packet(args->buffer, args->r_queue, args->n_op_queue, args->op_queue);
    printf("\nTotal packets filtered: %d\n", sum_filtered);
    return NULL;
}


int find_packet(unsigned char *buffer, Queue *r_queue, Queue *n_op_queue, Queue *op_queue) {
    // This function will change, currently it filters out CTFS packets
    static size_t buffer_spill_offset = 0;

    Task *task = dequeue(r_queue);
    int sum_detected = 0;
    size_t start = task->offset - buffer_spill_offset; // Seperated to keep for from being too long
    size_t end = task->offset + task->length; // Allows consideration of buffer_spill_offset in out of bounds calculation

    buffer_spill_offset = 0;
    
    for (size_t i = start; i < end; i++) { // Prevent out-of-bounds access
        if (buffer[i] == 0x43) {

            if (i + 16 > end){ // If header is split across 2 packets
                buffer_spill_offset = end - i;
                break;
            }

            if (!matches_pattern(buffer, i)){
                continue;
            }

            // Converts two raw bytes into single 16 bit integer
            uint16_t sequence_number = ((uint16_t)buffer[i + 4] << 8) | buffer[i + 5]; // Love low level languages, 
            size_t data_length = ((size_t)buffer[i + 6] << 8) | buffer[i + 7]; // Declared here since it is used in skip logic

            if (i + 16 + data_length > end){ // If data is split across 2 packets
                buffer_spill_offset = end - i;
                break;
            }
            
            struct Task *new_task = create_task(sequence_number, i, data_length);
            enqueue(op_queue, new_task);

            sum_detected++;
            i += data_length + 15; // header size + data
        }
        else if (buffer[i] == 0x08 && i >= 12){ // Protection for fetching headers

            if (i + 6 > end){ // If header length field split or in next packet
                buffer_spill_offset = end - i;
                break;
            }

            if (buffer[i + 1] != 0x00 || buffer[i + 2] != 0x45){
                continue;
            }

            size_t data_length = ((uint16_t)buffer[i + 4] << 8) | (uint16_t)buffer[i + 5];
    
            if (i + 2 + data_length > end){ // If header length field split or in next packet
                buffer_spill_offset = end - i;
                break;
            }

            struct Task *new_task = create_task(0, i - 12, data_length + 14); // 14 for the header
            enqueue(n_op_queue, new_task);
            i += data_length + 1; // Iteration through data
        }
    }
    free(task);
    return sum_detected;
}


/*
NOTES

Would probably be easier not to print detected packets instead of altering dump

Filter could instead return the positions, sizes and types of certain packets.



*/