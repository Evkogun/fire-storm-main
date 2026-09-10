#include "find_packet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int matches_pattern(const unsigned char *buffer, int i) {
    static const unsigned char pattern[] = "CTFS"; // CTFS, also prevents re-creation

    for (int j = 0; j < 4; j++) {
        if (buffer[i + j] != pattern[j])
            return 0;
    }
    return 1;
}

// Creates a new packet structure
struct packet *create_packet(unsigned char *data, uint16_t sequence_int, int index, uint16_t data_length) {
    struct packet *new_packet = malloc(sizeof(*new_packet));

    if (!new_packet) {
        perror("Failed to allocate memory for new packet");
        exit(EXIT_FAILURE);
    }

    new_packet->data = malloc(data_length); // Since we don't know how long data
    // will be until we read the lendth, we allocate it here

    new_packet->sequence_number = sequence_int;
    new_packet->length_data = data_length;
    new_packet->index = index;

    if (data_length > 0) {
        if (!new_packet->data) {
            perror("Failed to allocate memory for packet data");
            free(new_packet);
            exit(EXIT_FAILURE);
        }
        memcpy(new_packet->data, &data[index + 16], data_length);
    } 
    
    return new_packet;
}


// wrapper made to satify pthread_create's function signature
void *find_packet_thread(void *arg) {
    struct args_find_packet *args = (struct args_find_packet *)arg;
    int sum_filtered = find_packet(args->buffer, args->bytes_read, args->queue);
    printf("\nTotal packets filtered: %d\n", sum_filtered);
    return NULL;
}


int find_packet(unsigned char *buffer, int bytes_read, Queue *queue) {
    // This function will change, currently it filters out CTFS packets
    Task old_task;
    if (task != NULL) {
        old_task = *task;
    } else {
        old_task.offset = 0;
        old_task.length = bytes_read;
    }
    Task task = dequeue(queue);
    int sum_detected = 0;
    
    for (int i = task.offset; i <= task.offset + task.length - 1; i += 1) { // Prevent out-of-bounds access
        if (buffer[i] == 0x43 && matches_pattern(buffer, i)) {

            if (i + 16 > bytes_read){ // Header exists?
                break;
            }
            // Converts two raw bytes into single 16 bit integer
            uint16_t key = ((uint16_t)buffer[i + 4] << 8) | buffer[i + 5]; // Love low level languages, 
            uint16_t data_length = ((uint16_t)buffer[i + 6] << 8) | buffer[i + 7]; // Declared here since it is used in skip logic

            if (i + 16 + data_length > bytes_read){
                break;
            }
            
            struct packet *new_packet = create_packet(buffer, key, i, data_length);

            sum_detected++;
            i += data_length + 15; // header size + data
        }
    }
    return sum_detected;
}


/*
NOTES

Would probably be easier not to print detected packets instead of altering dump

Filter could instead return the positions, sizes and types of certain packets.



*/