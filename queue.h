#ifndef CS241_QUEUE_H
#define CS241_QUEUE_H

#include <pcap.h>
#include <pthread.h>

typedef struct Task {
    int offset;
    int length;
} Task;

typedef struct Queue {
    Task *tasks;
    int front, rear, size, capacity;
    pthread_mutex_t lock;
    pthread_cond_t cond;
} Queue;

// Function prototypes
Queue *create_queue(int capacity);
void enqueue(Queue *queue, Task task);
Task dequeue(Queue *queue);
void free_queue_q(Queue *queue);

// temp
void print_queue(Queue *queue);


#endif // CS241_QUEUE_H
