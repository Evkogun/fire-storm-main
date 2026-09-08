#include "queue.h"
#include <stdlib.h>

// Create a queue
Queue *create_queue(int capacity) {
    Queue *queue = (Queue *)malloc(sizeof(Queue));
    queue->tasks = (Task *)malloc(sizeof(Task) * capacity);
    queue->front = queue->rear = queue->size = 0;
    queue->capacity = capacity;
    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->cond, NULL);
    return queue;
}

// Add a task to the queue
void enqueue(Queue *queue, Task task) {
    pthread_mutex_lock(&queue->lock);

    while (queue->size == queue->capacity) {
        pthread_cond_wait(&queue->cond, &queue->lock);
    }

    queue->tasks[queue->rear] = task;
    queue->rear = (queue->rear + 1) % queue->capacity;
    queue->size++;

    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->lock);
}

// Remove a task from the queue
Task dequeue(Queue *queue) {
    pthread_mutex_lock(&queue->lock);

    while (queue->size == 0) {
        pthread_cond_wait(&queue->cond, &queue->lock);
    }

    Task task = queue->tasks[queue->front];
    queue->front = (queue->front + 1) % queue->capacity;
    queue->size--;

    pthread_cond_signal(&queue->cond);
    pthread_mutex_unlock(&queue->lock);

    return task;
}

// Free the queue and its resources
void free_queue_q(Queue *queue) {
    if (queue != NULL) {
        free(queue->tasks);

        pthread_mutex_destroy(&queue->lock);
        pthread_cond_destroy(&queue->cond);

        free(queue);
    }
}
