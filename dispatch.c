#include "dispatch.h"
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include "analysis.h"
#include "queue.h"
#include <unistd.h>

// Number of threads specified by the specification
#define NUMTHREADS 2
// create the worker queue for requests
struct queue *work_queue;
//  Create mutex lock and condition
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
// array to store thread id's
pthread_t tid[NUMTHREADS]; 
int run = 0;
int exists = 0;

void dispatch(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
  // Construct a new packet
  struct thread_args *new_threads = malloc(sizeof(struct thread_args));
  new_threads->header = header;
  new_threads->packet = packet;
  new_threads->verbose = verbose;    
    
  pthread_mutex_lock(&lock);
  // Enqueue the new packet
  enqueue(work_queue,new_threads);  
  pthread_cond_broadcast(&cond);
  pthread_mutex_unlock(&lock);   
}

// Function to be executed by each worker thread
void *thread_code(void *arg) { 
  // Continue checking if work to be done   
  while (run == 1){
    // acquire lock, get connection socket descriptor from work queue, release lock
		// wait if work queue is empty
    pthread_mutex_lock(&lock);
		while(isempty(work_queue) && run == 1){  // want to exit if joining threads
			pthread_cond_wait(&cond,&lock);
		} 
    if (run == 1){
      // Initialise thread
      struct thread_args *thread = NULL;//malloc(sizeof(struct thread_args));
      // Set it to the head value of the worker queue
      thread = work_queue->head->item;
      // Dequeue this item from the queue
      dequeue(work_queue);
      pthread_mutex_unlock(&lock);    
      // Send this item to the analyse method
      analyse(thread->header, thread->packet, thread->verbose);  
      // Free the thread
      free(thread);
    }   
    else{
      pthread_mutex_unlock(&lock);
    }
    
  }    
  
  return NULL;
}

// Creates the threads and work queue
void createThreads(){
  // Set run to 1, to start the work queue loop  
  run = 1;  
  work_queue = create_queue();
  int i;
  for(i=0;i<NUMTHREADS;i++){
		if (pthread_create(&tid[i],NULL,&thread_code,(void *) NULL) != 0){
      printf("Failed to create thread");
    } 
	}
}

// Joins the threads
void joinThreads(){    
  // Stop the work queue loop
  run = 0;  
  // Send signal to wake up all waiting threads
  pthread_cond_broadcast(&cond);
  int i;
  // Join threads    
  if (run == 0){
    for(i=0;i<NUMTHREADS;i++){        
      pthread_join(tid[i],NULL);    
    }            
  }    
}

// Stop the possible memory leaks
void destroyQueue(){
  // Done with queue so delete it
  destroy_queue(work_queue);
  // Done with lock and cond so destroy them
  pthread_mutex_destroy(&lock);
  pthread_cond_destroy(&cond);
}
