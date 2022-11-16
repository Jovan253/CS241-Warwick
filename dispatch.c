#include "dispatch.h"
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include "analysis.h"
#include "queue.h"
#include <unistd.h>

#define NUMTHREADS 2
struct queue *work_queue; 
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_t tid[NUMTHREADS]; // array to store thread id's

void *thread_code(void *arg) {    
  //struct thread_args *recvln = malloc(sizeof(struct thread_args));
  //long long limit;
  
  //long tid = (long)arg;
  //printf("Thread ID: %ld", tid);
  while (1){
    pthread_mutex_lock(&lock);
		while(isempty(work_queue)){  
			pthread_cond_wait(&cond,&lock);
		}
    struct thread_args *thread = malloc(sizeof(struct thread_args));
		thread = work_queue->head->item;
		dequeue(work_queue);
		pthread_mutex_unlock(&lock);    
    analyse(thread->header, thread->packet, thread->verbose);
   
    //free(threads);
  }  

  return NULL;
}

void dispatch(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
  struct thread_args *new_threads = malloc(sizeof(struct thread_args));
  new_threads->header = header;
  new_threads->packet = packet;
  new_threads->verbose = verbose;    
  //int tworking; 
  
  work_queue = create_queue();

  for(int i=0;i<NUMTHREADS;i++){
		if (pthread_create(&tid[i],NULL,&thread_code,(void *) NULL) != 0){
      printf("Failed to create thread");
    }
	}

  
  pthread_mutex_lock(&lock);
  enqueue(work_queue,new_threads);
  pthread_cond_broadcast(&cond);
  pthread_mutex_unlock(&lock); 

  for (int i =0; i < NUMTHREADS; i++){
    pthread_join(tid[i], NULL);
  }

  //pthread_mutex_destroy(&lock);
  //pthread_cond_destroy(&cond);
  //destroy_queue(work_queue);
}

// void joinThreads(){
//   pthread_mutex_lock(&lock);
//   pthread_cond_broadcast(&cond);
//   pthread_mutex_unlock(&lock);
//   pthread_mutex_destroy(&lock);
//   pthread_cond_destroy(&cond);  
//   for(int i=0;i<NUMTHREADS;i++){
//     pthread_join(tid[i],NULL);
//   }
// }
