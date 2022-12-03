#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
/* ethernet headers always 14 bytes*/
#define SIZE_ETHERNET 14
pthread_mutex_t synLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t blacklistLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t arpLock = PTHREAD_MUTEX_INITIALIZER;


int synCounter = 0;
int arpCounter = 0;
int blacklistViolations = 0;
int googleViolations = 0;
int facebookViolations = 0;

int count = 0;
int *arr = NULL;
int numDistinct = 0;

// Detecting Syn Flood Attacks
void synFloodAttack(const struct iphdr *ip_head, const struct tcphdr *tcp_head){
  // Filter by SYN packets set
  if (tcp_head->syn == 1 && tcp_head->ack==0){ 
    pthread_mutex_lock(&synLock);
    synCounter++;    
    count++;
    // Add the address of the ip to an array
    arr = (int *) realloc(arr, count*sizeof(int));    
    arr[count-1] = ip_head->saddr;
    pthread_mutex_unlock(&synLock);
  }
}

// Detecting blacklisted URLs
void blacklistedURLs(const struct tcphdr *tcp_head, const char *payload, const struct iphdr *ip_head){
  // Checking that it comes in on port 80
  if (ntohs(tcp_head->dest) == 80){    
    // if the payload is google address display appropriate messages
    if (strstr(payload, "Host: www.google.co.uk")){      
      pthread_mutex_lock(&blacklistLock);
      printf("\n========================");
      printf("\nBlacklisted URL violation detected");
      // Obtain Source IP Address
      struct in_addr ipaddr;
      ipaddr.s_addr = ip_head->saddr;      
      printf("\nSource IP address: %s", inet_ntoa(ipaddr));      
      // Obtain Destination IP address
      ipaddr.s_addr = ip_head->daddr;
      printf("\nDestination IP address: %s", inet_ntoa(ipaddr));
      printf("\n========================\n");
      blacklistViolations++;
      googleViolations++;      
      pthread_mutex_unlock(&blacklistLock);
    }
    // if the payload is facebook address display appropriate messages
    else if (strstr(payload, "Host: www.facebook.com"))
    {      
      pthread_mutex_lock(&blacklistLock);
      printf("\n========================");
      printf("\nBlacklisted URL violation detected");
      // Obtain Source IP Address
      struct in_addr ipaddr;
      ipaddr.s_addr = ip_head->saddr;      
      printf("\nSource IP address: %s", inet_ntoa(ipaddr));
      // Obtain Destination IP address
      ipaddr.s_addr = ip_head->daddr;
      printf("\nDestination IP address: %s", inet_ntoa(ipaddr));
      printf("\n========================\n");
      blacklistViolations++;
      facebookViolations++;
      pthread_mutex_unlock(&blacklistLock);
    }    
  }
}

// Display the malicious attacks 
void detectionReport(){
    // Find the number of distinct number of ip address in the SYN attack  
    int j;
    for (int i = 0; i < count; i++){
      for (j = 0; j < i; j++){
        if (arr[i] == arr[j]){
          break; // Duplicate found        
        }
      }
      if (i == j){
        numDistinct++; // Increment disctinct number
      }
    }  
    // Free the array
    free(arr);        

    // Print the attacks
    printf("\nIntrusion Detection Report: ");
    printf("\n%d SYN packets detected from %d different IPs (syn attack)", synCounter, numDistinct);
    printf("\n%d ARP responses (cache poisoning)", arpCounter);
    printf("\n%d URL Blacklist violations (%d google and %d facebook)\n", blacklistViolations, googleViolations, facebookViolations);  
    pthread_mutex_destroy(&arpLock);
    pthread_mutex_destroy(&synLock);
    pthread_mutex_destroy(&blacklistLock);       
    exit(0); // stops infinte run of program   
}

void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {  

  const struct ether_header *ethernet = (struct ether_header*)(packet); /* The ethernet header with pointer set to start of packet */
  const struct iphdr *ip = (struct iphdr*)(packet + ETH_HLEN); /* The IP header */
  u_int size_ip = (ip->ihl*4); // IP_HL function to get the size of all ip
  const struct tcphdr *tcp = (struct tcphdr*)(packet + ETH_HLEN + size_ip); /* The TCP header */  
  const char *payload;
  /* 4 times the data offset*/
  u_int size_tcp = (tcp->doff*4);  
  payload = (char*)(packet + ETH_HLEN + size_ip + size_tcp);

  // If packet type is IP
  if (ntohs(ethernet->ether_type) == ETHERTYPE_IP){
    // Check for SYN Flood Attacks and Blacklisted URLs
    synFloodAttack(ip, tcp);
    blacklistedURLs(tcp, payload, ip);
    // free(tcp);
    // free(ethernet);
    // free(ip);    
  }
  // If packet type is ARP 
  else if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP){
    // Construct arp packet
    const struct ether_arp *arp = (struct ether_arp *)(ip);   
    // Test for ARP poisoning attack
    if (ntohs(arp->arp_op) == ARPOP_REPLY){
      pthread_mutex_lock(&arpLock);
      arpCounter++;      
      pthread_mutex_unlock(&arpLock);
    }        
  }   
}
