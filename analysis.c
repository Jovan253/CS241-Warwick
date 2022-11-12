#include "analysis.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
/* ethernet headers always 14 bytes*/
#define SIZE_ETHERNET 14

int synCounter = 0;
int arpCounter = 0;
int blacklistViolations = 0;
int googleViolations = 0;
int facebookViolations = 0;

int count = 0;
int *arr = NULL;
int numDistinct = 0;

void synFloodAttack(const struct iphdr *ip_head, const struct tcphdr *tcp_head){
  if (tcp_head->syn == 1){ /* filter by SYN packets set*/
    synCounter++;    
    count++;
    arr = (int *) realloc(arr, count*sizeof(int));    
    arr[count-1] = ip_head->saddr;
  }
}

void arpPoison(const struct ether_arp *arp){  
  arpCounter++;  
}

void blacklistedURLs(const struct tcphdr *tcp_head, const char *payload){
  if (ntohs(tcp_head->dest) == 80){
    // printf("\nBlacklisted URL violation detected");
    // printf("\nSource IP address: %d", tcp_head->src);
    if (strstr(payload, "Host: www.google.co.uk")){      
      blacklistViolations++;
      googleViolations++;      
    }
    else if (strstr(payload, "Host: www.facebook.com"))
    {      
      blacklistViolations++;
      facebookViolations++;
    }
    
  }
}


void detectionReport(int signo){
  if (signo == SIGINT){    
    int j;
    for (int i = 0; i < count; i++){
      for (j = 0; j < i; j++){
        if (arr[i] == arr[j]){
          break; // duplicate found        
        }
      }
      if (i == j){
        numDistinct++; // increment disctinct
      }
    }

    printf("\nIntrusion Detection Report: ");
    printf("\n%d SYN packets detected from %d different IPs (syn attack)", synCounter, numDistinct);
    printf("\n%d ARP responses (cache poisoning)", arpCounter);
    printf("\n%d URL Blacklist violations (%d google and %d facebook)\n", blacklistViolations, googleViolations, facebookViolations);  
    exit(0);  
  }


}

void analyse(struct pcap_pkthdr *header, const unsigned char *packet, int verbose) {
  signal(SIGINT, detectionReport);

  const struct ether_header *ethernet = (struct ether_header*)(packet); /* The ethernet header with pointer set to start of packet */
  const struct iphdr *ip = (struct iphdr*)(packet + ETH_HLEN); /* The IP header */
  u_int size_ip = (ip->ihl*4); // IP_HL function to get the size of all ip
  const struct tcphdr *tcp = (struct tcphdr*)(packet + ETH_HLEN + size_ip); /* The TCP header */  
  const char *payload;
  /* 4 times the data offset*/
  u_int size_tcp = (tcp->doff*4);  
  payload = (char*)(packet + ETH_HLEN + size_ip + size_tcp);

  if (ntohs(ethernet->ether_type) == ETHERTYPE_IP){
    synFloodAttack(ip, tcp);
    blacklistedURLs(tcp, payload);
  }
  else if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP){
    const struct ether_arp *arp = (struct ether_arp *)(ip);
    arpPoison(arp);
  }        
}
