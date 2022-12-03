#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <signal.h>

#include "dispatch.h"

pcap_t *pcap_handle;
int verbose;

// Application main sniffing loop
void sniff(char *interface, int verbose) {
  verbose = verbose;
  char errbuf[PCAP_ERRBUF_SIZE];

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);

  // Call the signalDetecor method, if not possible return error message
  if (signal(SIGINT, signalDetector) == SIG_ERR){
    printf("\nCan't catch SIGINT\n");
		exit(0);
	}

  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }  
   
  // first we initialise the threads
  createThreads();
  // Then call the efficient method pcap_loop to capture the packets
  pcap_loop(pcap_handle, -1, callback, (u_char *) &verbose);  

}

// Deals with every new packet recieved
void callback(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet){  
  int verbose = (int) *args;
  // if in verbose call dump
  if (verbose){
    dump(packet, header->len);
  }    
  // Dispatch packet for processing
  dispatch((struct pcap_pkthdr *)header, packet, verbose);    
}

// Used to join threads and return a report for any errors found once ^C is inputted
void signalDetector(int sig){  
  if (sig == SIGINT){
    // Stop sniffing for packets
    pcap_breakloop(pcap_handle);   
    // if in verbose join the threads    
    printf("JOIN EM");
    joinThreads();
    if (verbose){
      printf("CLOSSE");
    }
    // if pcap_handle has been declared, close it
    detectionReport(); 
    if (pcap_handle){
      pcap_close(pcap_handle); 
    } 
    // Call the detection report - errors detected report
    //detectionReport(); 
    // Destroy queue and all packets in it  
    destroyQueue();  
    //Close the process
    exit(0);
  }
  
}

// Utility/Debugging method for dumping raw packet data
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  // Decode Packet Header
  struct ether_header *eth_header = (struct ether_header *) data;
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nType: %hu\n", eth_header->ether_type);
  printf(" === PACKET %ld DATA == \n", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN;
  const unsigned char *payload = data + ETH_HLEN;
  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}
