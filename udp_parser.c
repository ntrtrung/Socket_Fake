#include <string.h>
#include "udp_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>

#define BUFSIZE 4096

/* This fuction identifies if the captured packet is TCP or UDP.
 Fuction will return: Protocol code e.g.  6 for TCP and 17 UDP.*/

int identify_ip_protocol(ipq_packet_msg_t *msg) {
    int protocol=0;  /* 6 = TCP, 16 = UDP */
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* get the protocol identifier from the ip header */
    protocol = iph->protocol;
    
    return(protocol);
    
}

/* Identifies the source interface(e.g. eth0, eth1, etc) that the packet came from */
void identify_incomimg_interface(ipq_packet_msg_t *msg, char *interface) {
    // just copy the interface name!
    strcpy(interface, msg->indev_name);
    
}

/* This function gets src IP from captured packet.
 Returns source IP in inet_addr form */
unsigned int get_src_ip(ipq_packet_msg_t *msg) {
    unsigned int src_ip_addr;
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* get src address from iphdr */
    src_ip_addr = iph->saddr;
    
    return(src_ip_addr);
    
}
int get_udp_sin_port(ipq_packet_msg_t *msg) {
    int sin_port=0;
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* Cast the UDP Header from the raw packet */
    struct udphdr *udp = (struct udphdr *) (msg->payload + (iph->ihl << 2));
    
    /* get the destination port of the packet */
    sin_port = ntohs(udp->source);
    
    return(sin_port);
    
}

/* This function gets dst IP from captured packet.
 Returns destination IP in inet_addr form */
unsigned int get_dst_ip(ipq_packet_msg_t *msg) {
    unsigned int dst_ip_addr;
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* get dst address from iphdr */
    dst_ip_addr = iph->daddr;
    
    return(dst_ip_addr);
    
}

int get_udp_dst_port(ipq_packet_msg_t *msg) {
    int dst_port=0;
    
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
    /* Cast the UDP Header from the raw packet */
    struct udphdr *udp = (struct udphdr *) (msg->payload + (iph->ihl << 2));
    
    /* get the destination port of the packet */
    dst_port = ntohs(udp->dest);
    
    return(dst_port);
    
}

int udp_get_payload_size(ipq_packet_msg_t *msg) {
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);
    
     /* calculate the length of the payload */
     /* length of udp header = 8*/
    int unsigned payload_length = (unsigned int) ntohs(iph->tot_len) - ((iph->ihl << 2) + 8);
    
    return(payload_length);
    
}

void udp_get_payload(ipq_packet_msg_t *msg, char *buffer) {
       
    /* Cast the IP Header from the raw packet */
    struct iphdr *iph = ((struct iphdr *) msg->payload);

     /* calculate the length of the payload */
     /* length of udp header = 8*/
    int unsigned payload_length = (unsigned int) ntohs(iph->tot_len) - ((iph->ihl << 2) + 8);
    
    /* get the payload offset from within the raw packet */
    int unsigned payload_offset = ((iph->ihl << 2) + 8 );
    
    
    if(payload_length) {
        memcpy(buffer, msg->payload + payload_offset, payload_length);
    }
    else{
        	buffer[0]='\0';
	}
}

//change ip address from number to string
char *addr_itoa(unsigned long addr)
{
  static char buff[18];
  char *p;
  
  p = (char *) &addr;
  sprintf(buff, "%d.%d.%d.%d", (*p & 255), (*(p + 1) & 255), (*(p + 2) & 255), (*(p + 3) & 255));
  return buff;
} 

// destroy ipq_handle
void die(struct ipq_handle *h) 
{	
	printf("\n bi die rui\n");
	ipq_perror("passer");
	ipq_destroy_handle(h);
	exit(1) ;
}




