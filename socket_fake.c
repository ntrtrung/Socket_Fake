#include "socket_fake.h"
#include <netinet/ip.h>
#include <stdio.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/netfilter.h>
#include <string.h>
#include "udp_parser.h"

int sendto_fake(int source_addr,u_short src_prt,struct sockaddr_in *dst_str,unsigned char *payload,u_short payload_s)
{
    u_char enet_src[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    //u_char enet_src[6]= {0x00,0x0C,0x29,0xCC,0x1F,0x50};
    //u_char enet_dst[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
     u_char enet_dst[6]	= {0x00,0x0C,0X29,0x14,0xF4,0x64}  ;
  // u_char enet_dst[6]={0x00,0x13,0x20,0xDA,0x61,0x1A};
    u_short dst_prt;
    
    int c, build_ip;
    libnet_t *l;
    libnet_ptag_t udp;
    libnet_ptag_t t;
    struct libnet_stats ls;
    char errbuf[LIBNET_ERRBUF_SIZE];
    struct libnet_ether_addr *e;

      //default device = eth1	
    l = libnet_init(LIBNET_LINK,"eth0",errbuf);                                
     if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE);
    }
    //get MAC address of eth1
    e = libnet_get_hwaddr(l);
    memcpy(enet_src,e->ether_addr_octet,6);

    if (e == NULL)
    {
        fprintf(stderr, "Can't get hardware address: %s\n", libnet_geterror(l));
    }

    dst_prt = ntohs(dst_str->sin_port);
     //build udp packet             
    udp = 0;
    build_ip = 1;
   unsigned char * buf=NULL;
   if(payload_s%2==1){
    buf=(unsigned char *)malloc(payload_s*sizeof(unsigned char)+1);
    memset(buf,0,payload_s+1);
    memcpy(buf,payload,payload_s);   
    udp = libnet_build_udp(src_prt,dst_prt,LIBNET_UDP_H + payload_s, 0,buf,payload_s+1,l,udp);
    }
   else         
    udp =libnet_build_udp(src_prt,dst_prt,LIBNET_UDP_H + payload_s ,0,payload,payload_s,l,udp);              
    if (udp == -1)
    {
       fprintf(stderr, "Can't build UDP header (at port %d): %s\n", src_prt, libnet_geterror(l));
                goto bad;
    }
     //build IP header
    if (build_ip)
    {
        build_ip = 0;
        t = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + payload_s,0,242,0,64,IPPROTO_UDP,0,
		             source_addr,dst_str->sin_addr.s_addr,NULL,0,l,0);
	if (t == -1)
 	   {
               fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
               goto bad;
	    }
	
	//build ethernet header
         t = libnet_build_ethernet(enet_dst,enet_src,ETHERTYPE_IP,NULL,0,l,0);
	  if (t == -1)
	  {
	            fprintf(stderr, "Can't build ethernet header: %s\n",
	                    libnet_geterror(l));
	   goto bad;
	  }
	
     }
     //begin send frame 
     c = libnet_write(l); 
     if (c == -1)
     {
         fprintf(stderr, "write error: %s\n", libnet_geterror(l));
      }
    libnet_stats(l, &ls);
    libnet_destroy(l);
    if(buf!=NULL) free(buf);
    return (int)payload_s;
bad:
    libnet_destroy(l);
    return -1;

}
struct ipq_handle *init_ipq_handle()
{
     struct ipq_handle *h;
     h = ipq_create_handle(0, PF_INET); 
     return h;
}
//warning: buffer must have BUFSIZE length to prevent that buffer overflows occur.
int recvfrom_fake(struct ipq_handle *h,struct sockaddr_in *in,char *buffer,char *dst_addr,int dst_prt)
{
	
	unsigned char buf[BUFSIZE];
	int status;
	if(h==NULL)
	{
		die(h);
		return -1;
	}
	if(buffer==NULL)
	{
		return -1;
	}

	do
	{
		
		status = ipq_read(h, buf, BUFSIZE, 0); 
		
		if (status < 0){
			 die(h);
			return -1;
		}
		
		switch (ipq_message_type(buf)) 
		{ 
			
			case IPQM_PACKET: 
			{
			
				ipq_packet_msg_t *m = ipq_get_packet(buf);
				struct iphdr *iph = (struct iphdr *) m->payload;
				struct udphdr *udp = (struct udphdr *) (m->payload + (iph->ihl << 2));
				unsigned int src_ip_addr;
       			 	src_ip_addr = iph->saddr;
				unsigned int dst_ip_addr;
				dst_ip_addr = iph->daddr;
				int addr_pub= inet_addr(dst_addr);
				int port = ntohs(udp->dest);
				if(dst_ip_addr==addr_pub && port==dst_prt)
				{	
					in->sin_family=AF_INET;
					in->sin_port=udp->source;
					in->sin_addr.s_addr=iph->saddr;
					int data_size=(unsigned int) ntohs(iph->tot_len) - ((iph->ihl << 2) + 8);
					if(data_size>0){
						udp_get_payload(m,buffer);
					}
										
					buffer[data_size]='\0';
			               	status = ipq_set_verdict(h, m->packet_id,NF_DROP,0,NULL);
					 if (status < 0){
	                                        die(h);
						return -1;
					}
					return  data_size;

				}
				else{
					status = ipq_set_verdict(h, m->packet_id,NF_ACCEPT,0,NULL);
					if (status < 0){
	                                        die(h);
						return -1;
					}
				}

				 break;
			
			}
			case NLMSG_ERROR:
				fprintf(stderr, "Received error message %d0", ipq_get_msgerr(buf)); break;
			default:
				fprintf(stderr, "Unknown message type!0");
			 	break;
		}
	} while (1);
	return -1;
}
