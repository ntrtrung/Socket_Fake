#ifndef _UDP_PARSER_H_
#define _UDP_PARSER_H_

#include "libipq.h"

extern int identify_ip_protocol(ipq_packet_msg_t *msg);
extern void identify_incomimg_interface(ipq_packet_msg_t *msg, char *interface);
extern unsigned int get_src_ip(ipq_packet_msg_t *msg);
extern unsigned int get_dst_ip(ipq_packet_msg_t *msg);
extern int get_udp_dst_port(ipq_packet_msg_t *msg);
extern int udp_get_payload_size(ipq_packet_msg_t *msg);
extern void udp_get_payload(ipq_packet_msg_t *msg, char *buffer);
extern int get_udp_sin_port(ipq_packet_msg_t *msg);

extern void change_dest_port(ipq_packet_msg_t *m,unsigned short port);
extern void change_source_port(ipq_packet_msg_t *m,unsigned short port);
extern void change_dest_addr(ipq_packet_msg_t *m,int c_addr);
extern void change_source_addr(ipq_packet_msg_t *m ,int c_addr);
extern void die(struct ipq_handle *h);
extern unsigned short chksum_udphdr(ipq_packet_msg_t *msg);
extern char *addr_itoa(unsigned long addr);
extern unsigned short chksum_iphdr1(unsigned short *addr, int len);
extern unsigned short chksum_iphdr(unsigned short *addr, int size);

#endif
