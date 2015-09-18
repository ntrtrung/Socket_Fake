#ifndef __SOCKET_FAKE_H_
#define __SOCKET_FAKE_H_

#include <libnet.h>
#include "udp_parser.h"

#define BUFSIZE 2048

extern int sendto_fake(int source_addr,u_short src_prt, struct sockaddr_in *dst_str ,unsigned char *payload, u_short payload_s);
extern struct ipq_handle *init_ipq_handle();
extern int recvfrom_fake(struct ipq_handle *h,struct sockaddr_in *in,char *buffer,char *dst_addr,int dst_prt);

#endif
