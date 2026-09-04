#ifndef UDP_H
#define UDP_H

#include "../Service/protocols.h"
#include "../Service/error.h"

#define SIZE_UDP 8

/* UDP header */
typedef struct  {
	uint16_t uh_sport;	/* source port */
	uint16_t uh_dport;	/* destination port */
	uint16_t uh_ulen;	/* datagram length, header included */
	uint16_t uh_sum;	/* checksum */
}sniff_udp;

void parse_udp(sniff_udp** udpHeader,const u_char* packet,u_int offset);

#endif
