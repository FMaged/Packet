#ifndef IP6_H
#define IP6_H

#include <arpa/inet.h>  // For inet_ntop()
#include "../Service/protocols.h"
#include "../Service/error.h"

/* IPv6 header is always exactly 40 bytes */
#define SIZE_IP6 40

typedef struct  {
	uint32_t ip6_flow;	/* version << 28 | traffic class << 20 | flow label */
	uint16_t ip6_plen;	/* payload length, header excluded */
	uint8_t ip6_nxt;	/* next header */
	uint8_t ip6_hlim;	/* hop limit */
	uint8_t ip6_src[16];
	uint8_t ip6_dst[16];
}sniff_ip6;

#define IP6_V(ip6)	  ((ntohl((ip6)->ip6_flow) >> 28) & 0x0f)
#define IP6_TC(ip6)	  ((ntohl((ip6)->ip6_flow) >> 20) & 0xff)
#define IP6_FLOW(ip6) (ntohl((ip6)->ip6_flow) & 0xfffff)

/* Returns the next-header value, which shares IPv4's IANA protocol numbers */
uint8_t parse_ip6(sniff_ip6** ip6Header,const u_char* packet);

sniffer_error_t ip6_To_String(char* buffer,const uint8_t* addr,size_t size);

#endif
