#ifndef ICMP_H
#define ICMP_H

#include "../Service/protocols.h"
#include "../Service/error.h"

#define SIZE_ICMP 8

/* ICMP header — the 4 bytes after the checksum vary by type */
typedef struct  {
	uint8_t icmp_type;
	uint8_t icmp_code;
	uint16_t icmp_sum;	/* checksum */
	uint16_t icmp_id;	/* echo identifier */
	uint16_t icmp_seq;	/* echo sequence number */
}sniff_icmp;

void parse_icmp(sniff_icmp** icmpHeader,const u_char* packet,u_int offset);

const char* icmp_type_to_string(uint8_t type);

/* Echo request/reply carry a meaningful id and sequence; other types do not */
int icmp_is_echo(uint8_t type);

#endif
