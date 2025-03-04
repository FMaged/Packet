#ifndef IP_H
#define IP_H

#include <stdio.h>
#include <string.h>

#include <netinet/in.h>
#include "../Service/error.h"

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14


/* IP header */
typedef struct  {
						/*HL must be at least 5 (20 bytes)*/
						/*HL cannot be more than 15.*/
	uint8_t ip_vhl;		/* version << 4 | header length >> 2 */
						/*version must be 4 or 6*/
	u_char ip_tos;		/* type of service */
	uint16_t ip_len;		/* total length */
	uint16_t ip_id;		/* identification */
	uint16_t ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	uint8_t ip_ttl;		/* time to live */
	uint8_t ip_p;		/* protocol */
	uint16_t ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
}sniff_ip;
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)



uint8_t parse_ip (sniff_ip** ipHeader,const u_char* packet);


sniffer_error_t ipV_to_string(uint8_t extractedVersion,char* buffer);

int ip_DF(uint16_t ip_off);
int ip_MF(uint16_t ip_off);
int ip_offset(uint16_t ip_off);

uint16_t calculate_checksum(sniff_ip ipHeader);

#endif