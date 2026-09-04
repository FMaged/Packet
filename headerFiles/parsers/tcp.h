#ifndef TCP_H
#define TCP_H

#include "../Service/protocols.h"
#include "../Service/error.h"

/* TCP header */
typedef uint32_t tcp_seq;

typedef struct  {
	uint16_t th_sport;	/* source port */
	uint16_t th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	uint8_t th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	uint8_t th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	uint16_t th_win;		/* window */
	uint16_t th_sum;		/* checksum */
	uint16_t th_urp;		/* urgent pointer */
}sniff_tcp;

/* Longest output is "FIN|SYN|RST|PSH|ACK|URG|ECE|CWR" plus terminator */
#define TCP_FLAGS_STRLEN 32

void parse_tcp(sniff_tcp** tcpHeader,const u_char* packet,u_int offset);

sniffer_error_t tcp_flags_to_string(uint8_t flags,char* buffer,size_t size);

#endif
