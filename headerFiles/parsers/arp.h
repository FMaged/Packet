#ifndef ARP_H
#define ARP_H

#include "../Service/protocols.h"
#include "../Service/error.h"

/* Only Ethernet/IPv4 ARP is decoded, so the address fields are fixed width */
#define SIZE_ARP 28

typedef struct  {
	uint16_t ar_hrd;	/* hardware type */
	uint16_t ar_pro;	/* protocol type */
	uint8_t ar_hln;		/* hardware address length */
	uint8_t ar_pln;		/* protocol address length */
	uint16_t ar_op;		/* opcode */
	uint8_t ar_sha[ETHER_ADDR_LEN];	/* sender hardware address */
	uint8_t ar_spa[4];	/* sender protocol address */
	uint8_t ar_tha[ETHER_ADDR_LEN];	/* target hardware address */
	uint8_t ar_tpa[4];	/* target protocol address */
}sniff_arp;

void parse_arp(sniff_arp** arpHeader,const u_char* packet);

const char* arp_opcode_to_string(uint16_t opcode);

/* True when the header describes Ethernet/IPv4, the only layout this struct matches */
int arp_is_ethernet_ipv4(const sniff_arp* arpHeader);

#endif
