#ifndef ETHERNET_H
#define ETHERNET_H

#include "../Service/protocols.h"
#include "../Service/error.h"

/* Ethernet header */

typedef struct  {
	uint8_t ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	uint8_t ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	uint16_t ether_type; /* IP? ARP? RARP? etc */
}sniff_ethernet;




uint16_t parse_ethernet(sniff_ethernet** etherFrame,const u_char* packet);

sniffer_error_t mac_to_string(const uint8_t* mac, char* buffer,size_t size);

sniffer_error_t type_to_sting(uint16_t type,char* buffer,size_t size);











#endif