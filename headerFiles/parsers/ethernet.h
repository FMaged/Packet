#ifndef ETHERNET_H
#define ETHERNET_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>

#include "../Service/error.h"

typedef unsigned char u_char;



#define ETHERTYPE_IP  0x0800  // IPv4
#define ETHERTYPE_ARP 0x0806  // ARP
#define ETHERTYPE_IPV6 0x86DD // IPv6

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */

typedef struct  {
	uint8_t ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	uint8_t ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	uint16_t ether_type; /* IP? ARP? RARP? etc */
}sniff_ethernet;




uint16_t parse_ethernet(sniff_ethernet** etherFrame,const u_char* packet);

sniffer_error_t mac_to_string(uint8_t* mac, char* buffer,size_t size);

sniffer_error_t type_to_sting(uint16_t type,char* buffer,size_t size);











#endif