#ifndef PROTOCOLS_H
#define PROTOCOLS_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <netinet/in.h>

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;

/* Ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

#define ETHERTYPE_IP   0x0800  // IPv4
#define ETHERTYPE_ARP  0x0806  // ARP
#define ETHERTYPE_IPV6 0x86DD  // IPv6

/* IPv4 ip_p and IPv6 next-header share the same IANA number space */
const char* protocol_to_string(uint8_t protocol);

#endif
