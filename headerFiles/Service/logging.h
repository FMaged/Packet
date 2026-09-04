#ifndef LOGGING_H
#define LOGGING_H

#include "protocols.h"
#include "../parsers/ethernet.h"
#include "../parsers/ip.h"
#include "../parsers/ip6.h"
#include "../parsers/arp.h"
#include "../parsers/tcp.h"
#include "../parsers/udp.h"
#include "../parsers/icmp.h"

void print_ethernet(const sniff_ethernet* etherFrame);

void print_ip(const sniff_ip* ipHeader);

void print_ip6(const sniff_ip6* ip6Header);

void print_arp(const sniff_arp* arpHeader);

void print_tcp(const sniff_tcp* tcpHeader);

void print_udp(const sniff_udp* udpHeader);

void print_icmp(const sniff_icmp* icmpHeader);

void print_separator(void);

#endif
