#include "../../headerFiles/parsers/arp.h"

#define ARP_HRD_ETHERNET 1


void parse_arp(sniff_arp** arpHeader,const u_char* packet){
	*arpHeader=(sniff_arp*)(packet+SIZE_ETHERNET);
}


const char* arp_opcode_to_string(uint16_t opcode){
	switch (ntohs(opcode)) {
		case 1: return "Request";
		case 2: return "Reply";
		case 3: return "RARP Request";
		case 4: return "RARP Reply";
		default: return "Unknown";
	}
}


int arp_is_ethernet_ipv4(const sniff_arp* arpHeader){
	return ntohs(arpHeader->ar_hrd)==ARP_HRD_ETHERNET
	    && ntohs(arpHeader->ar_pro)==ETHERTYPE_IP
	    && arpHeader->ar_hln==ETHER_ADDR_LEN
	    && arpHeader->ar_pln==4;
}
