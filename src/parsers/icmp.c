#include "../../headerFiles/parsers/icmp.h"


void parse_icmp(sniff_icmp** icmpHeader,const u_char* packet,u_int offset){
	*icmpHeader=(sniff_icmp*)(packet+offset);
}


const char* icmp_type_to_string(uint8_t type){
	switch (type) {
		case 0:  return "Echo Reply";
		case 3:  return "Destination Unreachable";
		case 4:  return "Source Quench";
		case 5:  return "Redirect";
		case 8:  return "Echo Request";
		case 11: return "Time Exceeded";
		case 12: return "Parameter Problem";
		case 13: return "Timestamp";
		case 14: return "Timestamp Reply";
		default: return "Unknown";
	}
}


int icmp_is_echo(uint8_t type){
	return type==0 || type==8;
}
