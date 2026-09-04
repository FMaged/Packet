#include "../../headerFiles/parsers/udp.h"


void parse_udp(sniff_udp** udpHeader,const u_char* packet,u_int offset){
	*udpHeader=(sniff_udp*)(packet+offset);
}
