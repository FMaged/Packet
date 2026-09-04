#include "../../headerFiles/Service/protocols.h"


const char* protocol_to_string(uint8_t protocol){
	switch (protocol) {
        case 1:  return "ICMP";
        case 2:  return "IGMP";
        case 6:  return "TCP";
        case 17: return "UDP";
        case 41: return "IPv6";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 58: return "ICMPv6";
        case 89: return "OSPF";
        default: return "Unknown";
	}
}
