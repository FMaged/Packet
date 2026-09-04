#include "../../headerFiles/parsers/ip6.h"


uint8_t parse_ip6(sniff_ip6** ip6Header,const u_char* packet){
	*ip6Header=(sniff_ip6*)(packet+SIZE_ETHERNET);
	return (*ip6Header)->ip6_nxt;
}


sniffer_error_t ip6_To_String(char* buffer,const uint8_t* addr,size_t size){
	if (!buffer || !addr) return sniffer_error_create(SNIFFER_ERROR_INVALID_ARG,"Buffer or address is NULL");

	if (inet_ntop(AF_INET6,addr,buffer,size)==NULL){
		return sniffer_error_create(SNIFFER_ERROR_INVALID_ARG,"Invalid Address");
	}
	return sniffer_error_create(SNIFFER_OK,"OK");
}
