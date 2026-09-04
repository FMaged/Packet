#include "../../headerFiles/parsers/tcp.h"


void parse_tcp(sniff_tcp** tcpHeader,const u_char* packet,u_int offset){
	*tcpHeader=(sniff_tcp*)(packet+offset);
}


sniffer_error_t tcp_flags_to_string(uint8_t flags,char* buffer,size_t size){
	if (!buffer) return sniffer_error_create(SNIFFER_ERROR_INVALID_ARG,"Buffer is NULL");

	static const struct { uint8_t bit; const char* name; } table[] = {
		{TH_FIN,"FIN"}, {TH_SYN,"SYN"}, {TH_RST,"RST"}, {TH_PUSH,"PSH"},
		{TH_ACK,"ACK"}, {TH_URG,"URG"}, {TH_ECE,"ECE"}, {TH_CWR,"CWR"},
	};

	size_t used=0;
	for (size_t i=0;i<sizeof(table)/sizeof(table[0]);i++){
		if (!(flags & table[i].bit)) continue;
		int written=snprintf(buffer+used,size-used,"%s%s",used?"|":"",table[i].name);
		if (written<0 || (size_t)written>=size-used){
			return sniffer_error_create(SNIFFER_ERROR_INVALID_ARG,"Buffer size too small");
		}
		used+=written;
	}

	if (!used && size) buffer[0]='\0';
	return sniffer_error_create(SNIFFER_OK,"OK");
}
