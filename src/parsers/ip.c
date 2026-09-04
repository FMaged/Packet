#include "../../headerFiles/parsers/ip.h"




uint8_t parse_ip (sniff_ip** ipHeader,const u_char* packet){
	*ipHeader=(sniff_ip*)(packet+SIZE_ETHERNET);
	u_int size_ip=IP_HL(*ipHeader)*4;
	if (size_ip < 20) {
		fprintf(stderr,"* Invalid IP header length: %d bytes\n", size_ip);
		return 0;
	}
    return (*ipHeader)->ip_p;
}

sniffer_error_t ipV_to_string(uint8_t extractedVersion,char* buffer,size_t size){
	if (buffer == NULL) {
        return sniffer_error_create(SNIFFER_ERROR_INVALID_ARG, "Buffer is NULL");
    }

	const char* name;
	switch (extractedVersion)
	{
	case 4:
		name = "IPv4";
		break;
	case 6:
		name = "IPv6";
		break;
	default:
		if ((size_t)snprintf(buffer, size, "Unknown (%d)", extractedVersion) >= size) {
			return sniffer_error_create(SNIFFER_ERROR_INVALID_ARG, "Buffer size too small");
		}
		return sniffer_error_create(SNIFFER_ERROR_INIT, "Unknown IP Version");
	}

	if ((size_t)snprintf(buffer, size, "%s", name) >= size) {
		return sniffer_error_create(SNIFFER_ERROR_INVALID_ARG, "Buffer size too small");
	}
	return sniffer_error_create(SNIFFER_OK, "OK");

}

int ip_DF(uint16_t ip_off){
ip_off = ntohs(ip_off);  				// Convert from network to host byte order
    int DF = (ip_off & 0x4000) >> 14;	// Isolate DF flag and shift
	return DF;							// Returns 1 if DF is set, else 0
}
int ip_MF(uint16_t ip_off){
	ip_off = ntohs(ip_off);  // Convert from network to host byte order
    int MF = (ip_off & 0x2000) >> 13;
	return MF;
}
							
int ip_offset(uint16_t ip_off){										
	ip_off = ntohs(ip_off); 
	int frag_offset = (ip_off & 0x1FFF);
	return frag_offset;



}

uint16_t calculate_checksum(const sniff_ip* ipHeader){
    uint32_t sum = 0;
    // Read as bytes: the packet sits in libpcap's buffer, which must not be
    // written to, and a uint16_t* view would break strict aliasing.
    const uint8_t* bytes = (const uint8_t*)ipHeader;
    size_t hdr_len_words = (IP_HL(ipHeader) * 4) / 2;

    for (size_t i = 0; i < hdr_len_words; i++) {
        if (i == IP_SUM_WORD) continue;  // the checksum field counts as zero
        sum += (uint32_t)(bytes[2*i] << 8 | bytes[2*i + 1]);
    }

    // Fold 32-bit sum into 16 bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Return 1's complement, in network byte order
    return htons((uint16_t)(~sum));


}
sniffer_error_t validateChecksum(uint16_t checksum,uint16_t calculatedChecksum){
	if(checksum==calculatedChecksum){
		return sniffer_error_create(SNIFFER_OK,"OK");
	}else{
		return sniffer_error_create(SNIFFER_ERROR_INIT, "Invalid!");
	}

}

sniffer_error_t ip_To_String(char* buffer, uint32_t ip_addr,size_t bufferSize){
    struct in_addr addr={.s_addr=ip_addr};
    const char* dstString= inet_ntop(AF_INET,&addr,buffer,bufferSize);
    if(dstString==NULL){
        return sniffer_error_create(SNIFFER_ERROR_INVALID_ARG,"Invaild Address");
    }
    return sniffer_error_create(SNIFFER_OK,"OK");
}
