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

sniffer_error_t ipV_to_string(uint8_t extractedVersion,char* buffer){
	if (buffer == NULL) {
        return sniffer_error_create(SNIFFER_ERROR_INIT, "Buffer is NULL");
    }
	switch (extractedVersion)
	{
	case 4:
		strcpy(buffer, "IPv4");
		break;
	case 6:
		strcpy(buffer, "IPv6");
		break;
	default:
	snprintf(buffer, 32, "Unknown (%d)", extractedVersion);
	return sniffer_error_create(SNIFFER_ERROR_INIT, "Unknown IP Version");
}



return sniffer_error_create(SNIFFER_OK, "OK");

}

int ip_DF(uint16_t ip_off){
	ip_off = ntohs(ip_off);  // Convert from network to host byte order
    int DF = (ip_off & 0x4000) >> 14;
	return DF;
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


uint16_t calculate_checksum(sniff_ip ipHeader){
    uint32_t sum = 0;  // 32-bit accumulator to handle overflow
		







}


