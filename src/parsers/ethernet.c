#include "../../headerFiles/parsers/ethernet.h"




uint16_t parse_ethernet(sniff_ethernet** etherFrame,const u_char* packet){
    *etherFrame=(sniff_ethernet*)(packet);
    return (*etherFrame)->ether_type;
}


sniffer_error_t mac_to_string(const uint8_t* mac, char* buffer,size_t size){

    if (!mac) return sniffer_error_create(SNIFFER_ERROR_INIT,"THE MAC | BUFFER  IS NULL"); // Avoid NULL pointer issues
    
    if (size < 18) {
        return sniffer_error_create(SNIFFER_ERROR_INIT, "BUFFER SIZE TOO SMALL");
    }
    
    int len=snprintf(buffer, size, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    if (len < 0 || (size_t)len >= size) {
        return sniffer_error_create(SNIFFER_ERROR_INIT, "THE MAC FORMAT IS INVALID");
    }
    
    return sniffer_error_create(SNIFFER_OK,("OK"));     



}





sniffer_error_t type_to_sting(uint16_t type,char* buffer,size_t size){
    if (!buffer) return sniffer_error_create(SNIFFER_ERROR_INVALID_ARG,"THE BUFFER IS NULL");

    type = ntohs(type);  // struct fields arrive in network order

    const char* name;
    switch (type)
    {
    case ETHERTYPE_IP:
        name = "IPv4";
        break;

    case ETHERTYPE_IPV6:
        name = "IPv6";
        break;

    case ETHERTYPE_ARP:
        name = "ARP";
        break;

    default:
        if ((size_t)snprintf(buffer, size, "Unknown (0x%04X)", type) >= size) {
            return sniffer_error_create(SNIFFER_ERROR_INVALID_ARG,"BUFFER SIZE TOO SMALL");
        }
        return sniffer_error_create(SNIFFER_ERROR_INIT,"UNDEFINED TYPE");

    }

    if ((size_t)snprintf(buffer, size, "%s", name) >= size) {
        return sniffer_error_create(SNIFFER_ERROR_INVALID_ARG,"BUFFER SIZE TOO SMALL");
    }
    return sniffer_error_create(SNIFFER_OK,"OK");



}
