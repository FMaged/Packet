#include "../../headerFiles/parsers/ethernet.h"




uint16_t parse_ethernet(sniff_ethernet** etherFrame,const u_char* packet){
    *etherFrame=(sniff_ethernet*)(packet);
    return (*etherFrame)->ether_type;
}


sniffer_error_t mac_to_string(uint8_t* mac, char* buffer,size_t size){

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





sniffer_error_t type_to_sting(uint16_t type,char* buffer){
    if (!type ) {
        return sniffer_error_create(SNIFFER_ERROR_INIT,"THE TYPE IS NULL");
    }

    // Convert from network to host byte order
    type = ntohs(type); 
    switch (type)
    {
    case ETHERTYPE_IP:
        strcpy(buffer,"Ipv4");
        //buffer="Ipv4";
        break;
    
    case ETHERTYPE_IPV6:
        strcpy(buffer, "Ipv6"); 
        break;

    case ETHERTYPE_ARP:
        strcpy(buffer, "ARP"); 
        break;

    default:
        snprintf(buffer, 32, "Unknown (0x%04X)", type);
        return sniffer_error_create(SNIFFER_ERROR_INIT,"UNDEFINED TYPE");
        
    }
    return sniffer_error_create(SNIFFER_OK,"OK");



}
