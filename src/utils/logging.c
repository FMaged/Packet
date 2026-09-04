#include "../../headerFiles/Service/logging.h"


void print_ethernet(const sniff_ethernet* etherFrame){
    char dhost_buffer[18];
    char shost_buffer[18];
    char type_buffer[32];

    if (mac_to_string(etherFrame->ether_dhost,dhost_buffer,sizeof(dhost_buffer)).code==SNIFFER_OK){
        printf("dst MacAddress: %s\n",dhost_buffer);
    }
    if (mac_to_string(etherFrame->ether_shost,shost_buffer,sizeof(shost_buffer)).code==SNIFFER_OK){
        printf("Sender MacAddress: %s\n",shost_buffer);
    }
    type_to_sting(etherFrame->ether_type,type_buffer,sizeof(type_buffer));
    printf("Type: %s\n",type_buffer);
}


void print_ip(sniff_ip* ipHeader){
    char version_buffer[16];
    char ip_dstStr[INET_ADDRSTRLEN];
    char ip_srcStr[INET_ADDRSTRLEN];

    printf("Protocol: %s\n",protocol_to_string(ipHeader->ip_p));
    printf("version: %d\n",IP_V(ipHeader));
    ipV_to_string(IP_V(ipHeader),version_buffer,sizeof(version_buffer));
    printf("Version string: %s\n",version_buffer);
    printf("header length: %d bytes\n",IP_HL(ipHeader)*4);
    printf("Total Length: %d bytes\n",ntohs(ipHeader->ip_len));
    printf("ID: %d\n",ntohs(ipHeader->ip_id));
    printf("Fragmention: %d\n",ntohs(ipHeader->ip_off));
    printf("Dont Fragment: %d\n",ip_DF(ipHeader->ip_off));
    printf("More Fragment: %d\n",ip_MF(ipHeader->ip_off));
    printf("frag Offset: %d\n",ip_offset(ipHeader->ip_off));
    printf("TTL: %d\n",ipHeader->ip_ttl);

    uint16_t calculated=calculate_checksum(ipHeader);
    printf("Checksum: %d  %s\n",ipHeader->ip_sum,validateChecksum(ipHeader->ip_sum,calculated).msg);

    if (ip_To_String(ip_dstStr,ipHeader->ip_dst,sizeof(ip_dstStr)).code==SNIFFER_OK
     && ip_To_String(ip_srcStr,ipHeader->ip_src,sizeof(ip_srcStr)).code==SNIFFER_OK){
        printf("Destination Address: %s\n",ip_dstStr);
        printf("Sender Address: %s\n",ip_srcStr);
    }
}


void print_ip6(const sniff_ip6* ip6Header){
    char ip6_dstStr[INET6_ADDRSTRLEN];
    char ip6_srcStr[INET6_ADDRSTRLEN];

    printf("Protocol: %s\n",protocol_to_string(ip6Header->ip6_nxt));
    printf("version: %d\n",IP6_V(ip6Header));
    printf("Traffic Class: %d\n",IP6_TC(ip6Header));
    printf("Flow Label: %d\n",IP6_FLOW(ip6Header));
    printf("Payload Length: %d bytes\n",ntohs(ip6Header->ip6_plen));
    printf("Hop Limit: %d\n",ip6Header->ip6_hlim);

    if (ip6_To_String(ip6_dstStr,ip6Header->ip6_dst,sizeof(ip6_dstStr)).code==SNIFFER_OK
     && ip6_To_String(ip6_srcStr,ip6Header->ip6_src,sizeof(ip6_srcStr)).code==SNIFFER_OK){
        printf("Destination Address: %s\n",ip6_dstStr);
        printf("Sender Address: %s\n",ip6_srcStr);
    }
}


void print_arp(const sniff_arp* arpHeader){
    char sha_buffer[18];
    char tha_buffer[18];
    char spa_buffer[INET_ADDRSTRLEN];
    char tpa_buffer[INET_ADDRSTRLEN];

    printf("Operation: %s\n",arp_opcode_to_string(arpHeader->ar_op));

    if (!arp_is_ethernet_ipv4(arpHeader)){
        printf("Unsupported ARP layout (hw %d, proto 0x%04X)\n",
               ntohs(arpHeader->ar_hrd),ntohs(arpHeader->ar_pro));
        return;
    }

    if (mac_to_string(arpHeader->ar_sha,sha_buffer,sizeof(sha_buffer)).code==SNIFFER_OK
     && mac_to_string(arpHeader->ar_tha,tha_buffer,sizeof(tha_buffer)).code==SNIFFER_OK
     && inet_ntop(AF_INET,arpHeader->ar_spa,spa_buffer,sizeof(spa_buffer))
     && inet_ntop(AF_INET,arpHeader->ar_tpa,tpa_buffer,sizeof(tpa_buffer))){
        printf("Sender: %s (%s)\n",spa_buffer,sha_buffer);
        printf("Target: %s (%s)\n",tpa_buffer,tha_buffer);
    }
}


void print_tcp(const sniff_tcp* tcpHeader){
    char flags_buffer[TCP_FLAGS_STRLEN];

    printf("Src Port: %d\n",ntohs(tcpHeader->th_sport));
    printf("Dst Port: %d\n",ntohs(tcpHeader->th_dport));
    printf("Seq: %u\n",ntohl(tcpHeader->th_seq));
    printf("Ack: %u\n",ntohl(tcpHeader->th_ack));
    printf("header length: %d bytes\n",TH_OFF(tcpHeader)*4);
    tcp_flags_to_string(tcpHeader->th_flags,flags_buffer,sizeof(flags_buffer));
    printf("Flags: %s\n",flags_buffer);
    printf("Window: %d\n",ntohs(tcpHeader->th_win));
    printf("Checksum: %d\n",ntohs(tcpHeader->th_sum));
}


void print_udp(const sniff_udp* udpHeader){
    printf("Src Port: %d\n",ntohs(udpHeader->uh_sport));
    printf("Dst Port: %d\n",ntohs(udpHeader->uh_dport));
    printf("Length: %d bytes\n",ntohs(udpHeader->uh_ulen));
    printf("Checksum: %d\n",ntohs(udpHeader->uh_sum));
}


void print_icmp(const sniff_icmp* icmpHeader){
    printf("ICMP Type: %d (%s)\n",icmpHeader->icmp_type,icmp_type_to_string(icmpHeader->icmp_type));
    printf("ICMP Code: %d\n",icmpHeader->icmp_code);
    printf("Checksum: %d\n",ntohs(icmpHeader->icmp_sum));
    if (icmp_is_echo(icmpHeader->icmp_type)){
        printf("ID: %d\n",ntohs(icmpHeader->icmp_id));
        printf("Seq: %d\n",ntohs(icmpHeader->icmp_seq));
    }
}


void print_separator(void){
    printf("===============================\n");
}
