#include "../../headerFiles/Service/capture.h"


pcap_if_t* get_all_interfaces(char *errbuf){
    pcap_if_t *interfaces;
    if(pcap_findalldevs(&interfaces,errbuf)==-1){
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return NULL;
    }
    return interfaces;  // Caller must free it!
}
void get_first_interface(char** dev,char* errbuf){
    pcap_if_t *interfaces=get_all_interfaces(errbuf);
    if (!interfaces) return ;
    *dev=strdup(interfaces->name);
    if (!*dev) {
        pcap_freealldevs(interfaces);
        return ;
    } 
    pcap_freealldevs(interfaces);
    return ;
}   






void get_device(char** dev,bpf_u_int32* net,bpf_u_int32* mask,char* errbuf){
    get_first_interface(dev,errbuf);
    if(!*dev){
        *net = 0;
        *mask = 0;
        return;
    }
    if(pcap_lookupnet(*dev,net,mask,errbuf)==-1){
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", *dev, errbuf);
		*net = 0;
		*mask = 0;
    }


}


pcap_t* open_device(char* dev,char* errbuf){
    pcap_t* handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		
	}
    return handle;
}




sniffer_error_t compile_and_apply_filter(pcap_t* handle, struct bpf_program* fp, char* filter_exp,bpf_u_int32 net){
    if(pcap_compile(handle,fp,filter_exp,0,net)==-1){
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return sniffer_error_create(SNIFFER_ERROR_INIT,"Couldn't parse filter");
    }
    if (pcap_setfilter(handle, fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        pcap_freecode(fp);
        return sniffer_error_create(SNIFFER_ERROR_INIT,"Couldn't install filter");
    }
    return sniffer_error_create(SNIFFER_OK,"OK");
}




/* Decodes the transport layer shared by IPv4 and IPv6 */
static void dispatch_transport(const u_char* packet,u_int offset,bpf_u_int32 caplen,uint8_t protocol){
    switch (protocol) {
    case IPPROTO_TCP: {
        if (caplen < offset+20) return;
        sniff_tcp* tcpHeader=NULL;
        parse_tcp(&tcpHeader,packet,offset);
        print_tcp(tcpHeader);
        break;
    }
    case IPPROTO_UDP: {
        if (caplen < offset+SIZE_UDP) return;
        sniff_udp* udpHeader=NULL;
        parse_udp(&udpHeader,packet,offset);
        print_udp(udpHeader);
        break;
    }
    case IPPROTO_ICMP: {
        if (caplen < offset+SIZE_ICMP) return;
        sniff_icmp* icmpHeader=NULL;
        parse_icmp(&icmpHeader,packet,offset);
        print_icmp(icmpHeader);
        break;
    }
    }
}


void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    (void)user_data;

    if (pkthdr->caplen < SIZE_ETHERNET) return;

    sniff_ethernet* etherFrame=NULL;
    uint16_t type=parse_ethernet(&etherFrame,packet);
    print_ethernet(etherFrame);

    switch (ntohs(type)) {
    case ETHERTYPE_IP: {
        if (pkthdr->caplen < SIZE_ETHERNET+20) break;
        sniff_ip* ipHeader=NULL;
        parse_ip(&ipHeader,packet);

        u_int header_len=IP_HL(ipHeader)*4;
        if (header_len < 20 || pkthdr->caplen < SIZE_ETHERNET+header_len) break;

        print_ip(ipHeader);
        dispatch_transport(packet,SIZE_ETHERNET+header_len,pkthdr->caplen,ipHeader->ip_p);
        break;
    }
    case ETHERTYPE_IPV6: {
        if (pkthdr->caplen < SIZE_ETHERNET+SIZE_IP6) break;
        sniff_ip6* ip6Header=NULL;
        uint8_t next=parse_ip6(&ip6Header,packet);
        print_ip6(ip6Header);
        dispatch_transport(packet,SIZE_ETHERNET+SIZE_IP6,pkthdr->caplen,next);
        break;
    }
    case ETHERTYPE_ARP: {
        if (pkthdr->caplen < SIZE_ETHERNET+SIZE_ARP) break;
        sniff_arp* arpHeader=NULL;
        parse_arp(&arpHeader,packet);
        print_arp(arpHeader);
        break;
    }
    }

    print_separator();
}

void start_Capture(pcap_t* handle,int count,u_char *userdata){
    if(pcap_loop(handle,count,packet_handler,userdata)==-1){
        fprintf(stderr, "Couldn't loop: %s\n", pcap_geterr(handle));
        return;
    }
}