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
    if(pcap_lookupnet(*dev,net,mask,errbuf)==-1){
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", *dev, errbuf);
		net = 0;
		mask = 0;
    }


}


pcap_t* open_device(char* dev,char* errbuf){
    pcap_t* handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
    if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		
	}
    return handle;
}




void compile_and_apply_filter(pcap_t* handle, struct bpf_program* fp, char* filter_exp,bpf_u_int32 net){
    if(pcap_compile(handle,fp,filter_exp,0,net)==-1){
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        handle=NULL;
        return;
    }
    if (pcap_setfilter(handle, fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        handle=NULL;
        return;
    }



    
}




void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet){
    
    sniff_ethernet* etherFrame=NULL;
    sniff_ip* ipHeader=NULL;
    char buffer[32];
    char dhost_buffer[18];
    char shost_buffer[18];
    char Vbuffer[16];
    uint16_t type= parse_ethernet(&etherFrame,packet);
    sniffer_error_t result=type_to_sting(type,buffer,sizeof(buffer));
    sniffer_error_t macResult=mac_to_string(etherFrame->ether_dhost,dhost_buffer,sizeof(dhost_buffer));
    sniffer_error_t senderMacResult=mac_to_string(etherFrame->ether_shost,shost_buffer,sizeof(shost_buffer));
    
    if(result.code==SNIFFER_OK&&macResult.code==SNIFFER_OK&&senderMacResult.code==SNIFFER_OK){
        printf("dst MacAddress: %s\n",dhost_buffer);    
        printf("Sender MacAddress: %s\n",shost_buffer);
        printf("Type: %s\n",buffer);
        if(type==htons(ETHERTYPE_IP)){
            u_char protocol=parse_ip(&ipHeader,packet);
            printf("Protocol: %s\n",protocol_to_string(protocol));
            printf("version: %d\n",IP_V(ipHeader));
            result=ipV_to_string(IP_V(ipHeader),Vbuffer,sizeof(Vbuffer));
            printf("Verśion string: %s\n",Vbuffer);
            printf("header length: %d bits\n",IP_HL(ipHeader)*4);   
            printf("Total Length: %d bytes\n",ntohs(ipHeader->ip_len ));
            printf("ID: %d\n",ntohs(ipHeader->ip_id));
            printf("Fragmention: %d\n",ntohs(ipHeader->ip_off));
            printf("Dont Fragment: %d\n",ip_DF(ipHeader->ip_off));
            printf("More Fragment: %d\n",ip_MF(ipHeader->ip_off));
            printf("frag Offset: %d\n",ip_offset(ipHeader->ip_off));
            printf("TTL: %d\n",ipHeader->ip_ttl);
            uint16_t cChecksum=calculate_checksum(ipHeader);
            printf("Checksum: %d  %s\n",ipHeader->ip_sum,validateChecksum(ipHeader->ip_sum,cChecksum).msg);


            char ip_dstStr[INET_ADDRSTRLEN];
            char ip_SenStr[INET_ADDRSTRLEN];
            sniffer_error_t ipResult=ip_To_String(ip_dstStr,ipHeader->ip_dst,sizeof(ip_dstStr));
            sniffer_error_t ipSenderResult=ip_To_String(ip_SenStr,ipHeader->ip_src,sizeof(ip_SenStr));
            if(ipResult.code==SNIFFER_OK&&ipSenderResult.code==SNIFFER_OK){
                printf("Destnion Address: %s\n", ip_dstStr);
                printf("Sender Address: %s\n",ip_SenStr);
            }


            

            
            printf("===============================\n");
        }else{
            printf("ipv6\n\n\n");
    }

}






}

void start_Capture(pcap_t* handle,int count,u_char *userdata){
    if(pcap_loop(handle,count,packet_handler,NULL)==-1){
        fprintf(stderr, "Couldn't loop: %s\n", pcap_geterr(handle));
        handle=NULL;
        return;
    }
}