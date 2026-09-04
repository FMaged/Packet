#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "headerFiles/Service/capture.h"



int main(){

    pcap_t *handle;		/* Session handle */
    char* dev = NULL;		/* Device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    struct bpf_program fp;		/* The compiled filter expression */
    char filter_exp[] ="ip or ip6 or arp";	/* The filter expression */
    bpf_u_int32 mask;		/* The netmask of our sniffing device */
    bpf_u_int32 net;		/* The IP of our sniffing device */
    int count=0;  /* Number of packets to capture (0 for infinite).*/

    get_device(&dev,&net,&mask,errbuf);
    if(!dev){
        fprintf(stderr, "No capture device available\n");
        return 1;
    }

    handle=open_device(dev,errbuf);
    free(dev);
    if(!handle){
        return 1;
    }

    if(compile_and_apply_filter(handle,&fp,filter_exp,net).code != SNIFFER_OK){
        pcap_close(handle);
        return 1;
    }
    printf("Network: %s\n", inet_ntoa(*(struct in_addr*)&net));

    start_Capture(handle,count,NULL);

    pcap_freecode(&fp);
    pcap_close(handle);
    return 0;
}
