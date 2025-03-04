#ifndef CAPtURE_H
#define CAPTURE_H

#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "../parsers/ethernet.h"
#include "../parsers/ip.h"

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;



pcap_if_t* get_all_interfaces(char *errbuf);

void get_first_interface(char** dev,char* errbuf);

void get_device(char** dev,bpf_u_int32* net,bpf_u_int32* mask,char* errbuf);

pcap_t* open_device(char* dev,char* errbuf);

void compile_and_apply_filter(pcap_t* handle, struct bpf_program* fp, char* filter_exp,bpf_u_int32 net);

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet);

void start_Capture(pcap_t* handle,int count,u_char *userdata);








#endif