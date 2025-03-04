#ifndef PACKET_SNIFFER_INCLUDE_UTILS_ERROR_H
#define PACKET_SNIFFER_INCLUDE_UTILS_ERROR_H

typedef struct  {
    int code;
    const char* msg;
}sniffer_error_t;

    
#define SNIFFER_OK 0                    // No error
#define SNIFFER_ERROR_INIT 1            // Initialization error
#define SNIFFER_ERROR_CAPTURE 2         // capture error
#define SNIFFER_ERROR_INVALID_ARG 3     // Invalid argument





sniffer_error_t sniffer_error_create(int Code,const char* Msg);    

const char* sniffer_error_message(sniffer_error_t error);



#endif  