#include "../../headerFiles/Service/error.h"


sniffer_error_t sniffer_error_create(int Code,const char* Msg){
    return (sniffer_error_t){.code= Code,.msg=Msg };

}    


const char* sniffer_error_message(sniffer_error_t error) {
    switch (error.code) {
        case SNIFFER_OK:
            return "No error";
        case SNIFFER_ERROR_INIT:
            return "Failed to initialize sniffer";
        case SNIFFER_ERROR_CAPTURE:
            return "Failed to capture";
        case SNIFFER_ERROR_INVALID_ARG:
            return "Invalid argument provided";
        default:
            return "Unknown error";
    }
}