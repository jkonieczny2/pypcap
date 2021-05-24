#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <pcap.h>
#include <pcap/bpf.h>

#ifndef PYPCAP_UTIL
#include "util.h"
#endif

char *af_to_string(int domain){
    if(domain == AF_INET){
        return "IPV4";
    } else if(domain == AF_INET6){
        return "IPV6";
    } else if(domain == AF_UNIX){
        return "UNIX";
    } else if(domain == AF_UNSPEC){
        return "UNSPECIFIED";
    } else if(domain == AF_LOCAL){
        return "LOCAL";
    } else{
        return "UNKNOWN";
    }
}

/*
Modify the char *host passed into the function

Return 0 on success, -1 on failure
*/
int sockaddr_addr(struct sockaddr *sockaddr, char *host){
    int s = -1;

    if(sockaddr->sa_family == AF_INET || sockaddr->sa_family == AF_INET6){
        s = getnameinfo(
            sockaddr,
            (sockaddr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
            host, NI_MAXHOST,
            NULL, 0, NI_NUMERICHOST
        );
    }

    return s;
}

/*
Convert pcap_if_t->flags to array of strings
*/
struct pflags pcap_flags(bpf_u_int32 flags){
    int i = 0;
    struct pflags pf;

    int all_flags[PCAP_FLAG_MAX] = {
        PCAP_IF_LOOPBACK,
        PCAP_IF_UP,
        PCAP_IF_RUNNING,
        PCAP_IF_WIRELESS
    };

    char *flag_str[PCAP_FLAG_MAX] = {
        "LOOPBACK",
        "UP",
        "RUNNING",
        "WIRELESS"
    };

    for(int j=0; j<PCAP_FLAG_MAX; j++){
        if(flags & all_flags[j]){
            pf.flags[i] = flag_str[j];
            i++;
        }
    }

    pf.size = i;
    return pf;
}

/* utility method to get strings out of PyUnicode objects */
char *
PyUnicode_ToString(PyObject *obj){
    Py_XINCREF(obj);

    if(!PyUnicode_Check(obj)){
        PyErr_SetString(PyExc_AttributeError, "Cannot obtain a char * from a non-PyUnicode object");
        return NULL;
    }   

    PyObject *ascii_string = PyUnicode_AsASCIIString(obj);
    if(ascii_string == NULL){
        PyErr_SetString(PyExc_AttributeError, "PyUnicode object could not be converted to ASCII");
        return NULL;
    }   

    char *c_str = PyBytes_AsString(ascii_string);
    if(c_str == NULL){
        PyErr_SetString(PyExc_AttributeError, "Error converting PyBytes object to c string");
        return NULL;
    }   

    // clean up references, not 100% sure if this is necessary
    Py_DECREF(obj);
    Py_DECREF(ascii_string);

    return c_str;
}

