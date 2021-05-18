#include <arpa/inet.h>
#include "util.h"

uint16_t sockaddr_to_port(struct sockaddr *sockaddr){
    struct sockaddr_in *sock_in = (struct sockaddr_in *) &sockaddr;
    in_port_t port = sock_in->sin_port;
    return (uint16_t)port;
}

char *sockaddr_to_inet_addr(struct sockaddr *sockaddr){
    struct sockaddr_in *sock_in = (struct sockaddr_in *) &sockaddr;
    char *ip = inet_ntoa(sock_in->sin_addr);
    return ip;
}

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

