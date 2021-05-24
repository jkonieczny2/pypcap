#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <sys/socket.h>

#define PYPCAP_UTIL // header guard
#define PCAP_FLAG_MAX 4 // no type safety with this macro

struct pflags{
    unsigned int size;
    char *flags[PCAP_FLAG_MAX];
};

char *af_to_string(int domain);
int sockaddr_addr(struct sockaddr *sockaddr, char *host);
struct pflags pcap_flags(bpf_u_int32 flags);
// IP address and nmask return 0, which cannot be correct
// should use system libs like in https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
/*
convert a PyUnicode object to a C string
*/
char *PyUnicode_ToString(PyObject *obj);
