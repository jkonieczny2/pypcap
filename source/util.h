#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <sys/socket.h>

char *af_to_string(int domain);
int sockaddr_addr(struct sockaddr *sockaddr, char *host);
// IP address and nmask return 0, which cannot be correct
// should use system libs like in https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
/*
convert a PyUnicode object to a C string
*/
char *PyUnicode_ToString(PyObject *obj);
