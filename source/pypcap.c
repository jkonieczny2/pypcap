#include <pcap.h>
#include "pypcap.h"
#include "writer.h"
//#include "reader.h" //included this already in writer.h; figure out how ifndef works

/*
Methods to create python objects
*/

/*
Return number of items in a linked list of pcap_addr_t
*/
Py_ssize_t len_addresses(pcap_addr_t *addr){
    Py_ssize_t count = 0;
    while(addr != NULL){
        count++;
        addr = addr->next;
    }
    return count;
}

/*
Return a PyDict representing a struct sockaddr
*/
PyObject *Py_Build_Sockaddr(struct sockaddr *sockaddr){
    PyObject *sockaddr_dict = PyDict_New();
    if(sockaddr_dict == NULL){
        PyErr_NoMemory();
    }

    // address family
    char *address_type = af_to_string(sockaddr->sa_family);
    PyObject *py_addr_type = Py_BuildValue("s", address_type);
    if(py_addr_type == NULL){
        PyErr_NoMemory();
    }
    PyDict_SetItemString(sockaddr_dict, "address_family", py_addr_type);

    // inet addr of socket
    char host[NI_MAXHOST];
    int s = sockaddr_addr(sockaddr, host);

    if(s==0){
        PyObject *py_addr = Py_BuildValue("s", host);
        PyDict_SetItemString(sockaddr_dict, "address", py_addr);
    }

    if(sockaddr_dict == NULL){
        PyErr_SetString(PyExc_ValueError, "Error retrieving sockaddr information");
        return NULL;
    }
    return sockaddr_dict;
}

/*
Return a PyDict representing a pcap_addr_t
*/
PyObject *Py_Build_Addr(pcap_addr_t *addr){
    PyObject *addr_dict = PyDict_New();
    if(addr_dict == NULL){
        PyErr_NoMemory();
    }

    // addr
    PyObject *py_addr = Py_Build_Sockaddr(addr->addr);
    PyDict_SetItemString(addr_dict, "addr", py_addr);

    // netmask
    // TODO: pass this directly to Py_Build_Sockaddr
    //       that way we get a more compact dict
    if(addr->netmask != NULL){
        PyObject *nmask = Py_Build_Sockaddr(addr->netmask);
        PyDict_SetItemString(addr_dict, "netmask", nmask);
    }

    // broadaddr
    if(addr->broadaddr != NULL){
        PyObject *nmask = Py_Build_Sockaddr(addr->broadaddr);
        PyDict_SetItemString(addr_dict, "broadaddr", nmask);
    }

    // dstaddr
    if(addr->dstaddr != NULL){
        PyObject *nmask = Py_Build_Sockaddr(addr->dstaddr);
        PyDict_SetItemString(addr_dict, "dstaddr", nmask);
    }

    if(addr_dict == NULL){
        PyErr_SetString(PyExc_ValueError, "Error retrieving pcap_addr_t information");
        return NULL;
    }

    return addr_dict;
}

/*
Return a PyDict containing interface details
*/
PyObject *Py_Build_Interface(pcap_if_t *iface){
    PyObject *iface_dict = Py_BuildValue(
        "{s:s, s:s, s:i}",
        "name", iface->name,
        "description", iface->description,
        "flags", iface->flags
    );

    // Build address information
    int len_addrs = len_addresses(iface->addresses);
    PyObject *addr_list = PyList_New(len_addrs);
    if(addr_list == NULL){
        PyErr_SetString(PyExc_ValueError, "Error initializing pcap_addr_t list");
        return NULL;
    }
    pcap_addr_t *addr = iface->addresses;
    for(Py_ssize_t i=0; i<len_addrs; i++){
        PyObject *py_addr = Py_Build_Addr(addr);
        if(py_addr == NULL){ // is this redundant since i'm already doing it in the function?
            PyErr_SetString(PyExc_ValueError, "Error retrieving pcap_addr_t information");
            return NULL;
        }
        PyList_SetItem(addr_list, i, py_addr);
        addr = addr->next;
    }

    int addr_set = PyDict_SetItemString(iface_dict, "addresses", addr_list);
    if(addr_set == -1){
        PyErr_SetString(PyExc_ValueError, "Could not set 'addresses' value in interface dict");
        return NULL;
    }

    if (iface_dict == NULL){
        PyErr_SetString(PyExc_ValueError, "Error retrieving interface definintions");
        return NULL;
    }

    return iface_dict;
}

/*
Return dict of all network devices on this machine
*/
static PyObject *
find_all_devs(PyObject *self, PyObject *args)
{
    // get ifaces
    char errbuf[1024] = "";
    pcap_if_t *iface = malloc(sizeof(pcap_if_t));
    if(iface == 0){
        PyErr_NoMemory();
        return NULL;
    }
    int res = pcap_findalldevs(&iface, errbuf);

    if(res == -1){
        PyErr_SetString(PyExc_SystemError, errbuf);
        return NULL;
    }

    // build dict of interface details
    PyObject *iface_dict = PyDict_New();

    while(iface != NULL){
        PyObject *idict = Py_Build_Interface(iface);
        PyObject *iface_name = Py_BuildValue("s", iface->name);
        PyDict_SetItem(iface_dict, iface_name, idict);
        iface = iface->next;
    }

    // clean up iface objects
    pcap_freealldevs(iface);

    return iface_dict;
};

/*
Define module-level methods
*/
static PyMethodDef PyPcapMethods[] = {
    {"find_all_devs" , find_all_devs, METH_VARARGS, "List all network devices on the system"},
    {NULL, NULL, 0, NULL}
};

/*
Register Python module
*/
static struct PyModuleDef pypcap = {
    PyModuleDef_HEAD_INIT,
    "pypcap",
    NULL,
    -1,
    PyPcapMethods,
    NULL,
    NULL,
    NULL,
    NULL
};

/*
Init Python module
*/
PyMODINIT_FUNC
PyInit_pypcap(void)
{
    PyObject *m;
    if (PyType_Ready(&PcapWriterType) < 0)
        return NULL;
    if (PyType_Ready(&PcapReaderType) < 0)
        return NULL;

    m = PyModule_Create(&pypcap);
    if(m == NULL)
        return NULL;

    Py_INCREF(&PcapWriterType);
    if(PyModule_AddObject(m, "PcapWriter", (PyObject *) &PcapWriterType) < 0){
        Py_DECREF(&PcapWriterType);
        Py_DECREF(m);
        return NULL;
    };

    Py_INCREF(&PcapReaderType);
    if(PyModule_AddObject(m, "PcapReader", (PyObject *) &PcapReaderType) < 0){
        Py_DECREF(&PcapReaderType);
        Py_DECREF(m);
        return NULL;
    };

    return m;
};
