#include <pcap.h>
#include "pypcap.h"

/*
Methods to create python objects
*/
PyObject *Py_Build_Interface(pcap_if_t *iface){
    // might want to try building a pydict, custom object is a PITA
    PyObject *iface_name = Py_BuildValue("s", iface->name);
    return iface_name;
}

PyObject *Py_Build_Interface_List(int size, pcap_if_t *iface){
    PyObject *iface_list = PyList_New(size);

    for(int i=0; i<size; i++){
        PyObject *iface_name = Py_Build_Interface(iface);
        PyList_SetItem(iface_list, i, iface_name);
        iface = iface->next; // you have to get the size right or this will segfault!!!
    }

    return iface_list;
}

/*
Return array of all network devices on this machine
*/
static PyObject *
find_all_devs(PyObject *self, PyObject *args)
{
    // get ifaces
    char errbuf[1024] = "";
    pcap_if_t *iface = malloc(sizeof(pcap_if_t));
    if(iface == 0){
        PyErr_NoMemory();
    }
    int res = pcap_findalldevs(&iface, errbuf);

    if(res == -1){
        return PyUnicode_FromString(errbuf);
    }

    // count ifaces to get array size
    pcap_if_t *iface_first = iface;
    int iface_count = 0;
    while(iface->next){
        iface_count++;
        iface = iface->next;
    }

    // Store ifaces in Python list
    PyObject *iface_list = Py_Build_Interface_List(iface_count, iface_first);

    // clean up iface objects
    pcap_freealldevs(iface);

    return iface_list;
};

static PyObject *
pcap_writer(PyObject *self, PyObject *args)
{
    const char * filename;
    const char * mode;

    if(!PyArg_ParseTuple(args, "ss", &filename, &mode)){
        printf("Could not open file\n");
        PyErr_NoMemory(); // also retarded, lol
    }

    // create file descriptor
    FILE *fp = fopen(filename, mode);
    if(fp == NULL){
        printf("Could not open file %s\n", filename);
        PyErr_NoMemory(); // retarded, lol
    }
    int fd = fileno(fp);

    // return Py file obj
    PyObject *fobj = PyFile_FromFd(fd, filename, mode, -1, NULL, NULL, NULL, 1); // PyFile_FromFile died in 2.7
    if(fobj == NULL){
        printf("Could not create python file obj\n");
        PyErr_NoMemory(); // this is retarded but fine for now
    }

    return fobj;
}

/*
Define methods in the module
*/
static PyMethodDef PyPcapMethods[] = {
    {"find_all_devs" , find_all_devs, METH_VARARGS, "List all network devices on the system"},
    {"pcap_writer", pcap_writer, METH_VARARGS, "Open a file for writing pcaps"},
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
    if (PyType_Ready(&InterfaceType) < 0)
        return NULL;

    m = PyModule_Create(&pypcap);
    if(m == NULL)
        return NULL;

    Py_INCREF(&InterfaceType);
    if(PyModule_AddObject(m, "Interface", (PyObject *) &InterfaceType) < 0){
        Py_DECREF(&InterfaceType);
        Py_DECREF(m);
        return NULL;
    };

    return m;
};
