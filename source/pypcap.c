#include <pcap.h>
#include "pypcap.h"
#include "writer.h"
//#include "reader.h" //included this already in writer.h; figure out how ifndef works

/*
Methods to create python objects
*/

/*
Return a PyDict containing interface details
*/
PyObject *Py_Build_Interface(pcap_if_t *iface){
    PyObject *iface_dict = Py_BuildValue(
        "{s:s, s:s}",
        "name", iface->name,
        "description", iface->description
    );

    if (iface_dict == NULL){
        PyErr_NoMemory(); //lol
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
    }
    int res = pcap_findalldevs(&iface, errbuf);

    if(res == -1){
        return PyUnicode_FromString(errbuf);
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

static PyObject *
pcap_writer(PyObject *self, PyObject *args)
{
    const char * filename;
    const char * mode;

    if(!PyArg_ParseTuple(args, "ss", &filename, &mode)){
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
