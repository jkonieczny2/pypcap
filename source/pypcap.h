#define PY_SSIZE_T_CLEAN
#include <Python.h>

typedef struct
{
    PyObject_HEAD
    char *name;
    char *description;
}Interface;

static PyTypeObject InterfaceType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pypcap.Interface",
    .tp_doc = "Object representing a network interface",
    .tp_basicsize = sizeof(Interface),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_new = PyType_GenericNew,
};

/*
Module functions
*/
static PyObject *find_all_devs(PyObject *self, PyObject *args);
static PyObject *pcap_writer(PyObject *self, PyObject *args);

/*
Methods for creating Python objects from pcap structs
*/
PyObject *Py_Build_Interface(pcap_if_t *iface);
PyObject *Py_Build_Interface_List(int size, pcap_if_t *iface);
