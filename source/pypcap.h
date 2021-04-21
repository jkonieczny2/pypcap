#define PY_SSIZE_T_CLEAN
#include <Python.h>

/*
Module functions
*/
static PyObject *find_all_devs(PyObject *self, PyObject *args);
static PyObject *pcap_writer(PyObject *self, PyObject *args);

/*
Methods for creating Python objects from pcap structs
*/
PyObject *Py_Build_Interface(pcap_if_t *iface);
