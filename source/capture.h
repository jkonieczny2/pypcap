#define PY_SSIZE_T_CLEAN
#include <assert.h>
#include <Python.h>
#include <string.h>
#include <structmember.h>
#include <stdio.h>

#ifndef PYPCAP_UTIL
#include "util.h"
#endif

#define PYPCAP_CAPTURE
#define LINKTYPE_ETHERNET 1

#ifndef MAX_PACKET_SIZE
#define MAX_PACKET_SIZE 65535
#endif

typedef struct{
    PyObject_HEAD
    /* C-style properties*/    
    char *_interface_name;
    int _packet_len;
    int _promisc;
    int _timeout_ms;
    char *_output_filename;
    int _max_packets;
    char _errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *_pcap;
    /* Python properties */
    PyObject *interface_name;
    PyObject *packet_len;
    PyObject *promisc;
    PyObject *timeout_ms;
    PyObject *output_filename;
    PyObject *max_packets;
} PcapCapture;

/* creation method */
static PyObject *
PcapCapture_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PcapCapture *self;
    self = (PcapCapture *) type->tp_alloc(type,0);
    return (PyObject *) self;
}

/* initialization method */
static int
PcapCapture_init(PcapCapture *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {
        "interface_name",
        "output_filename",
        "max_packets",
        "promiscuous",
        "timeout_ms",
        NULL
    };

    PyObject *interface_name=NULL, *output_filename=NULL, *tmp;
    int promiscuous=0, timeout_ms=1000, max_packets;

    if(!PyArg_ParseTupleAndKeywords(
        args,
        kwds,
        "OOi|ii",
        kwlist,
        &interface_name, &output_filename, &max_packets,
        &promiscuous, &timeout_ms
    )){
        return -1;
    }

    // interface name
    if(interface_name){
        char *iface_name = PyUnicode_ToString(interface_name);
        if(iface_name == NULL){
            PyErr_SetString(PyExc_ValueError, "Could not convert interface_name into C string");
            return -1;
        }
        self->_interface_name = iface_name;

        tmp = self->interface_name;
        Py_INCREF(interface_name);
        self->interface_name = interface_name;
        Py_XDECREF(tmp);
    }

    // output filename
    if(output_filename){
        char *fname = PyUnicode_ToString(output_filename);
        if(fname == NULL){
            PyErr_SetString(PyExc_ValueError, "Could not convert output_filename into C string");
            return -1;
        }
        self->_output_filename = fname;

        tmp = self->output_filename;
        Py_INCREF(output_filename);
        self->output_filename = output_filename;
        Py_XDECREF(tmp);
    }

    // max packets
    if(max_packets <= 0){
        PyErr_SetString(PyExc_ValueError, "max_packets must be > 0");
        return -1;
    }
    PyObject *py_max_packets = PyLong_FromLong((long)max_packets);
    if(py_max_packets == NULL){
        PyErr_NoMemory();
        return -1;
    }
    self->_max_packets = max_packets;
    tmp = self->max_packets;
    Py_INCREF(py_max_packets);
    self->max_packets = py_max_packets;
    Py_XDECREF(tmp);

    // promisc mode
    PyObject *py_promisc = PyBool_FromLong((long)promiscuous);
    if(py_promisc == NULL){
        PyErr_NoMemory();
        return -1;
    }
    self->_promisc = promiscuous;
    tmp = self->promisc;
    Py_INCREF(py_promisc);
    self->promisc = py_promisc;
    Py_XDECREF(tmp);

    // timeout
    if(timeout_ms <= 0){
        PyErr_SetString(PyExc_ValueError, "timeout_ms must be > 0");
        return -1;
    }
    PyObject *py_timeout_ms = PyLong_FromLong((long)timeout_ms);
    if(py_timeout_ms == NULL){
        PyErr_NoMemory();
        return -1;
    }
    self->_timeout_ms = timeout_ms;
    tmp = self->timeout_ms;
    Py_INCREF(py_timeout_ms);
    self->timeout_ms = py_timeout_ms;
    Py_XDECREF(tmp);

    // packet length
    // hard code this to MAX_PACKET_SIZE
    // should be no reason not to capture full packets
    PyObject *packet_length = PyLong_FromLong(MAX_PACKET_SIZE);
    if(packet_length == NULL){
        PyErr_NoMemory();
        return -1;
    }
    self->_packet_len = MAX_PACKET_SIZE;
    tmp = self->packet_len;
    Py_INCREF(packet_length);
    self->packet_len = packet_length;
    Py_XDECREF(tmp);

    return 0;
}

static PyObject *
PcapCapture_start(PcapCapture *self, PyObject *args)
{
    // open live pcap captures on interface
    pcap_t *pcap = pcap_open_live(
        self->_interface_name,
        self->_packet_len,
        self->_promisc,
        self->_timeout_ms,
        self->_errbuf
    );

    if(pcap == NULL){
        PyErr_Format(PyExc_SystemError, "Could not open interface %s for packet capture: %s", self->_interface_name, self->_errbuf);
        return NULL;
    }
    self->_pcap = pcap;

    pcap_dumper_t *d = pcap_dump_open(self->_pcap, self->_output_filename);
    if(d == NULL){
        PyErr_Format(PyExc_SystemError, "Could not open pcap dumper for %s", self->_output_filename);
        return NULL;
    }

    int processed = pcap_loop(
        self->_pcap,
        self->_max_packets,
        pcap_dump_handler,
        (u_char *)d
    );

    // TODO: call get_error for better alert here
    if(processed != 0){
        PyErr_Format(PyExc_SystemError, "Problem processing pcaps on interface %s", self->_interface_name);
        return NULL;
    }

    return Py_BuildValue("");
}
/* expose attributes as custom members */
static PyMemberDef PcapCapture_members[] = {
    {"_interface_name", T_STRING, offsetof(PcapCapture, _interface_name), 0, "c string for interface name"},
    {"_packet_len", T_INT, offsetof(PcapCapture, _packet_len), 0, "c int for packet length"},
    {"_promisc", T_INT, offsetof(PcapCapture, _promisc), 0, "c int for promiscuous mode"},
    {"_timeout_ms", T_INT, offsetof(PcapCapture, _timeout_ms), 0, "c int for timeout in ms"},
    {"_output_filename", T_STRING, offsetof(PcapCapture, _output_filename), 0, "c string for output filename"},
    {"_max_packets", T_INT, offsetof(PcapCapture, _max_packets), 0, "c int for max packets"},
    {"_errbuf", T_STRING, offsetof(PcapCapture, _errbuf), 0, "pcap errbuf"},
    {"_pcap", T_OBJECT_EX, offsetof(PcapCapture, _pcap), 0, "pcap_t pointer"},
    {NULL}
};

/* expose methods */
static PyMethodDef PcapCapture_methods[] = {
    {"start", (PyCFunction) PcapCapture_start, METH_NOARGS, "Start capturing pcaps on self.interface_name and write them to self.output_filename"},
    {NULL}
};

/* custom getter/setter methods to control member types */
static PyObject *
PcapCapture_get_interface_name(PcapCapture *self, void *closure)
{
    Py_INCREF(self->interface_name);
    return self->interface_name;
}

static int
PcapCapture_set_interface_name(PcapCapture *self, PyObject *value, void *closure){
    PyErr_SetString(PyExc_AttributeError, "interface_name attribute is read-only");
    return -1;
}

static PyObject *
PcapCapture_get_output_filename(PcapCapture *self, void *closure)
{
    Py_INCREF(self->output_filename);
    return self->output_filename;
}

static int
PcapCapture_set_output_filename(PcapCapture *self, PyObject *value, void *closure){
    PyErr_SetString(PyExc_AttributeError, "output_filename attribute is read-only");
    return -1;
}

static PyObject *
PcapCapture_get_max_packets(PcapCapture *self, void *closure)
{
    Py_INCREF(self->max_packets);
    return self->max_packets;
}

static int
PcapCapture_set_max_packets(PcapCapture *self, PyObject *value, void *closure){
    PyErr_SetString(PyExc_AttributeError, "max_packets attribute is read-only");
    return -1;
}

static PyObject *
PcapCapture_get_promisc(PcapCapture *self, void *closure)
{
    Py_INCREF(self->promisc);
    return self->promisc;
}

static int
PcapCapture_set_promisc(PcapCapture *self, PyObject *value, void *closure){
    PyErr_SetString(PyExc_AttributeError, "promisc attribute is read-only");
    return -1;
}

static PyObject *
PcapCapture_get_timeout_ms(PcapCapture *self, void *closure)
{
    Py_INCREF(self->timeout_ms);
    return self->timeout_ms;
}

static int
PcapCapture_set_timeout_ms(PcapCapture *self, PyObject *value, void *closure){
    PyErr_SetString(PyExc_AttributeError, "timeout_ms attribute is read-only");
    return -1;
}

static PyObject *
PcapCapture_get_packet_len(PcapCapture *self, void *closure)
{
    Py_INCREF(self->packet_len);
    return self->packet_len;
}

static int
PcapCapture_set_packet_len(PcapCapture *self, PyObject *value, void *closure){
    PyErr_SetString(PyExc_AttributeError, "packet_len attribute is read-only");
    return -1;
}

static PyGetSetDef PcapCapture_getsetters[] = {
    {"interface_name", (getter) PcapCapture_get_interface_name, (setter) PcapCapture_set_interface_name, "interface_name", NULL},
    {"output_filename", (getter) PcapCapture_get_output_filename, (setter) PcapCapture_set_output_filename, "output_filename", NULL},
    {"max_packets", (getter) PcapCapture_get_max_packets, (setter) PcapCapture_set_max_packets, "max_packets", NULL},
    {"promisc", (getter) PcapCapture_get_promisc, (setter) PcapCapture_set_promisc, "promisc", NULL},
    {"timeout_ms", (getter) PcapCapture_get_timeout_ms, (setter) PcapCapture_set_timeout_ms, "timeout_ms", NULL},
    {"packet_length", (getter) PcapCapture_get_packet_len, (setter) PcapCapture_set_packet_len, "packet_length", NULL},
    {NULL}
};

/* avoid cyclic references / enable cyclic GC */
static int
PcapCapture_traverse(PcapCapture *self, visitproc visit, void *arg)
{

    Py_VISIT(self->interface_name);
    Py_VISIT(self->output_filename);
    Py_VISIT(self->max_packets);
    Py_VISIT(self->promisc);
    Py_VISIT(self->timeout_ms);
    Py_VISIT(self->packet_len);

    return 0;
}

static int
PcapCapture_clear(PcapCapture *self)
{
    Py_CLEAR(self->interface_name);
    Py_CLEAR(self->output_filename);
    Py_CLEAR(self->max_packets);
    Py_CLEAR(self->promisc);
    Py_CLEAR(self->timeout_ms);
    Py_CLEAR(self->packet_len);

    return 0;
}

/* deallocation method */
static void
PcapCapture_dealloc(PcapCapture *self)
{
    /* close all C objects */

    /* dealloc with cyclic GC check */
    PyObject_GC_UnTrack(self);
    PcapCapture_clear(self);

    /* deallocate the object itself */
    Py_TYPE(self)->tp_free((PyObject *)self);
}

/*
PcapWriter Type construction

.tp_flags:
    Py_TPFLAGS_DEFAULT = always use
    Py_TPFLAGS_BASETYPE = allows to be subclassed. do this only if methods don't care about type of object created/used
    Py_TPFLAGS_HAVE_GC = cyclic GC causes segfault if this isn't set
*/
static PyTypeObject PcapCaptureType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pypcap.PcapCapture",
    .tp_doc = "Object that captures packets off a given interface",
    .tp_basicsize = sizeof(PcapCapture),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_new = PcapCapture_new,
    .tp_dealloc = (destructor) PcapCapture_dealloc,
    .tp_init = (initproc) PcapCapture_init,
    .tp_members = PcapCapture_members, // expose custom properties as members
    .tp_methods = PcapCapture_methods, // expose custom methods
    .tp_traverse = (traverseproc) PcapCapture_traverse, // cyclic GC enable
    .tp_clear = (inquiry) PcapCapture_clear,
    .tp_getset = PcapCapture_getsetters, // custom getter/setter methods
};
