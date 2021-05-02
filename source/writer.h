#define PY_SSIZE_T_CLEAN
#include <assert.h>
#include <Python.h>
#include <string.h>
#include <structmember.h>
#include <stdio.h>
#include "reader.h"

#define LINKTYPE_ETHERNET 1
#define MAX_PACKET_SIZE 65536

typedef struct{
    PyObject_HEAD
    /* type specific fields*/    
    FILE *fp;
    PyObject *stream;
    pcap_t *_pcap;
    pcap_dumper_t *_pcap_dumper;
} PcapWriter;

/* creation method */
static PyObject *
PcapWriter_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PcapWriter *self;
    self = (PcapWriter *) type->tp_alloc(type,0);
    return (PyObject *) self;
}

/* initialization method */
static int
PcapWriter_init(PcapWriter *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"stream", NULL};
    PyObject *stream=NULL, *tmp;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &stream)){
        return -1;
    }

    // create file pointer
    int fd = PyObject_AsFileDescriptor(stream);
    FILE *fp = fdopen(fd, "wb");
    if(fp == NULL){
        PyErr_SetString(PyExc_SystemError, "Could not open file object for writing");
        return -1;
    }
    self->fp = fp;

    // create pcap writer
    pcap_t *pcap;
    pcap_dumper_t *pcap_dumper;
    pcap = pcap_open_dead_with_tstamp_precision(LINKTYPE_ETHERNET, MAX_PACKET_SIZE, PCAP_TSTAMP_PRECISION_NANO);

    if(pcap == NULL){
        PyErr_SetString(PyExc_SystemError, "Could not open pcap object for writing");
        return -1;
    }
    self->_pcap = pcap;

    // create pcap dumper
    pcap_dumper = pcap_dump_fopen(pcap, self->fp);
    if(pcap_dumper == NULL){
        PyErr_SetString(PyExc_SystemError, "Could not create pcap file writer");
        return -1;
    }
    self->_pcap_dumper = pcap_dumper;

    // set pyobject attributes
    if(stream){
        tmp = self->stream;
        Py_INCREF(stream);
        self->stream = stream;
        Py_XDECREF(tmp);
    }

    return 0;
}

/* write method */
static PyObject * // cannot return 0 for a Py C function, lol
PcapWriter_write(PcapWriter *self, PyObject *args)
{
    if(self->fp == NULL)
        return PyErr_Format(PyExc_SystemError, "Cannot perform write operation on closed file");

    PyObject *py_bytes = NULL;
    if(!PyArg_ParseTuple(args, "O", &py_bytes)){
        PyErr_SetString(PyExc_AttributeError, "Could not parse arguments to write() method");
        return NULL;
    }

    if(!PyBytes_Check(py_bytes)){
        PyErr_SetString(PyExc_AttributeError, "write method requires a Bytes-like argument");
        return NULL;
    }

    // get size of buffer
    Py_ssize_t size = PyBytes_Size(py_bytes);
    // allocate buffer
    char *buf = PyBytes_AsString(py_bytes);
    // write to the file
    fwrite(buf, size, 1, self->fp);

    return PyLong_FromSsize_t(size);
}

/* write from PcapReader */
static PyObject *
PcapWriter_write_from_pcap_reader(PcapWriter *self, PyObject *args){
    if(self->fp == NULL)
        return PyErr_Format(PyExc_SystemError, "Cannot perform write operation on closed file");

    // obtain PcapReader argument
    PcapReader *pcap_reader;
    if(!PyArg_ParseTuple(args, "O", &pcap_reader)){
        PyErr_SetString(PyExc_ValueError, "write_from_pcap_reader method requires a PcapReader argument");
        return NULL;
    }
    // TODO: check that pcap_reader is a PcapReader object
    Py_INCREF(pcap_reader);

    // copy reader to writer
    pcap_t *pcap = pcap_reader->_pcap;
    if(pcap == NULL){
        PyErr_SetString(PyExc_SystemError, "PcapReader object is not open for reading");
        return NULL;
    }

    struct pcap_pkthdr pkt_header;
    const uint8_t *packetData;
    long pkt_count = 0;

    while((packetData = pcap_next(pcap, &pkt_header))){
        pcap_dump((uint8_t *)self->_pcap_dumper, &pkt_header, packetData);
        pkt_count++;
    }

    return PyLong_FromLong(pkt_count);
}

/* fileno of open file */
static PyObject *
PcapWriter_fileno(PcapWriter *self, PyObject *Py_UNUSED(ignored))
{
    if(self->fp == NULL){
        PyErr_SetString(PyExc_SystemError, "Cannot obtain fileno, file is already closed");
        return NULL;
    }

    int fd = fileno(self->fp);
    return PyLong_FromLong((long) fd);
}

/* close method */
static PyObject *
PcapWriter_close(PcapWriter *self, PyObject *Py_UNUSED(ignored))
{
    if(self->_pcap_dumper == NULL)
        return Py_BuildValue("");

    pcap_dump_close(self->_pcap_dumper);
    self->_pcap_dumper = NULL;
    self->_pcap = NULL;
    self->fp = NULL;

    return Py_BuildValue(""); // return None
}

/* expose attributes as custom members */
static PyMemberDef PcapWriter_members[] = {
    {NULL}
};

/* expose methods */
static PyMethodDef PcapWriter_methods[] = {
    {"close", (PyCFunction) PcapWriter_close, METH_NOARGS, "Close the object's file pointer"},
    {"write", (PyCFunction) PcapWriter_write, METH_VARARGS, "Write PyBytes object to file"},
    {"write_from_pcap_reader", (PyCFunction) PcapWriter_write_from_pcap_reader, METH_VARARGS, "Write a PcapReader object to file"},
    {"fileno", (PyCFunction) PcapWriter_fileno, METH_VARARGS, "Get file descriptor attached to open file"},
    {NULL}
};

/* custom getter/setter methods to control member types */
static PyObject *
PcapWriter_get_closed(PcapWriter *self, PyObject *value, void *closure)
{
    int _closed = (self->fp == NULL);
    return PyBool_FromLong((long) _closed); // we don't incref because creation implies refcount=1
}

static int
PcapWriter_set_closed(PcapWriter *self, PyObject *value, void *closure)
{
    PyErr_SetString(PyExc_AttributeError, "closed attribute is read-only");
    return -1;
}

static PyObject *
PcapWriter_get_stream(PcapWriter *self, void *closure){
    Py_INCREF(self->stream);
    return self->stream;
}

static int
PcapWriter_set_stream(PcapWriter *self, PyObject *value, void *closure){
    PyErr_SetString(PyExc_AttributeError, "closed attribute is read-only");
    return -1;
}

static PyGetSetDef PcapWriter_getsetters[] = {
    {"stream", (getter) PcapWriter_get_stream, (setter) PcapWriter_set_stream, "stream", NULL},
    {"closed", (getter) PcapWriter_get_closed, (setter) PcapWriter_set_closed, "closed", NULL},
    {NULL}
};

/* avoid cyclic references / enable cyclic GC */
static int
PcapWriter_traverse(PcapWriter *self, visitproc visit, void *arg)
{
    Py_VISIT(self->stream);
    return 0;
}

static int
PcapWriter_clear(PcapWriter *self)
{
    Py_CLEAR(self->stream);
    return 0;
}

/* deallocation method */
static void
PcapWriter_dealloc(PcapWriter *self)
{
    /* close the file pointer */
    if(self->fp != NULL)
        fclose(self->fp);

    /* dealloc with cyclic GC check */
    PyObject_GC_UnTrack(self);
    PcapWriter_clear(self);

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
static PyTypeObject PcapWriterType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pypcap.PcapWriter",
    .tp_doc = "Stream-like object that writes pcaps to file",
    .tp_basicsize = sizeof(PcapWriter),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_new = PcapWriter_new,
    .tp_dealloc = (destructor) PcapWriter_dealloc,
    .tp_init = (initproc) PcapWriter_init,
    .tp_members = PcapWriter_members, // expose custom properties as members
    .tp_methods = PcapWriter_methods, // expose custom methods
    .tp_traverse = (traverseproc) PcapWriter_traverse, // cyclic GC enable
    .tp_clear = (inquiry) PcapWriter_clear,
    .tp_getset = PcapWriter_getsetters, // custom getter/setter methods
};
