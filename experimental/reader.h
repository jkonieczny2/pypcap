#define PY_SSIZE_T_CLEAN
#include <assert.h>
#include <Python.h>
#include <string.h>
#include <structmember.h>
#include <pcap.h>
#include <errno.h>
#include "util.h"

typedef struct{
    PyObject_HEAD
    /* type specific fields*/
    char *filename;
    char *_errbuf;
    FILE *fp;
    pcap_t *_pcap;
} PcapReader;

/* creation method */
static PyObject *
PcapReader_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PcapReader *self;
    self = (PcapReader *) type->tp_alloc(type,0);
    return (PyObject *) self;
}

/* initialization method */
static int
PcapReader_init(PcapReader *self, PyObject *args, PyObject *kwds)
{
    PyObject *filename=NULL, *tmp;

    static char *kwlist[] = {"filename", NULL};

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "O", kwlist, &filename)){
        return -1;
    }

    // get filename from passed object
    if(!PyUnicode_Check(filename)){
        PyErr_SetString(PyExc_ValueError, "Argument 'filename' must be a string");
        return -1;
    }

    char *_filename = PyUnicode_ToString(filename);
    if(_filename == NULL){
        PyErr_SetString(PyExc_ValueError, "Could not convert filename to a c string");
        return -1;
    }
 
    // create file pointer
    FILE *fp = fopen(_filename, "rb");
    if(fp == NULL){
        PyErr_SetString(PyExc_SystemError, "Could not open file object for reading");
        return -1;
    }
    self->fp = fp;

    // create pcap reader
    char errbuf[PCAP_ERRBUF_SIZE];
    self->_errbuf = errbuf;
    pcap_t *pcap = pcap_fopen_offline_with_tstamp_precision(fp, PCAP_TSTAMP_PRECISION_NANO, self->_errbuf);

    if(pcap == NULL){
        PyErr_SetString(PyExc_SystemError, "Could not create pcap reader for file object");
        return -1;
    }
    self->_pcap = pcap;

    // Set PyObject attributes
    if(filename){
        tmp = self->filename;
        Py_INCREF(filename);
        self->filename = filename;
        Py_XDECREF(tmp); // didn't set this to default in _new, so need XDECREF
    }

    return 0;
}

/* close method */
static PyObject *
PcapReader_close(PcapReader *self, PyObject *Py_UNUSED(ignored))
{
    if(self->fp == NULL)
        return Py_BuildValue("");

    pcap_close(self->_pcap); // todo: check errno, errbuf if this fails
    self->_pcap = NULL;
    self->fp = NULL;

    return Py_BuildValue(""); // return None
}

/* get fileno of pcap reader */
static PyObject *
PcapReader_fileno(PcapReader *self, PyObject *Py_UNUSED(ignored))
{
    if(self->fp == NULL){
        PyErr_SetString(PyExc_SystemError, "Cannot obtain fileno, file is already closed.");
        return NULL;
    }

    int fd = fileno(self->fp);
    return PyLong_FromLong(fd);
}

/* read file */
static PyObject *
PcapReader_read(PcapReader *self, PyObject *Py_UNUSED(ignored))
{
    if(self->_pcap == NULL){
        PyErr_SetString(PyExc_SystemError, "Cannot read; pcap reader is already closed.");
        return NULL;
    }   

    long pcap_count = 0;
    struct pcap_pkthdr pktHeader;

    while(pcap_next(self->_pcap, &pktHeader)){
        pcap_count++; // somehow this is fine with stdout, but not with an open PyFile obj
    }   

    return PyLong_FromLong(pcap_count);
}

/* expose attributes as custom members */
static PyMemberDef PcapReader_members[] = {
    {"_pcap", T_OBJECT_EX, offsetof(PcapReader, _pcap), 0, "pcap_t *pcap pointer"},
    {NULL}
};

/* expose methods */
static PyMethodDef PcapReader_methods[] = {
    {"close", (PyCFunction) PcapReader_close, METH_NOARGS, "Close the object's file pointer"},
    {"fileno", (PyCFunction) PcapReader_fileno, METH_NOARGS, "Return file descriptor number of PcapReader object"},
    {"read", (PyCFunction) PcapReader_read, METH_NOARGS, "Read pcap file"},
    {NULL}
};

/* getters and setters */
static PyObject *
PcapReader_get_closed(PcapReader *self, void *closure)
{
    int _closed = (self->fp == NULL);
    return PyBool_FromLong((long) _closed); // we don't incref because creation implies refcount=1
}

static int PcapReader_set_closed(PcapReader *self, PyObject *value, void *closure)
{
    PyErr_SetString(PyExc_AttributeError, "closed attribute is read-only");
    return -1;
}

static PyObject *
PcapReader_get_filename(PcapReader *self, PyObject *value, void *closure)
{
    Py_INCREF(self->filename);
    return self->filename;
}

static int
PcapReader_set_filename(PcapReader *self, void *closure)
{
    PyErr_SetString(PyExc_AttributeError, "filename attribute is read-only");
    return -1;
}

static PyGetSetDef PcapReader_getsetters[] = { 
    {"closed", (getter) PcapReader_get_closed, (setter) PcapReader_set_closed, "closed", NULL},
    {"filename", (getter) PcapReader_get_filename, (setter) PcapReader_set_filename, "filename", NULL},
    {NULL}
};

/* avoid cyclic references / enable cyclic GC */
static int
PcapReader_traverse(PcapReader *self, visitproc visit, void *arg)
{
    Py_VISIT(self->filename);
    return 0;
}

static int
PcapReader_clear(PcapReader *self)
{
    Py_CLEAR(self->filename);
    return 0;
}

/* deallocation method */
static void
PcapReader_dealloc(PcapReader *self)
{
    /* close the pcap pointer */
    if(self->_pcap != NULL){
        pcap_close(self->_pcap);
        self->_pcap = NULL;
        self->fp = NULL;
    }

    /* dealloc with cyclic GC check */
    PyObject_GC_UnTrack(self);
    PcapReader_clear(self);

    /* deallocate the object itself */
    Py_TYPE(self)->tp_free((PyObject *)self);
}

/*
PcapReader Type construction

.tp_flags:
    Py_TPFLAGS_DEFAULT = always use
    Py_TPFLAGS_BASETYPE = allows to be subclassed. do this only if methods don't care about type of object created/used
    Py_TPFLAGS_HAVE_GC = cyclic GC causes segfault if this isn't set
*/
static PyTypeObject PcapReaderType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "pypcap.PcapReader",
    .tp_doc = "Stream-like object that reads pcap files",
    .tp_basicsize = sizeof(PcapReader),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_GC,
    .tp_new = PcapReader_new,
    .tp_dealloc = (destructor) PcapReader_dealloc,
    .tp_init = (initproc) PcapReader_init,
    .tp_members = PcapReader_members, // expose custom properties as members
    .tp_methods = PcapReader_methods, // expose custom methods
    .tp_traverse = (traverseproc) PcapReader_traverse, // cyclic GC enable
    .tp_clear = (inquiry) PcapReader_clear,
    .tp_getset = PcapReader_getsetters, // custom getter/setter methods
};
