#define PY_SSIZE_T_CLEAN
#include <assert.h>
#include <Python.h>
#include <string.h>
#include <structmember.h>
#include <pcap.h>

typedef struct{
    PyObject_HEAD
    /* type specific fields*/
    const char *_filename;
    const char *_mode;
    char *_errbuf;
    PyObject *filename;
    PyObject *mode;
    FILE *fp;
    pcap_t *_pcap;
} PcapReader;

/* creation method */
static PyObject *
PcapReader_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PcapReader *self;
    self = (PcapReader *) type->tp_alloc(type,0);
    if (self != NULL) {
        /* init members to default, if desired */
        self->filename = PyUnicode_FromString("");
        if(self->filename == NULL) {
            Py_DECREF(self);
            return NULL;
        }
        self->mode = PyUnicode_FromString("wb");
        if(self->mode == NULL){
            Py_DECREF(self);
            return NULL;
        }
    }
    return (PyObject *) self;
}

/* initialization method */
static int
PcapReader_init(PcapReader *self, PyObject *args, PyObject *kwds)
{
    char *f;
    const char m[] = "rb"; // for now, we only support wb mode

    static char *kwlist[] = {"filename", NULL};
    PyObject *filename = NULL, *mode=NULL, *tmp;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &f)){
        return -1;
    }

    self->_filename = f;
    self->_mode = m;

    // create file pointer
    FILE *fp;
    if(!strcmp(f, "-")){
        fp = fdopen(0, m);
    } else{
        fp = fopen(f, m);
    }

    if(fp == NULL){
        PyErr_Format(PyExc_SystemError, "Could not open file '%s' for reading", self->_filename);
        return -1;
    }
    self->fp = fp;

    // create pcap reader
    char errbuf[PCAP_ERRBUF_SIZE];
    self->_errbuf = errbuf;
    pcap_t *pcap = pcap_fopen_offline_with_tstamp_precision(fp, PCAP_TSTAMP_PRECISION_NANO, self->_errbuf);

    if(pcap == NULL){
        PyErr_Format(PyExc_SystemError, "Could not create pcap reader for '%s': '%s'", self->_filename, self->_errbuf);
        return -1;
    }
    self->_pcap = pcap;

    // set PyObject attributes
    filename = PyUnicode_FromString(f);
    if(filename){
        tmp = self->filename;
        Py_INCREF(filename);
        self->filename = filename;
        Py_DECREF(tmp);
    }

    mode = PyUnicode_FromString(m);
    if(mode){
        tmp = self->mode;
        Py_INCREF(mode);
        self->mode = mode;
        Py_DECREF(tmp);
    }

    return 0;
}

/* close method */
static PyObject * // cannot return 0 for a Py C function, lol
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
        PyErr_Format(PyExc_SystemError, "Cannot obtain fileno for file '%s'; is already closed", self->_filename);
        return NULL;
    }

    int fd = fileno(self->fp);
    return PyLong_FromLong(fd);
}

/* expose attributes as custom members */
static PyMemberDef PcapReader_members[] = {
    {NULL}
};

/* expose methods */
static PyMethodDef PcapReader_methods[] = {
    {"close", (PyCFunction) PcapReader_close, METH_NOARGS, "Close the object's file pointer"},
    {"fileno", (PyCFunction) PcapReader_fileno, METH_NOARGS, "Return file descriptor number of PcapReader object"},
    {NULL}
};

/* custom getter/setter methods to control member types */
static PyObject *
PcapReader_get_filename(PcapReader *self, void *closure)
{
    Py_INCREF(self->filename);
    return self->filename;
}

static int PcapReader_set_filename(PcapReader *self, PyObject *value, void *closure)
{
    PyErr_SetString(PyExc_TypeError, "filename attribute can only be set on initialization");
    return -1;

    PyObject *tmp;

    /* prevent people from making attribute pointer NULL */
    if(value == NULL) {
        PyErr_SetString(PyExc_TypeError, "Cannot delete filename attribute");
        return -1; 
    }   

    if(!PyUnicode_Check(value)) {
        PyErr_SetString(PyExc_TypeError, "filename attribute must be a string");
        return -1; 
    }   
    tmp = self->filename;
    Py_INCREF(value);
    self->filename = value;
    Py_DECREF(tmp);
    return 0;
}

static PyObject *
PcapReader_get_mode(PcapReader *self, void *closure)
{
    Py_INCREF(self->mode);
    return self->mode;
}

static int PcapReader_set_mode(PcapReader *self, PyObject *value, void *closure)
{
    PyErr_SetString(PyExc_TypeError, "mode attribute can only be set on initialization");
    return -1;
}

static PyObject *
PcapReader_get_closed(PcapReader *self, PyObject *value, void *closure)
{
    int _closed = (self->fp == NULL);
    return PyBool_FromLong((long) _closed); // we don't incref because creation implies refcount=1
}

static int PcapReader_set_closed(PcapReader *self, PyObject *value, void *closure)
{
    PyErr_SetString(PyExc_AttributeError, "closed attribute is read-only");
    return -1;
}

static PyGetSetDef PcapReader_getsetters[] = { 
    {"filename", (getter) PcapReader_get_filename, (setter) PcapReader_set_filename, "filename", NULL},
    {"mode", (getter) PcapReader_get_mode, (setter) PcapReader_set_mode, "mode", NULL},
    {"closed", (getter) PcapReader_get_closed, (setter) PcapReader_set_closed, "closed", NULL},
    {NULL}
};

/* avoid cyclic references / enable cyclic GC */
static int
PcapReader_traverse(PcapReader *self, visitproc visit, void *arg)
{
    Py_VISIT(self->filename);
    Py_VISIT(self->mode);
    return 0;
}

static int
PcapReader_clear(PcapReader *self)
{
    Py_CLEAR(self->filename);
    Py_CLEAR(self->mode);
    return 0;
}

/* deallocation method */
static void
PcapReader_dealloc(PcapReader *self)
{
    /* close the pcap pointer */
    if(self->_pcap != NULL)
        pcap_close(self->_pcap);

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
//    .tp_new = PyType_GenericNew, // don't really need custom tp_new
    .tp_new = PcapReader_new,
    .tp_dealloc = (destructor) PcapReader_dealloc,
    .tp_init = (initproc) PcapReader_init,
    .tp_members = PcapReader_members, // expose custom properties as members
    .tp_methods = PcapReader_methods, // expose custom methods
    .tp_traverse = (traverseproc) PcapReader_traverse, // cyclic GC enable
    .tp_clear = (inquiry) PcapReader_clear,
    .tp_getset = PcapReader_getsetters, // custom getter/setter methods
};
