#define PY_SSIZE_T_CLEAN
#include <assert.h>
#include <Python.h>
#include <string.h>
#include <structmember.h>

typedef struct{
    PyObject_HEAD
    /* type specific fields*/
    const char *_c_filename;  // store c string filename
    const char *_c_mode; // store c file open mode
    PyObject *filename; //name of file to write to
    PyObject *mode;
    FILE *fp;
} PcapWriter;

/* creation method */
static PyObject *
PcapWriter_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
    PcapWriter *self;
    self = (PcapWriter *) type->tp_alloc(type,0);
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
PcapWriter_init(PcapWriter *self, PyObject *args, PyObject *kwds)
{
    char *f;
    const char m[] = "wb"; // for now, we only support wb mode

    static char *kwlist[] = {"filename", NULL};
    PyObject *filename = NULL, *mode=NULL, *tmp;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "s", kwlist, &f)){
        return -1;
    }

    self->_c_filename = f;
    self->_c_mode = m;

    // create file pointer
    FILE *fp;
    if(!strcmp(f, "-")){
        fp = fdopen(1, m); // write to stdout
    } else{
        fp = fopen(f, m);
    }
    if(fp == NULL){
        PyErr_Format(PyExc_SystemError, "Could not open file '%s'", self->_c_filename);
        return -1;
    }
    self->fp = fp;

    // set PyObject attributes
    filename = PyUnicode_FromString(f);
    if(filename){
        /*
        when initializing custom members, copy existing to temp var
        this avoids arbitrary code from modifying the member while we assign
        */
        tmp = self->filename;
        Py_INCREF(filename);
        self->filename = filename;
        Py_DECREF(tmp); // getter/setter ensure this is never NULL, so no need to use XDECREF
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

/* random custom function for demo purposes */
static PyObject *
PcapWriter_name(PcapWriter *self, PyObject *Py_UNUSED(ignored))
{
    if(self->filename == NULL) {
        PyErr_SetString(PyExc_AttributeError, "filename");
        return NULL;
    }
    return PyUnicode_FromFormat("%S", self->filename);
}

/* write method */
static PyObject * // cannot return 0 for a Py C function, lol
PcapWriter_write(PcapWriter *self, PyObject *args)
{
    if(self->fp == NULL)
        return PyErr_Format(PyExc_SystemError, "Cannot perform write operation on closed file '%S'", self->filename);

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

static PyObject *
PcapWriter_getfileno(PcapWriter *self, PyObject *args)
{
    PyObject *buf;
    if(!PyArg_ParseTuple(args, "O", &buf)){
        PyErr_SetString(PyExc_AttributeError, "Error parsing arguments for getfileno() method");
        return NULL;
    }

    int fd = PyObject_AsFileDescriptor(buf);
    if(fd == -1){
        PyErr_SetString(PyExc_AttributeError, "Could not determine file descriptor for object");
        return NULL;
    }

    return PyLong_FromLong((long) fd);
}

/* close method */
static PyObject * // cannot return 0 for a Py C function, lol
PcapWriter_close(PcapWriter *self, PyObject *Py_UNUSED(ignored))
{
    if(self->fp == NULL)
        return Py_BuildValue("");

    int i = fclose(self->fp);
    if(i !=0 ){
        PyErr_Format(PyExc_SystemError, "Could not close file '%S'", self->filename);
        return 0;
    }

    self->fp = NULL;
    return Py_BuildValue(""); // return None
}

/* expose attributes as custom members */
static PyMemberDef PcapWriter_members[] = {
    {NULL}
};

/* expose methods */
static PyMethodDef PcapWriter_methods[] = {
    {"name", (PyCFunction) PcapWriter_name, METH_NOARGS, "Returns filename of PcapWriter object"},
    {"close", (PyCFunction) PcapWriter_close, METH_NOARGS, "Close the object's file pointer"},
    {"write", (PyCFunction) PcapWriter_write, METH_VARARGS, "Write PyBytes object to file"},
    {"getfileno", (PyCFunction) PcapWriter_getfileno, METH_VARARGS, "Get file descriptor attached to an object"},
    {NULL}
};

/* custom getter/setter methods to control member types */
static PyObject *
PcapWriter_get_filename(PcapWriter *self, void *closure)
{
    Py_INCREF(self->filename);
    return self->filename;
}

static int PcapWriter_set_filename(PcapWriter *self, PyObject *value, void *closure)
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
PcapWriter_get_mode(PcapWriter *self, void *closure)
{
    Py_INCREF(self->mode);
    return self->mode;
}

static int PcapWriter_set_mode(PcapWriter *self, PyObject *value, void *closure)
{
    PyErr_SetString(PyExc_TypeError, "mode attribute can only be set on initialization");
    return -1;
}

static PyObject *
PcapWriter_get_closed(PcapWriter *self, PyObject *value, void *closure)
{
    int _closed = (self->fp == NULL);
    return PyBool_FromLong((long) _closed); // we don't incref because creation implies refcount=1
}

static int PcapWriter_set_closed(PcapWriter *self, PyObject *value, void *closure)
{
    PyErr_SetString(PyExc_AttributeError, "closed attribute is read-only");
    return -1;
}

static PyGetSetDef PcapWriter_getsetters[] = { 
    {"filename", (getter) PcapWriter_get_filename, (setter) PcapWriter_set_filename, "filename", NULL},
    {"mode", (getter) PcapWriter_get_mode, (setter) PcapWriter_set_mode, "mode", NULL},
    {"closed", (getter) PcapWriter_get_closed, (setter) PcapWriter_set_closed, "closed", NULL},
    {NULL}
};

/* avoid cyclic references / enable cyclic GC */
static int
PcapWriter_traverse(PcapWriter *self, visitproc visit, void *arg)
{
    Py_VISIT(self->filename);
    Py_VISIT(self->mode);
    return 0;
}

static int
PcapWriter_clear(PcapWriter *self)
{
    Py_CLEAR(self->filename);
    Py_CLEAR(self->mode);
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
//    .tp_new = PyType_GenericNew, // don't really need custom tp_new
    .tp_new = PcapWriter_new,
    .tp_dealloc = (destructor) PcapWriter_dealloc,
    .tp_init = (initproc) PcapWriter_init,
    .tp_members = PcapWriter_members, // expose custom properties as members
    .tp_methods = PcapWriter_methods, // expose custom methods
    .tp_traverse = (traverseproc) PcapWriter_traverse, // cyclic GC enable
    .tp_clear = (inquiry) PcapWriter_clear,
    .tp_getset = PcapWriter_getsetters, // custom getter/setter methods
};
