#define PY_SSIZE_T_CLEAN
#include <assert.h>
#include <Python.h>
#include <structmember.h>

typedef struct{
    PyObject_HEAD
    /* type specific fields*/
    PyObject *filename; //name of file to write to
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
    }
    return (PyObject *) self;
}


/* initialization method */
static int
PcapWriter_init(PcapWriter *self, PyObject *args, PyObject *kwds)
{
    static char *kwlist[] = {"filename", NULL};
    PyObject *filename = NULL, *tmp;

    if(!PyArg_ParseTupleAndKeywords(args, kwds, "|U", kwlist, &filename)){ // pipe separates varags from kwargs
        return -1;
    }

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

/* expose attributes as custom members */
static PyMemberDef PcapWriter_members[] = {
//    {"filename", T_OBJECT_EX, offsetof(PcapWriter, filename), 0, "filename"},
    {NULL}
};

/* expose methods */
static PyMethodDef PcapWriter_methods[] = {
    {"name", (PyCFunction) PcapWriter_name, METH_NOARGS, "Returns filename of PcapWriter object"},
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

static PyGetSetDef PcapWriter_getsetters[] = { 
    {"filename", (getter) PcapWriter_get_filename, (setter) PcapWriter_set_filename, "filename", NULL},
    {NULL}
};

/* avoid cyclic references / enable cyclic GC */
static int
PcapWriter_traverse(PcapWriter *self, visitproc visit, void *arg)
{
    Py_VISIT(self->filename);
    return 0;
}

static int
PcapWriter_clear(PcapWriter *self)
{
    Py_CLEAR(self->filename);
    return 0;
}

/* deallocation method */
static void
PcapWriter_dealloc(PcapWriter *self)
{
    /* deallocate all Python objects on the class */
    //Py_XDECREF(self->filename); // always needs to be null-safe.  may have failed to set in tp_new

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
