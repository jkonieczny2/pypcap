#include "util.h"

/* utility method to get strings out of PyUnicode objects */
char *
PyUnicode_ToString(PyObject *obj){
    Py_XINCREF(obj);

    if(!PyUnicode_Check(obj)){
        PyErr_SetString(PyExc_AttributeError, "Cannot obtain a char * from a non-PyUnicode object");
        return NULL;
    }   

    PyObject *ascii_string = PyUnicode_AsASCIIString(obj);
    if(ascii_string == NULL){
        PyErr_SetString(PyExc_AttributeError, "PyUnicode object could not be converted to ASCII");
        return NULL;
    }   

    char *c_str = PyBytes_AsString(ascii_string);
    if(c_str == NULL){
        PyErr_SetString(PyExc_AttributeError, "Error converting PyBytes object to c string");
        return NULL;
    }   

    // clean up references, not 100% sure if this is necessary
    Py_DECREF(obj);
    Py_DECREF(ascii_string);

    return c_str;
}

