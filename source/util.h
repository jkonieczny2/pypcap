#define PY_SSIZE_T_CLEAN
#include <Python.h>

/*
convert a PyUnicode object to a C string
*/
char *PyUnicode_ToString(PyObject *obj);

