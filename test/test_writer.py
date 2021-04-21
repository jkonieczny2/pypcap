import pypcap
import unittest

WRITER = pypcap.PcapWriter(filename='foo')

class TestWriter:
    def test_writer_creation(self):
        writer = pypcap.PcapWriter()
        assert(writer is not None)

    def test_writer_init_noargs(self):
        writer = pypcap.PcapWriter()
        assert(writer.filename == '')

    def test_writer_init_filename(self):
        writer = pypcap.PcapWriter(filename='/home/jkonieczny')
        assert(writer.filename == '/home/jkonieczny')

    def test_writer_init_varargs(self):
        w = pypcap.PcapWriter('/home/jkonieczny')
        assert(w.filename == '/home/jkonieczny')

    def test_writer_name_method(self):
        writer = pypcap.PcapWriter(filename='/home/jkonieczny')
        name = writer.name()
        assert(name == '/home/jkonieczny')

    def test_global_writer(self):
        assert(WRITER.filename == 'foo') 
