import pypcap
import unittest

WRITER = pypcap.PcapWriter('foo')
DEFAULT_MODE = 'wb'

class TestWriter(unittest.TestCase):
    def test_writer_creation(self):
        writer = pypcap.PcapWriter('foo')
        assert(writer is not None)
        assert(writer.mode == DEFAULT_MODE)

    def test_writer_with_kwargs(self):
        writer = pypcap.PcapWriter(filename='foo')
        assert(writer.filename == 'foo')

    def test_writer_init_varargs(self):
        w = pypcap.PcapWriter('foo')
        assert(w.filename == 'foo')

    def test_writer_name_method(self):
        writer = pypcap.PcapWriter('foo')
        name = writer.name()
        assert(name == 'foo')

    def test_global_writer(self):
        assert(WRITER.filename == 'foo')

    def test_close(self):
        writer = pypcap.PcapWriter('foo')
        assert(writer.closed == False)
        writer.close()

        assert(writer.filename == 'foo')
        assert(writer.mode == 'wb')
        assert(writer.closed == True)

    def test_error_on_failed_open(self):
        def open_bad_file():
            w = pypcap.PcapWriter('')
        self.assertRaises(SystemError, open_bad_file)

    def test_write_string(self):
        """ this should raise an error but not segfault """
        def write_string():
            w = pypcap.PcapWriter('foo')
            w.write("123")
        self.assertRaises(AttributeError, write_string)

    def test_write_int(self):
        """ this should raise an error but not segfault """
        def write_int():
            w = pypcap.PcapWriter('foo')
            w.write(123)
        self.assertRaises(AttributeError, write_int)

    def test_write_bytes(self):
        w = pypcap.PcapWriter('foo')
        to_write = b"bar"
        written = w.write(to_write)
        assert(written == len(to_write))

    def test_getfileno_file(self):
        w = pypcap.PcapWriter('foo')
        f = open('bar', 'w')
        fd = w.getfileno(f)
        assert(isinstance(fd, int))
        assert(fd > 2)

    def test_getfileno_string(self):
        """ should raise error but not segfault """
        def string_fileno():
            w = pypcap.PcapWriter('foo')
            return w.getfileno("bar")
        self.assertRaises(AttributeError, string_fileno)

    def test_getfileno_int(self):
        """ passing int to getfileno should just return the int """
        w = pypcap.PcapWriter('foo')
        i = 12
        fd = w.getfileno(i)
        assert(fd == i)
        
