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
