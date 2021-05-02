import pypcap
import unittest
import os

FILENAME = 'foo'

class TestWriter(unittest.TestCase):
    def setUp(self):
        self.f = FILENAME

    def open_file(self):
        return open(self.f, 'wb')

    def create_writer(self):
        fp = self.open_file()
        writer = pypcap.PcapWriter(fp)
        return writer

    def tearDown(self):
        os.remove(self.f)

    def test_create(self):
        fp = self.open_file()
        writer = pypcap.PcapWriter(fp)
        assert(not writer.closed)
        assert(writer.stream == fp)

    def test_close(self):
        writer = self.create_writer()
        writer.close()
        assert(writer.closed)
        writer.close() # calling twice should be OK

    def test_write(self):
        writer = self.create_writer()
        txt = b"foobar"
        written = writer.write(txt)
        assert(written == len(txt))

        writer.close()
        assert(writer.closed)

        read = open(self.f, 'rb').read()
        assert(read == txt)
