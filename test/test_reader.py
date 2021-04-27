import pypcap
import unittest
import os

DEFAULT_MODE = 'rb'
FILENAME = 'pcap_test.pcap'


class TestWriter(unittest.TestCase):
    def setUp(self):
        # create the file we'll be testing
        self.f = os.path.join(
            os.path.dirname(__file__),
            FILENAME,
        )
        self.default_mode = DEFAULT_MODE

    def create_reader(self):
        r = pypcap.PcapReader(open(self.f))
        return r

    def test_pcap_exists(self):
        assert(os.path.exists(self.f))

    def test_reader(self):
        r = self.create_reader()
        assert(isinstance(r.fileno(), int))
        assert(r.fileno() > 2)
        assert(not r.closed)

    def test_reader_close(self):
        r = self.create_reader()
        r.close()
        assert(r.closed)

    def test_reader_set_closed(self):
        def set_closed():
            r = self.create_reader()
            r.closed = False
        self.assertRaises(AttributeError, set_closed)
