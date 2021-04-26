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

    def test_pcap_exists(self):
        assert(os.path.exists(self.f))

    def test_reader(self):
        r = pypcap.PcapReader(self.f)
        assert(r.filename == self.f)
        assert(r.mode == self.default_mode)
        assert(not r.closed)

    def test_reader_close(self):
        r = pypcap.PcapReader(self.f)
        r.close()
        assert(r.closed)

    def test_reader_set_closed(self):
        def set_closed():
            r = pypcap.PcapReader(self.f)
            r.closed = False
        self.assertRaises(AttributeError, set_closed)

    def test_fileno(self):
        r = pypcap.PcapReader(self.f)
        c_fd = r.fileno()
        assert(isinstance(c_fd, int))
        assert(c_fd > 2)

    def not_yet_test_fileno_stdin(self): # doesn't work because stdin doesn't have pcaps in it yet
        r = pypcap.PcapReader('-')
        c_fd = r.fileno()
        assert(c_fd == 0)

