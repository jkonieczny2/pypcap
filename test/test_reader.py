import pypcap
import unittest
import os
import subprocess

DEFAULT_MODE = 'rb'
FILENAME = 'pcap_test.pcap'
PACKET_COUNT = 764 # so happens that packet count was 764

class TestWriter(unittest.TestCase):
    def setUp(self):
        # create the file we'll be testing
        self.f = os.path.join(
            os.path.dirname(__file__),
            FILENAME,
        )
        self.default_mode = DEFAULT_MODE

    def create_reader(self):
        with open(self.f, 'rb') as fp:
            r = pypcap.PcapReader(fp)
        return r

    def test_pcap_exists(self):
        assert(os.path.exists(self.f))

    def test_reader(self):
        r = self.create_reader()
        assert(isinstance(r.fileno(), int))
        assert(r.fileno() > 2)
        assert(not r.closed)

    def test_count(self):
        r = pypcap.PcapReader(open(self.f, 'rb'))
        assert(r.read() == 764) # somehow this is returning 22.  why???

    def test_reader_close(self):
        r = self.create_reader()
        r.close()
        assert(r.closed)

    def test_reader_set_closed(self):
        def set_closed():
            r = self.create_reader()
            r.closed = False
        self.assertRaises(AttributeError, set_closed)

    def test_subprocess(self):
        """
        Whole reason i am doing this
        So that the pcap reader can read from stdout
        """
        cmd = [
            'cat',
            self.f
        ]

        p_read = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        reader = pypcap.PcapReader(p_read.stdout)

        fd = p_read.stdout.fileno()
        p_fd = reader.fileno()
#        assert(fd == p_fd)
        assert(reader.read() == PACKET_COUNT)

    def test_open_in_r_mode(self):
        def open_r():
            fp = open(self.f, 'r')
            reader = pypcap.PcapReader(fp)
        self.assertRaises(AttributeError, open_r)

