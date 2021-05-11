import pypcap
import unittest
import os
import subprocess

FILENAME = 'foo'
PCAP_FILE = 'pcap_test.pcap'

class TestWriter(unittest.TestCase):
    def setUp(self):
        self.d = os.path.dirname(__file__)
        self.f = os.path.join(self.d, FILENAME)
        self.p = os.path.join(self.d, PCAP_FILE)

        reader = self.create_reader()
        self.exp_count = reader.read()
        reader.close()

    def open_file(self):
        return open(self.f, 'wb')

    def open_pcap_file(self):
        return open(self.p, 'rb')

    def create_writer(self):
        fp = self.open_file()
        writer = pypcap.PcapWriter(fp)
        return writer

    def create_reader(self):
        fp = self.open_pcap_file()
        reader = pypcap.PcapReader(fp)
        return reader

    def tearDown(self):
        if os.path.exists(self.f):
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

        # this won't work
        # incoming header is micros, outgoing is nanos
#        read = open(self.f, 'rb').read()
#        assert(read == txt)

    def test_write_from_pcap_reader(self, debug=False):
        if not debug:
            writer = self.create_writer()
        else:
            path = os.path.join(self.d, 'writer.pcap')
            writer = pypcap.PcapWriter(open(path, 'wb'))

        reader = self.create_reader()

        res = writer.write_from_pcap_reader(reader)
        assert(res == self.exp_count)

        # check file contents
        # unfotunately not b-for-b same, headers may diff
        writer.close()
        reader.close()

        w = pypcap.PcapReader(open(self.f, 'rb'))
        r = pypcap.PcapReader(open(self.p, 'rb'))
        assert(w.read() == r.read())

    def test_write_multiple_files(self):
        writer = self.create_writer()
        reader = self.create_reader()

        res = writer.write_from_pcap_reader(reader)

        reader.close()
        reader = self.create_reader()
        res2 = writer.write_from_pcap_reader(reader)

        writer.close()
        final = pypcap.PcapReader(open(self.f, 'rb'))
        pkt_count = final.read()
        e_pkt_count = res + res2
        assert(pkt_count == e_pkt_count)

    def test_subprocess(self):
        """
        Test that PcapWriter can read from stdout correctly
        """
        cmd = [ 
            'cat',
            self.p
        ]

        p_read = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        reader = pypcap.PcapReader(p_read.stdout)

        fd = p_read.stdout.fileno()
        p_fd = reader.fileno()

        writer = self.create_writer()
        res = writer.write_from_pcap_reader(reader)

        assert(res == self.exp_count)

    def test_open_in_w_mode(self):
        def open_w():
            fp = open(self.f, 'w')
            writer = pypcap.PcapWriter(fp)

        self.assertRaises(AttributeError, open_w)

    def test_context(self):
        def bad_close():
            with open(self.f, 'wb') as fh:
                writer = pypcap.PcapWriter(fh)
                writer.close()
        self.assertRaises(OSError, bad_close)

