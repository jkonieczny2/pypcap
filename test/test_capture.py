import pypcap
import unittest
import os
import subprocess

class TestCapture(unittest.TestCase):
    def test_create(self):
        c = pypcap.PcapCapture(
            "lo",
            "foo.pcap",
            10000,
        )

        assert(c.interface_name == "lo")
        assert(c.output_filename == "foo.pcap")
        assert(c.max_packets == 10000)
        assert(c.promisc == False)
        assert(c.timeout_ms == 1000)
        assert(c.packet_length == 65535)

