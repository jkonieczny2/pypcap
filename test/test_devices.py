import pypcap
import unittest
import os
import subprocess

DEFAULT_MODE = 'rb'
FILENAME = 'pcap_test.pcap'
PACKET_COUNT = 764 # so happens that packet count was 764

class TestDevices(unittest.TestCase):
    def test_find_all_devs(self):
        exp_keys = ['name', 'description', 'flags']
        devices = pypcap.find_all_devs()
        for dev_name, dev_details in devices.items():
            for e in exp_keys:
                assert(e in dev_details)
