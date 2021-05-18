#!/usr/bin/python3
from pprint import pprint
import pypcap

if __name__ == '__main__':
    devs = pypcap.find_all_devs()
    pprint(devs)
