#!/usr/bin/python3
import pypcap
import os

if __name__ == '__main__':
    print(pypcap.find_all_devs())

    filename = 'foo.txt'
    fh = pypcap.pcap_writer(filename, 'w')
    fh.write('bar')
    fh.close()

    text = open(filename).read()
    try:
        assert(text=='bar')
    except AssertionError as e:
        print('File contents do not match expected')
    finally:
        os.remove(filename)
