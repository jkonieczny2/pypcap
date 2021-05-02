from distutils.core import setup, Extension

pypcap = Extension(
    'pypcap',
    sources=[
        'source/pypcap.c',
        'source/util.c',
    ],
    libraries=['pcap'],
)

setup(
    name="pypcap",
    version='0.0',
    description='python wrapper around pcap library',
    ext_modules=[pypcap],
)
