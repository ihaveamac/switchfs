#!/usr/bin/env python3

import sys

from setuptools import setup
try:
    from Cython.Build import cythonize  # this has to be manually installed before somehow...
except ImportError:
    sys.exit("Couldn't import Cython to build extensions, please install via pip.")

if sys.hexversion < 0x030601f0:
    sys.exit('Python 3.6.1+ is required.')

with open('README.md', 'r', encoding='utf-8') as f:
    readme = f.read()

setup(
    name='switchfs',
    version='0.1.dev0',
    packages=['switchfs', 'switchfs.mount'],
    url='https://github.com/ihaveamac/switchfs',
    license='MIT',
    author='Ian Burgwin',
    author_email='',
    description='FUSE (Filesystem in Userspace) scripts for Nintendo Switch files',
    classifiers=[
        'Topic :: Utilities',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ],
    install_requires=['pycryptodomex', 'Cython'],
    ext_modules=cythonize('switchfs/ccrypto.pyx')
)
