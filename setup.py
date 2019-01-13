#!/usr/bin/env python3

import sys

from setuptools import setup, Extension

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
    ext_modules=[Extension('switchfs.ccrypto', sources=['switchfs/ccrypto.cpp', 'switchfs/aes.cpp'],
                           extra_compile_args=['/Ox' if sys.platform == 'win32' else '-O3',
                           '' if sys.platform == 'win32' else '-std=c++11'])]
)
