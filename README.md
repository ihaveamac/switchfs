# switchfs

FUSE (Filesystem in Userspace) scripts for Nintendo Switch files

In development. Requires Python 3.6.1+ and pycryptodomex. Supports Windows (via WinFsp), macOS (via FUSE for macOS) & Linux.

Speeds slow until Cython support is implemented, or a C backend for crypto.

# Usage
* Install via pip, or use setup.py
* Run `<py-cmd> -m switchfs nand -h` for help output

# Stuff to do
* Use Cython for crypto script
* implement option parsing
* more types
* ...

# License/Credits
`switchfs` is under the MIT license. fusepy is under the ISC license ([taken from `setup.py`](https://github.com/fusepy/fusepy/blob/b5f87a1855119d55c755c2c4c8b1da346365629d/setup.py)).

`switchfs/crypto.py` is taken from @plutooo's [crypto gist](https://gist.github.com/plutooo/fd4b22e7f533e780c1759057095d7896), modified for Python 3 compatibility and optimization.

# Related projects
* [fuse-3ds](https://github.com/ihaveamac/fuse-3ds) - some code shared
