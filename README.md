# switchfs

FUSE (Filesystem in Userspace) scripts for Nintendo Switch files

In development. Requires Python 3.6.1+. Supports Windows (via [WinFsp](http://www.secfs.net/winfsp/)), macOS (via [FUSE for macOS](https://osxfuse.github.io)) & Linux.

NAND currently requires a keys text file from biskeydump.

# Known issues
* None currently

# Usage
* Install Python 3.6.1 or later.
* Install development tools:
  * Windows: Install [Visual C++ Build Tools](http://landinghub.visualstudio.com/visual-cpp-build-tools)
  * macOS: Install Xcode command line tools (`xcode-select --install`)
  * Linux: Install `python3-dev` (or similar) via your package manager
* Install repo via pip, or clone/download and use `python3 setup.py install`
* Run `<py-cmd> -m switchfs nand -h` for help output
  * `<py-cmd>` is `py -3` on Windows, `python3` on macOS/Linux

# Stuff to do
* implement option parsing
* more types
* release binaries with pre-compiled extensions
* ...

# License/Credits
`switchfs` is under the MIT license. fusepy is under the ISC license ([taken from `setup.py`](https://github.com/fusepy/fusepy/blob/b5f87a1855119d55c755c2c4c8b1da346365629d/setup.py)).

`switchfs/aes.c` and `switchfs/aes.h` are from @kokke's [tiny-AES-C](https://github.com/kokke/tiny-AES-c) commit `ee68cb8`, and uses The Unlicense.

`switchfs/crypto.py` AES-XTS part is taken from @plutooo's [crypto gist](https://gist.github.com/plutooo/fd4b22e7f533e780c1759057095d7896), modified for Python 3 compatibility and optimization.

`switchfs/ccrypto.c` AES-XTS part is by @luigoalma, based on @plutooo's gist above; Python module implementation by me(@ihaveamac).

# Related projects
* [fuse-3ds](https://github.com/ihaveamac/fuse-3ds) - some code shared
