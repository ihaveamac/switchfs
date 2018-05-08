#!/usr/bin/env python3

from importlib import import_module
from os.path import basename, dirname, realpath
from sys import exit, argv, path, platform, hexversion, version_info

windows = platform in {'win32', 'cygwin'}

python_cmd = 'py -3' if windows else 'python3'

mount_types = ('nand',)
mount_aliases = {}

_path = dirname(realpath(__file__))
if _path not in path:
    path.insert(0, _path)

from __init__ import __version__ as version

# this should stay as str.format so it runs on older versions
print('switchfs v{} - https://github.com/ihaveamac/switchfs'.format(version))

if hexversion < 0x030601F0:
    exit('Python {0[0]}.{0[1]}.{0[2]} is not supported. Please use Python 3.6.1 or later.'.format(version_info))


def exit_print_types():
    print('Please provide a mount type as the first argument.')
    print(' ', ', '.join(mount_types))
    exit(1)


def mount(mount_type: str, return_doc: bool = False) -> int:
    if windows:
        from ctypes import windll
        if windll.shell32.IsUserAnAdmin():
            print('- Note: This should *not* be run as an administrator.',
                  '- The mount will not be normally accessible.',
                  '- This should be run from a non-administrator command prompt or PowerShell prompt.', sep='\n')
    else:
        try:
            from os import getuid
            if getuid() == 0:  # 0 == root on macos and linux
                print('- Note: This should *not* be run as root.',
                      '- The mount will not be normally accessible by other users.',
                      '- This should be run from a non-root terminal.',
                      '- If you want root to be able to access the mount,',
                      '-   you can add `-o allow_root` to the arguments.', sep='\n')
        except (AttributeError, ImportError):
            pass
    if mount_type not in mount_types and mount_type not in mount_aliases:
        exit_print_types()

    module = import_module('mount.' + mount_aliases.get(mount_type, mount_type))
    if return_doc:
        return module.__doc__

    prog = None
    if __name__ != '__main__':
        prog = 'mount_' + mount_aliases.get(mount_type, mount_type)
    try:
        return module.main(prog=prog)
    except RuntimeError as e:
        if e.args == (1,):
            pass  # assuming failed to mount and the reason would be displayed in the terminal


def main():
    exit(mount(basename(argv[0])[6:].lower()))


if __name__ == '__main__':
    # path fun times

    if len(argv) < 2:
        exit_print_types()

    exit(mount(argv.pop(1).lower()))
