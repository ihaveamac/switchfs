import logging
import os
from errno import ENOENT
from math import ceil
from stat import S_IFDIR, S_IFREG
from sys import argv
from typing import TYPE_CHECKING

from crypto import XTSN, parse_biskeydump

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn, fuse_get_context

from . import _common as _c

if TYPE_CHECKING:
    from typing import BinaryIO, List

# TODO: gpt parsing instead of hard-coding offsets
enc_partitions = {
    'PRODINFO': (0, 0x4400, 0x3FBC00),
    'PRODINFOF': (0, 0x400000, 0x400000),
    'BCPKG2-1-Normal-Main': (-1, 0x800000, 0x800000),
    'BCPKG2-2-Normal-Sub': (-1, 0x1000000, 0x800000),
    'BCPKG2-3-SafeMode-Main': (-1, 0x1800000, 0x800000),
    'BCPKG2-4-SafeMode-Sub': (-1, 0x2000000, 0x800000),
    'BCPKG2-5-Repair-Main': (-1, 0x2800000, 0x800000),
    'BCPKG2-6-Repair-Sub': (-1, 0x3000000, 0x800000),
    'SAFE': (1, 0x3800000, 0x4000000),
    'SYSTEM': (2, 0x7800000, 0xA0000000),
    'USER': (3, 0xA7800000, 0x680000000)
}


# TODO: writing?


class NANDImageMount(LoggingMixIn, Operations):
    fd = 0

    def __init__(self, nand_fp: 'BinaryIO', g_stat: os.stat_result, keys: str, readonly: bool = True):
        self.readonly = readonly
        self.g_stat = {'st_ctime': int(g_stat.st_ctime), 'st_mtime': int(g_stat.st_mtime),
                       'st_atime': int(g_stat.st_atime)}

        bis_keys = parse_biskeydump(keys)
        self.crypto: List[XTSN] = [None] * 4
        for x in range(4):
            self.crypto[x] = XTSN(*bis_keys[x])

        self.files = {}
        for n, o in enc_partitions.items():
            self.files[f'/{n.lower()}.img'] = {'real_filename': n + '.img', 'offset': o[1], 'size': o[2],
                                               'bis_key': o[0]}

        self.f = nand_fp

    def __del__(self, *args):
        try:
            self.f.close()
        except AttributeError:
            pass

    destroy = __del__

    @_c.ensure_lower_path
    def getattr(self, path: str, fh=None):
        uid, gid, pid = fuse_get_context()
        if path == '/':
            st = {'st_mode': (S_IFDIR | (0o555 if self.readonly else 0o777)), 'st_nlink': 2}
        elif path in self.files:
            st = {'st_mode': (S_IFREG | (0o444 if self.readonly else 0o666)),
                  'st_size': self.files[path]['size'], 'st_nlink': 1}
        else:
            raise FuseOSError(ENOENT)
        return {**st, **self.g_stat, 'st_uid': uid, 'st_gid': gid}

    def open(self, path: str, flags):
        self.fd += 1
        return self.fd

    @_c.ensure_lower_path
    def readdir(self, path: str, fh):
        yield from ('.', '..')
        yield from (x['real_filename'] for x in self.files.values())

    @_c.ensure_lower_path
    def read(self, path: str, size: int, offset: int, fh):
        fi = self.files[path]
        real_offset: int = fi['offset'] + offset

        if fi['offset'] + offset > fi['offset'] + fi['size']:
            return b''
        if offset + size > fi['size']:
            size = fi['size'] - offset

        if fi['bis_key'] >= 0:
            before = offset % 0x4000
            aligned_real_offset = real_offset - before
            aligned_offset = offset - before
            aligned_size: int = ceil((size + before) / 0x4000) * 0x4000
            self.f.seek(aligned_real_offset)
            xtsn = self.crypto[fi['bis_key']]
            sector_offset = aligned_offset // 0x4000
            # noinspection PyTypeChecker
            return xtsn.decrypt(self.f.read(ceil(aligned_size / 0x4000) * 0x4000), sector_offset, 0x4000)[
                   before:before + size]

        else:
            self.f.seek(real_offset)
            return self.f.read(size)

    # TODO: get the real nand size, instead of hard-coding it
    @_c.ensure_lower_path
    def statfs(self, path: str):
        return {'f_bsize': 4096, 'f_blocks': 0x747C00000 // 4096, 'f_bavail': 0, 'f_bfree': 0,
                'f_files': len(self.files)}


def main(prog: str = None, args: list = None):
    from argparse import ArgumentParser
    if args is None:
        args = argv[1:]
    parser = ArgumentParser(prog=prog, description='Mount Nintendo Switch NAND images. Read-only for now.')
    parser.add_argument('--keys', help='Keys text file from biskeydump.')
    parser.add_argument('nand', help='NAND image')
    parser.add_argument('mount_point', help='mount point')

    a = parser.parse_args(args)

    nand_stat = os.stat(a.nand)

    with open(a.nand, 'rb') as f, open(a.keys, 'r', encoding='utf-8') as k:
        mount = NANDImageMount(nand_fp=f, g_stat=nand_stat, keys=k.read())
        FUSE(mount, a.mount_point, foreground=True, ro=True, nothreads=True,
             fsname=os.path.realpath(a.nand).replace(',', '_'), allow_root=True)
        # allow_root is True by default here to allow mounting on *nix
        # this will be changed once option parsing is copied over
