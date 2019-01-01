import logging
import os
from collections import defaultdict
from errno import ENOENT
from math import ceil
from stat import S_IFDIR, S_IFREG
from sys import argv, exit
from typing import TYPE_CHECKING
from zlib import crc32

from crypto import XTSN, parse_biskeydump

from fuse import FUSE, FuseOSError, Operations, LoggingMixIn, fuse_get_context

from . import _common as _c

if TYPE_CHECKING:
    from typing import BinaryIO, List

bis_key_ids = defaultdict(lambda: -1, {
    'PRODINFO': 0,
    'PRODINFOF': 0,
    'SAFE': 1,
    'SYSTEM': 2,
    'USER': 3
})


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
        nand_fp.seek(0x200)
        gpt_header = nand_fp.read(0x5C)
        if gpt_header[0:8] != b'EFI PART':
            exit('GPT header magic not found.')

        header_to_hash = gpt_header[0:0x10] + b'\0\0\0\0' + gpt_header[0x14:]
        crc_expected = int.from_bytes(gpt_header[0x10:0x14], 'little')
        crc_got = crc32(header_to_hash) & 0xFFFFFFFF
        if crc_got != crc_expected:
            exit(f'GPT header crc32 mismatch (expected {crc_expected:08x}, got {crc_got:08x})')

        gpt_part_start = int.from_bytes(gpt_header[0x48:0x50], 'little')
        gpt_part_count = int.from_bytes(gpt_header[0x50:0x54], 'little')
        gpt_part_entry_size = int.from_bytes(gpt_header[0x54:0x58], 'little')

        nand_fp.seek(gpt_part_start * 0x200)
        gpt_part_full_raw = nand_fp.read(gpt_part_count * gpt_part_entry_size)
        gpt_part_crc_expected = int.from_bytes(gpt_header[0x58:0x5C], 'little')
        gpt_part_crc_got = crc32(gpt_part_full_raw) & 0xFFFFFFFF
        if gpt_part_crc_got != gpt_part_crc_expected:
            exit(f'GPT Partition table crc32 mismatch '
                 f'(expected {gpt_part_crc_expected:08x}, got {gpt_part_crc_got:08x})')
        gpt_parts_raw = [gpt_part_full_raw[i:i + gpt_part_entry_size] for i in range(0, len(gpt_part_full_raw),
                                                                                     gpt_part_entry_size)]
        for part in gpt_parts_raw:
            name = part[0x38:].decode('utf-16le').rstrip('\0')
            self.files[f'/{name.lower()}.img'] = {'real_filename': name + '.img', 'bis_key': bis_key_ids[name],
                                                  'start': int.from_bytes(part[0x20:0x28], 'little') * 0x200,
                                                  'end': (int.from_bytes(part[0x28:0x30], 'little') + 1) * 0x200}

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
            p = self.files[path]
            st = {'st_mode': (S_IFREG | (0o444 if self.readonly else 0o666)),
                  'st_size': p['end'] - p['start'], 'st_nlink': 1}
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
        real_offset: int = fi['start'] + offset

        if fi['start'] + offset > fi['end']:
            return b''
        if offset + size > fi['end']:
            size = fi['end'] - offset

        if fi['bis_key'] >= 0:
            before = offset % 0x4000
            aligned_real_offset = real_offset - before
            aligned_offset = offset - before
            aligned_size: int = ceil((size + before) / 0x4000) * 0x4000
            self.f.seek(aligned_real_offset)
            xtsn: XTSN = self.crypto[fi['bis_key']]
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
        # with open('test.bin', 'wb') as o:
        #     o.write(mount.read('/SAFE.img', 0x8000, 0, 0))
        FUSE(mount, a.mount_point, foreground=True, ro=True, nothreads=True,
             fsname=os.path.realpath(a.nand).replace(',', '_'), allow_root=True)
        # allow_root is True by default here to allow mounting on *nix
        # this will be changed once option parsing is copied over
