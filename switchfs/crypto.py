from sys import exit
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import List

try:
    # noinspection PyProtectedMember
    from .ccrypto import _xtsn_schedule, _xtsn_decrypt, _xtsn_encrypt
except ImportError:
    try:
        from ccrypto import _xtsn_schedule, _xtsn_decrypt, _xtsn_encrypt
    except ImportError:
        exit("Couldn't load ccrypto. The extension needs to be compiled.")
        # never reached, just to shut up the ide
        _xtsn_schedule = None
        _xtsn_decrypt = None
        _xtsn_encrypt = None


class XTSN:
    def __init__(self, crypt: bytes, tweak: bytes):
        self.roundkeys_x2 = _xtsn_schedule(crypt, tweak)

    def decrypt(self, buf: bytes, sector_off: int, sector_size: int = 0x200, skipped_bytes: int = 0) -> bytes:
        return _xtsn_decrypt(buf, self.roundkeys_x2, 0, sector_off, sector_size, skipped_bytes)

    def decrypt_long(self, buf: bytes, sector_off: int, sector_size: int = 0x200, skipped_bytes: int = 0) -> bytes:
        return _xtsn_decrypt(buf, self.roundkeys_x2, (sector_off >> 64) & 0xFFFFFFFFFFFFFFFF,
                             sector_off & 0xFFFFFFFFFFFFFFFF, sector_size, skipped_bytes)

    def encrypt(self, buf: bytes, sector_off: int, sector_size: int = 0x200, skipped_bytes: int = 0) -> bytes:
        return _xtsn_encrypt(buf, self.roundkeys_x2, 0, sector_off, sector_size, skipped_bytes)

    def encrypt_long(self, buf: bytes, sector_off: int, sector_size: int = 0x200, skipped_bytes: int = 0) -> bytes:
        return _xtsn_encrypt(buf, self.roundkeys_x2, (sector_off >> 64) & 0xFFFFFFFFFFFFFFFF,
                             sector_off & 0xFFFFFFFFFFFFFFFF, sector_size, skipped_bytes)


def parse_biskeydump(keys: str):
    bis_keys: List[List[bytes]] = [[None, None], [None, None], [None, None], [None, None]]
    for l in keys.splitlines():
        if l.startswith('BIS KEY'):
            data = l.split()[2:]
            key_idx = int(data[0])
            key_type = data[1][1:-2]
            if key_type not in {'crypt', 'tweak'}:
                raise RuntimeError('unknown type')  # TODO: give this a special error
            bis_keys[key_idx][0 if key_type == 'crypt' else 1] = bytes.fromhex(data[2])
        elif l.startswith('bis_key'):
            keyinfo, key = l.split(" = ")
            key_idx = int(keyinfo.split("_")[2])
            bis_keys[key_idx][0] = bytes.fromhex(key[:32])
            bis_keys[key_idx][1] = bytes.fromhex(key[32:])
    return bis_keys
