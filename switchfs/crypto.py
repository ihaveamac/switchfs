from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import List

try:
    # noinspection PyProtectedMember,PyUnresolvedReferences
    from ccrypto import _xtsn_decrypt


    class XTSN:
        def __init__(self, crypt: bytes, tweak: bytes):
            self.crypt = crypt
            self.tweak = tweak

        def decrypt(self, buf: bytes, sector_off: int, sector_size: int = 0x200) -> bytes:
            return _xtsn_decrypt(buf, self.crypt, self.tweak, (sector_off >> 64) & 0xFFFFFFFFFFFFFFFF,
                                 sector_off & 0xFFFFFFFFFFFFFFFF, sector_size)


except ImportError:
    print("Warning: couldn't load ccrypto, loading slower Python module.")

    import struct
    from Cryptodome.Cipher import AES


    def _xor(s1, s2):
        return bytes(a ^ b for a, b in zip(s1, s2))


    # taken from @plutooo's crypto gist (https://gist.github.com/plutooo/fd4b22e7f533e780c1759057095d7896),
    #   modified for Python 3 compatibility and optimization
    class XTSN:
        def __init__(self, crypt: bytes, tweak: bytes):
            self.crypt = crypt
            self.tweak = tweak

            self.c_enc = AES.new(self.tweak, AES.MODE_ECB).encrypt
            self.c_dec = AES.new(self.crypt, AES.MODE_ECB).decrypt

        def __repr__(self):
            return f'XTSN({self.crypt}, {self.tweak})'

        def decrypt(self, buf: bytes, sector_off: int, sector_size: int = 0x200) -> bytes:
            out = bytearray()

            p = struct.Struct('>QQ')

            for i in range(len(buf) // sector_size):
                pos = sector_off + i
                tweak = self.c_enc(p.pack(0, pos))

                for j in range(sector_size // 16):
                    off = i * sector_size + j * 16

                    blk = _xor(self.c_dec(_xor(buf[off:off + 16], tweak)), tweak)

                    tweak = int.from_bytes(tweak, 'little')
                    if tweak & (1 << 127):
                        tweak = ((tweak & ~(1 << 127)) << 1) ^ 0x87
                    else:
                        tweak <<= 1
                    tweak = tweak.to_bytes(16, 'little')

                    out.extend(blk)

            return bytes(out)


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
    return bis_keys
