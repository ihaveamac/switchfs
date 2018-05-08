import struct

from Cryptodome.Cipher import AES


def xor(s1, s2):
    return bytes(a ^ b for a, b in zip(s1, s2))


# taken from @plutooo's crypto gist (https://gist.github.com/plutooo/fd4b22e7f533e780c1759057095d7896),
#   modified for Python 3 compatibility and optimization
class XTSN:
    def __init__(self, crypt, tweak):
        self.crypt = crypt
        self.tweak = tweak

        self.c_enc = AES.new(self.tweak, AES.MODE_ECB).encrypt
        self.c_dec = AES.new(self.crypt, AES.MODE_ECB).decrypt

    def __repr__(self):
        return f'XTSN({self.crypt}, {self.tweak})'

    def decrypt(self, buf, sector_off, sector_size=0x200):
        out = bytearray()

        for i in range(len(buf) // sector_size):
            pos = sector_off + i
            tweak = self.c_enc(struct.pack('>QQ', (pos >> 64) & 0xffffffffffffffff, pos & 0xffffffffffffffff))

            for j in range(sector_size // 16):
                off = i * sector_size + j * 16

                blk = xor(self.c_dec(xor(buf[off:off + 16], tweak)), tweak)

                tweak = int.from_bytes(tweak, 'little')
                if tweak & (1 << 127):
                    tweak = ((tweak & ~(1 << 127)) << 1) ^ 0x87
                else:
                    tweak <<= 1
                tweak = tweak.to_bytes(16, 'little')

                out.extend(blk)

        return out


def parse_biskeydump(keys):
    bis_keys = [[None, None], [None, None], [None, None], [None, None]]
    for l in keys.splitlines():
        if l.startswith('BIS KEY'):
            data = l.split()[2:]
            key_idx = int(data[0])
            key_type = data[1][1:-2]
            if key_type not in {'crypt', 'tweak'}:
                raise RuntimeError('unknown type')  # TODO: give this a special error
            bis_keys[key_idx][0 if key_type == 'crypt' else 1] = bytes.fromhex(data[2])
    return bis_keys
