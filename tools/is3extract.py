"""InstallShield 3 .z archive lister/extractor (PKWare DCL 'blast' inside).

usage: is3extract.py ARCHIVE [OUTDIR] [--list] [--only SUBSTR]
"""
import os
import struct
import sys

MAXBITS = 13

LITLEN = bytes([
    11, 124, 8, 7, 28, 7, 188, 13, 76, 4, 10, 8, 12, 10, 12, 10, 8, 23, 8,
    9, 7, 6, 7, 8, 7, 6, 55, 8, 23, 24, 12, 11, 7, 9, 11, 12, 6, 7, 22, 5,
    7, 24, 6, 11, 9, 6, 7, 22, 7, 11, 38, 7, 9, 8, 25, 11, 8, 11, 9, 12,
    8, 12, 5, 38, 5, 38, 5, 11, 7, 5, 6, 21, 6, 10, 53, 8, 7, 24, 10, 27,
    44, 253, 253, 253, 252, 252, 252, 13, 12, 45, 12, 45, 12, 61, 12, 45,
    44, 173])
LENLEN = bytes([2, 35, 36, 53, 38, 23])
DISTLEN = bytes([2, 20, 53, 230, 247, 151, 248])
BASE = [3, 2, 4, 5, 6, 7, 8, 9, 10, 12, 16, 24, 40, 72, 136, 264]
EXTRA = [0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8]


def build(rep):
    """Return a table indexed by the next MAXBITS stream bits -> (sym, len)."""
    lengths = []
    for b in rep:
        lengths += [b & 15] * ((b >> 4) + 1)
    count = [0] * (MAXBITS + 1)
    for l in lengths:
        count[l] += 1
    count[0] = 0
    code = 0
    nextcode = [0] * (MAXBITS + 2)
    for l in range(1, MAXBITS + 1):
        nextcode[l] = code
        code = (code + count[l]) << 1
    table = [None] * (1 << MAXBITS)
    for sym, l in enumerate(lengths):
        if not l:
            continue
        c = nextcode[l]
        nextcode[l] += 1
        # codes are bit-inverted and read MSB-first from an LSB-first stream
        raw = 0
        for i in range(l):
            bit = ((c >> (l - 1 - i)) & 1) ^ 1
            raw |= bit << i
        for hi in range(1 << (MAXBITS - l)):
            table[raw | (hi << l)] = (sym, l)
    return table


LITCODE = build(LITLEN)
LENCODE = build(LENLEN)
DISTCODE = build(DISTLEN)


def blast(data):
    pos = 0
    bitbuf = 0
    bitcnt = 0
    n = len(data)
    out = bytearray()

    def need(k):
        nonlocal pos, bitbuf, bitcnt
        while bitcnt < k:
            b = data[pos] if pos < n else 0
            pos += 1
            bitbuf |= b << bitcnt
            bitcnt += 8

    def bits(k):
        nonlocal bitbuf, bitcnt
        need(k)
        v = bitbuf & ((1 << k) - 1)
        bitbuf >>= k
        bitcnt -= k
        return v

    def decode(table):
        nonlocal bitbuf, bitcnt
        need(MAXBITS)
        ent = table[bitbuf & ((1 << MAXBITS) - 1)]
        if ent is None:
            raise ValueError('bad code')
        sym, l = ent
        bitbuf >>= l
        bitcnt -= l
        return sym

    lit = bits(8)
    dct = bits(8)
    if lit > 1 or not 4 <= dct <= 6:
        raise ValueError('bad header %d %d' % (lit, dct))
    while True:
        if bits(1):
            sym = decode(LENCODE)
            length = BASE[sym] + bits(EXTRA[sym])
            if length == 519:
                break
            s = 2 if length == 2 else dct
            dist = (decode(DISTCODE) << s) + bits(s) + 1
            start = len(out) - dist
            if start < 0:
                raise ValueError('distance too far')
            if dist >= length:
                out += out[start:start + length]
            else:
                for i in range(length):
                    out.append(out[start + i])
        else:
            out.append(decode(LITCODE) if lit else bits(8))
    return bytes(out)


def entries(buf):
    if struct.unpack_from('<I', buf, 0)[0] != 0x8C655D13:
        raise ValueError('not an IS3 archive')
    nfiles = struct.unpack_from('<H', buf, 0x0C)[0]
    table = struct.unpack_from('<I', buf, 0x29)[0]
    ndirs = struct.unpack_from('<H', buf, 0x31)[0]
    p = table
    dirs = []
    for _ in range(ndirs):
        cnt, chunk, nl = struct.unpack_from('<HHH', buf, p)
        dirs.append((buf[p + 6:p + 6 + nl].decode('latin1'), cnt))
        p += chunk
    out = []
    for d, cnt in dirs:
        for _ in range(cnt):
            usize, csize, off = struct.unpack_from('<III', buf, p + 3)
            chunk = struct.unpack_from('<H', buf, p + 0x17)[0]
            nl = buf[p + 0x1D]
            name = buf[p + 0x1E:p + 0x1E + nl].decode('latin1')
            out.append((d, name, usize, csize, off))
            p += chunk
    assert len(out) == nfiles, (len(out), nfiles)
    return out


def main():
    args = sys.argv[1:]
    only = None
    if '--only' in args:
        i = args.index('--only')
        only = args[i + 1].lower()
        del args[i:i + 2]
    listing = '--list' in args
    args = [a for a in args if a != '--list']
    with open(args[0], 'rb') as f:
        buf = f.read()
    for d, name, usize, csize, off in entries(buf):
        rel = os.path.join(d, name) if d else name
        if only and only not in rel.lower():
            continue
        if listing or len(args) < 2:
            print('%10d %10d  %s' % (usize, csize, rel))
            continue
        data = blast(buf[off:off + csize])
        if len(data) != usize:
            print('SIZE MISMATCH', rel, len(data), usize)
        dst = os.path.join(args[1], rel.replace('\\', os.sep))
        os.makedirs(os.path.dirname(dst) or '.', exist_ok=True)
        with open(dst, 'wb') as f:
            f.write(data)
        print('%10d  %s' % (len(data), rel), flush=True)


if __name__ == '__main__':
    main()
