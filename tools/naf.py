"""Nightmare Ned NAF archive reader (RIFF 'NNAF').

Layout (NITENED.EXE FUN_00456600):
  head   0x98 bytes (+8 first scene, +12 last scene), then u32 count + count u32 scene ids
  xsdt / dsdt   raw record blobs, indexed by xsix / dsix
  NNdt   bulk data; index offsets are absolute file offsets
  ??ix   u32 slots; i32 first[nscenes]; i32 last[nscenes]; (u32 off, u32 size)[slots];
         then for each listed scene: u16 slot[last-first+1] (0xffff = none)
Resources are addressed by (scene, id).
"""
import struct


class Index:
    def __init__(self, buf, lo, hi, scenes):
        n = hi - lo + 1
        self.slots = struct.unpack_from('<I', buf, 0)[0]
        self.first = struct.unpack_from('<%di' % n, buf, 4)
        self.last = struct.unpack_from('<%di' % n, buf, 4 + 4 * n)
        p = 4 + 8 * n
        self.entries = [struct.unpack_from('<II', buf, p + 8 * i) for i in range(self.slots)]
        p += 8 * self.slots
        self.map = {}
        for s in scenes:
            # Every listed scene has a table, even an empty one (first = last = -1)
            f, l = self.first[s - lo], self.last[s - lo]
            cnt = l - f + 1
            ids = struct.unpack_from('<%dH' % cnt, buf, p)
            p += 2 * cnt
            if f < 0:
                continue
            for k, slot in enumerate(ids):
                if slot != 0xFFFF:
                    self.map[(s, f + k)] = slot
        self.tail = len(buf) - p


class Naf:
    def __init__(self, path):
        self.path = path
        with open(path, 'rb') as f:
            self.data = f.read()
        d = self.data
        if d[:4] != b'RIFF' or d[8:12] != b'NNAF':
            raise ValueError('not a NAF file')
        self.chunks = []
        off = 12
        while off + 8 <= len(d):
            tag = d[off:off + 4].decode('latin1')
            size = struct.unpack_from('<I', d, off + 4)[0]
            self.chunks.append((tag, off + 8, size))
            off += 8 + size + (size & 1)
        c = {t: (o, s) for t, o, s in self.chunks}
        ho = c['head'][0]
        self.lo, self.hi = struct.unpack_from('<ii', d, ho + 8)
        n = struct.unpack_from('<I', d, ho + 0x98)[0]
        self.scenes = list(struct.unpack_from('<%dI' % n, d, ho + 0x9C))
        self.index = {}
        for t, o, s in self.chunks:
            if t.endswith('ix'):
                self.index[t] = Index(d[o:o + s], self.lo, self.hi, self.scenes)

    def entry(self, ix, scene, rid):
        idx = self.index[ix]
        slot = idx.map[(scene, rid)]
        return idx.entries[slot]

    def raw(self, ix, scene, rid):
        off, size = self.entry(ix, scene, rid)
        return self.data[off:off + size]

    def ids(self, ix):
        return sorted(self.index[ix].map) if ix in self.index else []


def lzw(src, outsize):
    """LZ78 codec of FUN_0048a750: MSB-first LZW, 9-bit start, 0x100 end, 0x101 widen, 0x102 reset."""
    out = bytearray()
    pos = 0
    bitbuf = 0
    bitcnt = 0
    n = len(src)

    def read(w):
        nonlocal pos, bitbuf, bitcnt
        while bitcnt < w:
            bitbuf = (bitbuf << 8) | (src[pos] if pos < n else 0)
            pos += 1
            bitcnt += 8
        bitcnt -= w
        v = bitbuf >> bitcnt
        bitbuf &= (1 << bitcnt) - 1
        return v

    while True:
        table = [bytes([i]) for i in range(256)] + [b'', b'', b'']
        width = 9
        c = read(width)
        if c == 0x100:
            return bytes(out)
        prev = table[c]
        out += prev
        while True:
            c = read(width)
            if c == 0x100 or len(out) >= outsize:
                return bytes(out[:outsize])
            if c == 0x102:
                break
            if c == 0x101:
                width += 1
                continue
            if c < len(table):
                cur = table[c]
            else:
                cur = prev + prev[:1]
            out += cur
            table.append(prev + cur[:1])
            prev = cur


SPRITE_GUID = bytes.fromhex('805a8a9c1837d011bf2000a0c91a2629')


def container(blob):
    """'cC' container (TRPS = sprite bank, KCAB = background) -> (header dict, decoded payload)."""
    if blob[:2] != b'cC':
        raise ValueError('not a cC container')
    kind = blob[4:8][::-1].decode('latin1')
    na, nb = struct.unpack_from('<HH', blob, 8)
    codec = blob[12:16][::-1].decode('latin1')
    hsize, hoff, doff = struct.unpack_from('<III', blob, 0x10)
    off, size = struct.unpack_from('<II', blob, 0x1c)
    hdr = blob[hoff:hoff + hsize]
    if codec == 'LZ78':
        payload = lzw(blob[off:off + size], 1 << 26)
    else:
        payload = blob[off:off + size]
    return {'kind': kind, 'codec': codec, 'na': na, 'nb': nb, 'hdr': hdr}, payload


def background(blob):
    """bmix entry -> (w, h, pixels, palette768 or None)."""
    info, px = container(blob)
    w, h, bpp = struct.unpack_from('<HHH', info['hdr'], 0)
    pal = None
    if len(info['hdr']) >= 10 + 1024:
        p = info['hdr'][10:10 + 1024]
        pal = b''.join(p[4 * i:4 * i + 3] for i in range(256))
    return w, h, px, pal


def sprite_frames(slot):
    """spix entry (u32 unpacked size + cC bank) -> list of RDX compressed images."""
    if len(slot) < 0x28:
        return []
    info, px = container(slot[4:])
    n = px.find(SPRITE_GUID) // 4
    sizes = struct.unpack_from('<%dI' % n, px, 0)
    out, p = [], 4 * n
    for s in sizes:
        out.append(px[p:p + s])
        p += s
    return out


def rdx_image(f):
    """Decode an RDX compressed image (Dino2d FUN_100018f0 opcodes) -> (w, h, pixels, mask).

    ops: 00 n skip | 01 n c c c c run | 02 n lit[n] | 03 n k col[k] mask.. 00 (LSB-first bits)
         04 end of row | 05 end of image
    """
    if f[:16] != SPRITE_GUID:
        raise ValueError('not an RDX compressed image')
    w, h = struct.unpack_from('<II', f, 16)
    p = 44
    out = bytearray(w * h)
    mask = bytearray(w * h)
    x = y = 0
    while True:
        op = f[p]
        o = y * w + x
        if op == 5:
            break
        if op == 0:
            x += f[p + 1]
            p += 2
        elif op == 1:
            n = f[p + 1]
            out[o:o + n] = bytes([f[p + 2]]) * n
            mask[o:o + n] = b'\1' * n
            x += n
            p += 6
        elif op == 2:
            n = f[p + 1]
            out[o:o + n] = f[p + 2:p + 2 + n]
            mask[o:o + n] = b'\1' * n
            x += n
            p += 2 + n
        elif op == 3:
            n, k = f[p + 1], f[p + 2]
            cols = f[p + 3:p + 3 + k]
            q = p + 3 + k
            m = sh = 0
            while f[q]:
                m |= f[q] << sh
                sh += 8
                q += 1
            ci = 0
            for i in range(n):
                if m >> i & 1:
                    out[o + i] = cols[ci]
                    mask[o + i] = 1
                    ci += 1
            x += n
            p = q + 1
        elif op == 4:
            if x != w:
                raise ValueError('row %d is %d wide, not %d' % (y, x, w))
            y += 1
            x = 0
            p += 1
        else:
            raise ValueError('bad op %02x' % op)
    return w, h, bytes(out), bytes(mask)


def wave(slot):
    """auix entry: WAVEFORMATEX (18 bytes) + PCM -> RIFF WAVE bytes."""
    fmt, pcm = slot[:16], slot[18:]
    return (b'RIFF' + struct.pack('<I', 36 + len(pcm)) + b'WAVEfmt ' + struct.pack('<I', 16) + fmt
            + b'data' + struct.pack('<I', len(pcm)) + pcm)
