"""Minimal 8-bit palette PNG writer (stdlib only)."""
import struct
import zlib


def _chunk(tag, data):
    return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag + data) & 0xFFFFFFFF)


def write(path, w, h, px, pal, transparent=None):
    """px: w*h palette indices; pal: 768 bytes RGB (8-bit); transparent: index or None."""
    px = bytes(px).ljust(w * h, b'\0')
    raw = b''.join(b'\0' + px[y * w:(y + 1) * w] for y in range(h))
    out = b'\x89PNG\r\n\x1a\n' + _chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 3, 0, 0, 0))
    out += _chunk(b'PLTE', bytes(pal[:768]).ljust(768, b'\0'))
    if transparent is not None:
        out += _chunk(b'tRNS', b'\xff' * transparent + b'\0')
    out += _chunk(b'IDAT', zlib.compress(raw, 6)) + _chunk(b'IEND', b'')
    open(path, 'wb').write(out)


def vga(raw):
    """Scale a 6-bit VGA DAC palette to 8-bit (left alone if already 8-bit)."""
    scale = 4 if max(raw) < 64 else 1
    return bytes(min(255, c * scale) for c in raw)
