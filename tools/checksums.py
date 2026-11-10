"""Write the same resource checksums (first 8 hex of MD5) as the engine's nightmarened_checksums hook.

usage: checksums.py OUT.txt
Compare with: diff OUT.txt <engine output>
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import naf  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
NUMBERS = [0, 1000, 86000, 90000, 92000, 93000, 94000, 95000, 96000, 97000, 98000, 99000]


def digest(data):
    return hashlib.md5(bytes(data)).hexdigest()[:8]


def path(n):
    name = 'NED%05d.NAF' % n
    for d in ('reference-files/game-files/data/data', 'extracted/DATA'):
        p = os.path.join(ROOT, d, name)
        if os.path.exists(p):
            return p
    raise FileNotFoundError(name)


def main():
    out = []
    for n in NUMBERS:
        a = naf.Naf(path(n))
        for s, i in a.ids('bmix'):
            w, h, px, pal = naf.background(a.raw('bmix', s, i))
            out.append('%05d bg %d:%d %dx%d %s' % (n, s, i, w, h, digest(px[:w * h])))
        for s, i in a.ids('spix'):
            for k, f in enumerate(naf.sprite_frames(a.raw('spix', s, i))):
                w, h, px, mask = naf.rdx_image(f)
                inter = bytearray(2 * w * h)
                inter[0::2] = bytes(c if m else 0 for c, m in zip(px, mask))
                inter[1::2] = mask
                out.append('%05d spr %d:%d:%d %dx%d %s' % (n, s, i, k, w, h, digest(inter)))
        for s, i in a.ids('auix'):
            out.append('%05d snd %d:%d %d' % (n, s, i, len(a.raw('auix', s, i))))
        print(n, len(out), flush=True)
    open(sys.argv[1], 'w').write('\n'.join(out) + '\n')


if __name__ == '__main__':
    main()
