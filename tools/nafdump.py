"""Dump every resource in Nightmare Ned NAF archives.

usage: nafdump.py OUTDIR NAF [NAF...]

Per NAF -> OUTDIR/<name>/
  bg/<scene>_<id>.png        backgrounds (own palette)
  spr/<scene>_<id>_<f>.png   sprite frames (palette of the scene's first full background)
  snd/<scene>_<id>.wav       sounds
  seq.json, hit.json         xsdt animation sequences, dsdt hit boxes (raw fields)
  cb/<scene>_<id>.bin        cbix collision blobs (raw)
  index.json                 every resource with offset/size and decode result
"""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import naf  # noqa: E402
import png8  # noqa: E402

GREY = bytes(c for i in range(256) for c in (i, i, i))


def seq_record(b):
    magic, ver, kind, sprite, a, n, rate = struct.unpack_from('<HHHHHHI', b, 0)
    vals = list(struct.unpack_from('<%dH' % ((len(b) - 16) // 2), b, 16))
    return {'ver': ver, 'kind': kind, 'sprite': sprite, 'a': a, 'frames': n, 'rate': rate, 'data': vals}


def hit_record(b):
    magic, ver, n, w, h, k, ax, ay = struct.unpack_from('<2s7H', b, 0)
    frames = []
    for i in range(n):
        o = 0x10 + 0x68 * i
        if o + 0x68 > len(b):
            break
        head = struct.unpack_from('<4h', b, o)
        rects = [struct.unpack_from('<4i', b, o + 8 + 16 * r) for r in range(6)]
        rects = [r if r[0] != -0x7fff else None for r in rects]
        frames.append({'head': head, 'a': rects[:3], 'b': rects[3:]})
    return {'magic': magic.decode('latin1'), 'ver': ver, 'w': w, 'h': h, 'k': k, 'anchor': [ax, ay],
            'frames': frames}


def dump(path, outdir):
    a = naf.Naf(path)
    name = os.path.splitext(os.path.basename(path))[0]
    root = os.path.join(outdir, name)
    for sub in ('bg', 'spr', 'snd', 'cb'):
        os.makedirs(os.path.join(root, sub), exist_ok=True)
    index = {'scenes': a.scenes, 'chunks': [(t, o, s) for t, o, s in a.chunks], 'res': []}
    pals = {}
    stats = {'bg': 0, 'spr': 0, 'frames': 0, 'snd': 0, 'cb': 0, 'seq': 0, 'hit': 0, 'errors': 0}

    for s, rid in a.ids('bmix'):
        try:
            w, h, px, pal = naf.background(a.raw('bmix', s, rid))
            if pal and w * h >= 640 * 200 and s not in pals:
                pals[s] = pal
            png8.write(os.path.join(root, 'bg', '%d_%d.png' % (s, rid)), w, h, px, pal or GREY)
            index['res'].append(['bmix', s, rid, w, h])
            stats['bg'] += 1
        except Exception as e:  # noqa: BLE001
            index['res'].append(['bmix', s, rid, 'error', str(e)])
            stats['errors'] += 1
    fallback = next(iter(pals.values()), GREY)

    for s, rid in a.ids('spix'):
        try:
            frames = naf.sprite_frames(a.raw('spix', s, rid))
            dims = []
            for i, f in enumerate(frames):
                w, h, px, mask = naf.rdx_image(f)
                png8.write(os.path.join(root, 'spr', '%d_%d_%02d.png' % (s, rid, i)), w, h,
                           bytes(p if m else 0 for p, m in zip(px, mask)), pals.get(s, fallback),
                           transparent=0)
                dims.append([w, h])
            index['res'].append(['spix', s, rid, dims])
            stats['spr'] += 1
            stats['frames'] += len(frames)
        except Exception as e:  # noqa: BLE001
            index['res'].append(['spix', s, rid, 'error', str(e)])
            stats['errors'] += 1

    for s, rid in a.ids('auix'):
        raw = a.raw('auix', s, rid)
        with open(os.path.join(root, 'snd', '%d_%d.wav' % (s, rid)), 'wb') as f:
            f.write(naf.wave(raw))
        index['res'].append(['auix', s, rid, list(struct.unpack_from('<HHIIHH', raw, 0))])
        stats['snd'] += 1

    for s, rid in a.ids('cbix'):
        with open(os.path.join(root, 'cb', '%d_%d.bin' % (s, rid)), 'wb') as f:
            f.write(a.raw('cbix', s, rid))
        stats['cb'] += 1

    seqs, hits = {}, {}
    for s, rid in a.ids('xsix'):
        b = a.raw('xsix', s, rid)
        if b[:2] == b'yX':
            seqs['%d_%d' % (s, rid)] = seq_record(b)
            stats['seq'] += 1
    for s, rid in a.ids('dsix'):
        b = a.raw('dsix', s, rid)
        if b[:2] in (b'eD', b'dD'):
            hits['%d_%d' % (s, rid)] = hit_record(b)
            stats['hit'] += 1
    json.dump(seqs, open(os.path.join(root, 'seq.json'), 'w'))
    json.dump(hits, open(os.path.join(root, 'hit.json'), 'w'))
    json.dump(index, open(os.path.join(root, 'index.json'), 'w'))
    print(name, stats, flush=True)
    return stats


def main():
    out = sys.argv[1]
    for p in sys.argv[2:]:
        dump(p, out)


if __name__ == '__main__':
    main()
