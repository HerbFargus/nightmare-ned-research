"""Seeds for CreateFunctions.java: code pointers in .data/.rdata and post-padding starts not
inside a known function. usage: make_seeds.py <nightmare-ned dir>"""
import csv
import os
import struct
import sys

root = sys.argv[1]
fn = list(csv.DictReader(open(os.path.join(root, 'out', 'functions.csv'))))
iv = sorted((int(x['entry'], 16), int(x['end'], 16)) for x in fn)


def inside(a):
    return any(x <= a < y for x, y in iv)


d = open(os.path.join(root, 'extracted', 'NITENED.EXE'), 'rb').read()
T0 = 0x401000
t = d[0x400:0x400 + 0x93426]
lo, hi = T0, T0 + len(t)
seeds = set()
for base, o, sz in [(0x495000, 0x400 + 0x93600, 0x1200), (0x497000, 0x400 + 0x93600 + 0x1200, 0x23600)]:
    seg = d[o:o + sz]
    for i in range(0, sz - 3, 4):
        v = struct.unpack_from('<I', seg, i)[0]
        if lo <= v < hi and not inside(v):
            prev = t[v - T0 - 1]
            if v % 16 == 0 or prev in (0x90, 0xc3, 0xcc) or t[v - T0 - 3] == 0xc2:
                seeds.add(v)
for i in range(1, len(t)):
    a = T0 + i
    if a % 16 == 0 and t[i - 1] == 0x90 and t[i] != 0x90 and not inside(a):
        seeds.add(a)
open(os.path.join(root, 'out', 'seeds.txt'), 'w').write('\n'.join('%x' % s for s in sorted(seeds)))
print('seeds', len(seeds))
