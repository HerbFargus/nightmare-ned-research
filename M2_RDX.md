# M2 — Intel RDX (dmix + Dino2d) behavioural spec, CLUT8 subset used by Nightmare Ned

Scope: the 25 dmix + 27 Dino2d imports in NITENED.EXE, and the internals they reach, for 640x480x8 only.
The 16-bit, ModeX, GDI and batch paths are left out.

**Address prefixes.** `dm:` = dmix.dll, `d2:` = Dino2d.dll, `p5:` = rdxp5.dll (blitters, found by name with
GetProcAddress in `d2:10004b30`; rdxmmx exports the same names), `exe:` = NITENED.EXE. Most `dm:`/`d2:`
functions are in `out/rdx/<dll>/decomp/`. The base-class methods (`dm:10001000..100016b0`), the state table
targets (`dm:10009840/98a0/9970`) and the group broadcasters (`dm:10006db0..100070d0`) are only reached through
pointers, so Ghidra never created them. They came from a scratch re-run with `tools/CreateFunctions.java`, and
the blitters came from capstone disassembly of rdxp5. **[G]** marks a guess or inference; everything else was
read in code.

---

## 1. Object model (dmix)

Each RDX object is a `GlobalAlloc` block: a **0x60-byte header, then the class-specific body**. A handle
(`HOBJ`) points at the body, so header fields have negative offsets (`dm:spiCreateObject 10008130`). The
methods live in a class table at `class+0x28+4*idx`, and every `obj*` export calls `*(class+slot)(&args)`
through `obj-0x10` (e.g. `dm:objSetDrawOrder 10008980`).

| hdr off | meaning | default |
|---|---|---|
| -0x60 | 'HOBJ' | |
| -0x5c / -0x08 | next / prev sibling in the parent's draw list (as `base+4`, `base+0x58`) | 0 |
| -0x58 | visible (0/1) | class+8 = 1 |
| -0x54 | render state: -1 = needs prepare, -2 = failed, 0..3 = index into `dm:PTR 10015788`, 0xff = no destination | -1 |
| -0x50,-0x4c | **position x,y** (also destRect left/top) | 0,0 |
| -0x48,-0x44 | destRect **w,h** (extents, not right/bottom) | obj w,h |
| -0x40 | draw order (u32) | class+4 = 1 |
| -0x3c / -0x38 | current image / image count | 0 / 1 |
| -0x34,-0x2c,-0x30,-0x28 | **view x, y, w, h** (stored in that order) | 0,0,w,h |
| -0x24,-0x20 | object width, height | |
| -0x1c / -0x18 | message fn / its context (an effect shell swaps these) | class msgfn / obj |
| -0x0c | destination object | 0 |
| -0x04 | parent object base (list owner) | 0 |

`spiSetWidth/Height` (`dm:10008270/100082c0`), which Dino2d calls whenever data is attached, sets the object w/h
**and resets the view to (0,0,w,h) and the destRect extents to w,h**. It leaves position alone.
`spiSetSequenceSize` (`dm:10008310`) sets the count and **resets the current image to 0**.

Which class slots exist depends on the class flags (`dm:spiCreateClass 10001a20`). The Dino2d flags are at
`d2:100123d0`: spr=0xf7, bkg=0xff, grid=0xef, tile=0x12. **Sprites have no View methods** (bit 8 is
missing), so `objAdjView`/`objGetView` on a sprite calls a NULL slot. The game only uses them on backgrounds.

### Messages that dmix sends to an object's msgfn
`0x401` can you do effect GUID? (returns a capability) · `0x403` prepare / format negotiation · `0x404` prepare
without a parent · `0x405` here is the effect stack, pick a renderer · **`0x406` render** · `0x407` set effect
params · `0x409` set effect active · `0x40a` get active · `0x40b` effect removed.
Dino2d handlers: `SprMsgFn d2:10003f20`, `BkgMsgFn d2:100039d0`, `GridMsgFn d2:10008d00`,
`TileMsgFn d2:1000bc80`. Surface handler: `dm:10009af0`.

---

## 2. Imported API

stdcall argument counts come from the export decoration (`@N` = 4·N). "→" is the field each call writes.

### dmix
| function | args | effect |
|---|---|---|
| `srfCreate@16` `dm:100093b0` | (w, h, fmt, HSRF*) | Surface object 'SURF', 0x8c body: +0x20 w, +0x24 h, +0x28 fmt (0 = CLUT8), +4 flags = 0. Visible = 1, drawOrder = 1, view and destRect = (0,0,w,h) (`dm:10009480`). The game uses (640,480,0) twice: the main surface `exe:4468f0` and a callback surface `exe:45db30`. |
| `srfSetDestWindow@8` `dm:100095a0` | (srf, hwnd) | Detaches srf from any parent (`dm:100094e0`). Dest type +0x1c = 1, hwnd at +0x30, DirectDraw set up (`dm:10002810`), then `objPrepare`. On failure it reverts to type 0. |
| `srfDelete@4` `dm:10008860→10009560` | (srf) | Unlinks the surface's children (`dm:10001980`), detaches it, frees it. |
| `srfSetColor@8` `dm:100092e0→10009700` | (srf, colour) | flags \|= 8, +0x2c = colour. **Each srfDraw then clears the target to that palette index before drawing anything.** |
| `srfClearColor@4` `dm:10009300→10009740` | (srf) | flags &= ~8, so there is no clear and the previous pixels stay. |
| `srfDraw@4` `dm:10009050` | (srf) | Composites and presents. See §3. |
| `grpCreate@4` `dm:10009080→100071b0` | (HGRP*) | 'GRUP' object of its own class with an object array (+0xc, cap 50, +4 count). |
| `grpAddObject@8` `dm:100090c0→10007390` | (grp, obj) | Appends obj (a duplicate returns -0x10). The object's own destination is **not** changed. |
| `grpDelete@4` `dm:10007340` | (grp) | Frees the group only; members are untouched. |
| `objSetDestination@8` slot 0x70 `dm:100013d0` | (obj, parent) | Unlinks obj from its old parent (if obj is a surface, detaches it from its window). Marks it dirty (-0x54 = -1) and inserts it into **parent's child list sorted by draw order** (`dm:10001890`). -0x0c = parent. |
| `objSetDrawOrder@8` slot 0x28 `dm:10001000` | (obj, order) | -0x40 = order, then **always unlinks and re-inserts** into the parent list (see §3.2 for ties). |
| `objGetDrawOrder@8` 0x30 `dm:100010a0` | (obj, u32*) | |
| `objSetVisibility@8` 0x34 `dm:100010c0` | (obj, b) | -0x58 = (b != 0). |
| `objGetVisibility@8` 0x3c | (obj, int*) | |
| `objSetPosition@12` 0x40 `dm:10001120` | (obj, x, y) | -0x50,-0x4c only. |
| `objAdjPosition@12` 0x44 `dm:10001140` | (obj, dx, dy) | Adds dx, dy. |
| `objGetPosition@8` 0x48 `dm:10001170` | (obj, POINT*) | |
| `objAdjView@20` 0x50 `dm:10001250` | (obj, dx, dy, dw, dh) | x += dx, y += dy, w += dw, h += dh, then **x = x mod W, w = w mod (W+1), y = y mod H, h = h mod (H+1)**, with negative results moved into range. W,H = object size; if W or H is 0, that axis isn't wrapped. The game scrolls backgrounds with `objAdjView(bkg, dx, 0,0,0)`. |
| `objGetView@8` 0x54 `dm:10001300` | (obj, RECT*) | {left = x, top = y, right = **w**, bottom = **h**}. |
| `objSetCurrentImage@8` 0x58 `dm:10001340` | (obj, i) | -0x3c = i, clamped to [0, count-1]. Returns 1 if it clamped. |
| `objSetDestRect@20` 0x64 `dm:10001480` | (obj, x, y, w, h) | Sets **position and extents**. All four 0 → (0, 0, objW, objH), which also moves the object to 0,0. |
| `objApplyEffect@28` 0x78 `dm:10006080` | (obj, GUID g (4 dwords by value), void* params, HFX*) | Asks msgfn 0x401 (`dm:100061f0`); if the object refuses, it searches the registry for effect DLLs (`dm:10005940`). Allocates an 'FX ' node (`dm:10006100`: +4..+0x10 GUID, +0x20 params, +0x28 active = **1**). The node is pushed as a message filter: obj-0x1c = `spiEffectShell dm:10005760`, with the old msgfn/context saved at fx+0x50/+0x54. Sets -0x54 = -1, so the object is re-prepared at the next draw. |
| `objRemoveEffect@8` 0x7c `dm:100062f0` | (obj, fx) | Unlinks the node and sends **0x40b** to its handler (`dm:10005b90`), which restores the plain renderer. Marks the object dirty. |
| `objPrepare@4` 0x80 `dm:10006480` | (obj) | With no parent: msgfn 0x404, state = 0xff. Otherwise it offers formats {FMT_WRITE, FMT_READ_WRITE, and +FMT_DDRAW_WRITE/_READ_WRITE if the parent is DirectDraw} with msgfn 0x403, and stores the chosen index (0..3) in -0x54. The effect shell forwards this as 0x405 down the stack, and that is where the renderer is chosen. srfDraw prepares dirty objects automatically (`dm:10009850`), so the explicit calls in the game are redundant. |
| `fxSetActive@8` `dm:10006790` | (fx, b) | If b differs from fx+0x28: store it and send **0x409** {stackIndex, b, &GUID} to the handler. |
| `fxGetActive@8` `dm:100067f0` | (fx, int*) | Sends 0x40a, or reads fx+0x28 if there is no handler. |

**Groups** (`dm:100071b0` overrides member slots from the table `dm:10015360`): the Set/Adj methods (DrawOrder,
Visibility, Position, View, CurrentImage, DestRect, Destination: idx 0,1,3,4,6,7,9,10,0xc,0xd,0xf,0x10,0x12) are
**broadcast to every member in insertion order** (`dm:10006dd0`). The Get methods (idx 2,5,8,0xb,0xe,0x11,0x13)
return the **first** member that implements them (`dm:10006e70`). A group is never inserted in a draw list and
has no position, order or pixels of its own: it is a remote control. The game uses one group to set
destination, order 0x117b and visibility on several backgrounds at once. Because each member is re-inserted in
turn, members with equal order end up in **reverse insertion order** (the last one added is drawn first,
i.e. at the bottom).

### Dino2d
Every `bf*` worker is reached through `spiExecuteImmediate` → `S2DBeaterFn d2:10001000`, using the command
table at `d2:10012030` (index = command id).

| function | args | effect |
|---|---|---|
| `hbmpCreate@16` `d2:100011e0` | (w, h, fmt, HBMP*) | 'BMP ' 0x50 bytes: +4 w, +8 h, +0xc pitch = w·Bpp, +0x10 Bpp, +0x18 flags, +0x20 **transparency mode = 1 (opaque)**, +0x24 key = 0, +0x28 fmt, +0x2c pixels (own buffer of h·pitch plus a 4-byte trailer), +0x3c compressed stream, +0x40..+0x4c flip-variant copies. The trailer dword at pixels + w·h = `mode \| key<<8` (`d2:10004960`). The tile blitters read it. |
| `hbmpSetTransparencyColor@8` `d2:100013a0` | (bmp, key) | fmt 0: mode = 2, key = low byte. If a compressed image is already set and there are no pixels, it first decodes using the **old** key as the fill (`d2:10001400`), then re-encodes the compressed stream from the pixels with the new key (`d2:10004610→1000b410`). The game always calls it **before** `hbmpSetCompressedImage` (key = sprite-bank field +0x28, or 10, or the background's key if it isn't -1; `exe:458010`), so that path never runs in practice. |
| `hbmpSetCompressedImage@12` `d2:10003150` | (bmp, data, size) | `data` = the whole RDX compressed image (GUID `SPRITE_GUID`, NOTES §RDX). Requires `*(u32*)(data+0x24) == size-0x24`, otherwise -0x3e. For CLUT8 it **copies bytes data+0x24..end verbatim** (`d2:10002fb0`). The p5 blitters skip 8 bytes (the size and rows fields) and start decoding the opcodes at data+0x2c (= +44). flags \|= 2. If the bitmap belongs to a bkg/tile (flag 8) it is decoded to pixels at once; if it belongs to a sprite (flag 0x10) any pixel buffer is freed. |
| `hbmpSetPointer@12` `d2:100014f0` | (bmp, ptr, pitch) | ptr ≠ 0: pixels = ptr (**not copied**; owned buffer freed), pitch set, flags \|= 6. Rendering reads the caller's memory live. Refreshes (`d2:100046d0`) and re-encodes the compressed stream if a sprite uses the bitmap. ptr = 0: switches back to an owned buffer. |
| `hbmpGetLockedBuffer@12` `d2:10001780` | (bmp, void** pix, u32 info[2]) | Decodes the compressed stream into a new pixel buffer if needed: ColorFill8 with the key, then BlitSprite8 (`d2:10001070`). Returns the pixels; info = {h·pitch, pitch}. Sets locked (flags bit 0) and clears valid (bit 1). |
| `hbmpReleaseBuffer@4` `d2:10001810` | (bmp) | Must be locked. Valid again; refreshes the DirectDraw copy and flip variants, and re-encodes the compressed stream if a sprite uses the bitmap (flag 0x10). |
| `hbmpDelete@4` | (bmp) | |
| `hseqCreate@20` `d2:10002cb0` | (count, w, h, fmt, HSEQ*) | 'SEQ ': +4 w, +8 h, +0xc fmt, +0x10 count, +0x14 list of objects using it, +0x18 bmp[count] = 0. |
| `hseqSetData@12` `d2:10002d30` | (seq, i, bmp) | bmp[i] = bmp; each object using the sequence is notified (for sprites, `d2:1000b560` makes sure a compressed stream exists, encoding it from the pixels if needed). |
| `hseqGetData@12` `d2:10002d70` | (seq, i, HBMP*) | |
| `hseqDelete@4` | (seq) | |
| `sprCreate@4` `d2:10003430` | (HSPR*) | 'SPR ' body: +8 u16 count, +0xa flags (bit0 hflip, bit1 vflip, bit15 RW target), +0x24 renderer, +0x28 seq, +0x2c frame-array pointer. |
| `sprSetData@8` `d2:10003470` | (spr, seq-or-bmp) | A 'SEQ ' sets obj w,h = seq w,h and count = seq count (`d2:100034e0`); a bitmap gives count 1 and the bitmap's w,h (`d2:100035b0`). Current image resets to 0; the object is marked dirty. |
| `sprDelete@4` | (spr) | |
| `bkgCreate@4` `d2:10003710` / `bkgSetData@8` `d2:10003660` / `bkgDelete@4` | | Same as spr ('BKG '). Bitmaps get flag 8 and are kept as decoded pixels (`d2:100033c0`). |
| `bkgSetFlags@8` `d2:10004590` | (bkg, f) | When bit 0 is newly set, the frames are copied to DirectDraw surfaces (`d2:10004470`), so the renderer becomes BkgDDRender. **Pixel-identical [G]**; ScummVM can ignore it. |
| `tleCreate@4` `d2:1000b9f0` / `tleSetData@8` `d2:1000bb40` | (HTLE*) / (tile, bmp-or-seq) | 'TILE': +4 pointer to the current pixel variant, +8/+0xa u16 w,h, +0x12 flip flags. The bitmap gets flag 8 and a packed copy at +0x40[flip] (`d2:1000b960`). |
| `grdCreateEx@24` `d2:10008910` | (u16 cols, u16 rows, u16 cellW, u16 cellH, fmt, HGRD*) | 'GRID' with obj size cols·cellW × rows·cellH. +0x30 cell table with **row stride cols+1**: each row ends in a sentinel tile (+0x28 body). Every cell starts as a built-in default tile (+0x20 body) (`d2:100088c0`). The renderer is GridRender. |
| `grdSetData@12` `d2:10008b40` | (grd, (row<<16)\|col, tile) | table[(cols+1)·row + col] = tile, written to both copies (+0x30, +0x34). |
| `FX_HORIZ_FLIP`, `FX_SMORPH`, `FX_FULL_SCREEN`, `FX_RENDER_CALLBACK`, `FX_DDRAW_RENDER_CALLBACK` | data | 16-byte GUIDs, compared with a 16-byte memcmp everywhere. The game passes them by value to `objApplyEffect`. |

---

## 3. srfDraw end to end (`dm:10009050 → 10004240`)

1. `dm:10004090`: if the surface is **invisible** (-0x58 == 0), return without drawing or presenting. If it is
   dirty, `objPrepare` it. Build the render context `ctx` = {[0] Bpp, [1] buf (+0x78 or a DirectDraw lock),
   [2] pitch (+0x7c), [3] w, [4] h, [5..8] = destRect x,y,w,h, …, [10..13] clip x,y,w,h} and send 0x406 to
   itself. That reaches the surface renderer (+0x18 = `dm:1000a3d0` / `dm:10009f70`) and then
   **`dm:1000a000`**:
   1. A child surface (dest type 0) clips its destRect against the parent (`dm:1000a220`) and offsets its
      children by −view.xy. **[G: the exact arithmetic is only lightly checked; the game's child surface is
      640x480 at 0,0 with view 0,0,640,480, so it is the identity.]**
   2. **Clear**: if flags & 8, ColorFill8 the clip area with +0x2c (`dm:10009750`).
   3. **Children**: walk the list from the head (+0x34, next = base+4). For each child with **visible ≠ 0**, call
      `dm:PTR[state]`. Index -2 is a no-op (`dm:10009840`). Index -1 prepares and then dispatches
      (`dm:10009850`). Indices 0,1 are `dm:100098a0`: ctx[5] = child.x + originX, ctx[6] = child.y + originY,
      ctx[7] = child.w, ctx[8] = child.h, then child msgfn(0x406, &ctx[1]). Indices 2,3 are the DirectDraw
      variant `dm:10009970`.
   4. **FX_RENDER_CALLBACK** (flags & 1): `cb(srf, buf, pitch, user)`, where buf points at the surface's
      clipped origin (locked first if needed).
   5. **FX_DDRAW_RENDER_CALLBACK** (flags & 0x40): unlock, then `cb(srf, IDirectDraw* (dm:DAT_100171c8),
      IDirectDrawSurface*, user)`.
2. **Present** (`dm:10004240`). An iconic window is skipped. Otherwise the 640x480 buffer goes to the screen:
   page flip (`dm:100042c0`, +0x70 set) or a DirectDraw blit over the window's clip list (`dm:100046b0`). For
   ScummVM that means **copy the whole buffer and updateScreen**.

**There are no dirty rectangles.** Every srfDraw redraws every visible child (`dm:1000a000`); "dirty"
(`spiDirtyObject dm:10008260`, -0x54 = -1) only means "re-run prepare". The game turns clearing on and off with
srfSetColor/srfClearColor. With clearing off, every pixel that no child covers keeps its previous contents.

### 3.1 How the game wires it
- **Main surface** `exe:4468f0`: srfCreate(640,480,0). `objApplyEffect(FX_DDRAW_RENDER_CALLBACK, &{exe:446a40,
  &palState})`, where the callback uploads a pending 256-entry palette (CreatePalette/SetEntries) and clears
  the pending flag. `FX_FULL_SCREEN` params `exe:4a4818` = {640, 480, 0, 1} (display mode). srfSetDestWindow,
  objPrepare, srfDraw. **The palette therefore changes at the end of a composite, before present.**
- **Callback surface** `exe:45db30`: srfCreate(640,480). `FX_RENDER_CALLBACK` with {`exe:460730`, 0}, which
  draws straight into buf with pitch 640. fxSetActive(1), drawOrder 1, destination = main surface. It acts as a
  child "object" whose content is whatever the callback paints, at its place in the draw order.
- **Grid** `exe:442fb0`: grdCreateEx(1,12,640,148). All 12 cells use one tile made from a background bitmap
  (640x148), giving a 640×1776 world. Destination main, order 99, invisible at first. It scrolls with
  `objSetPosition(grid, 0, y)` for y in [480−1776, 0].

### 3.2 Draw order
`dm:10001890` inserts by walking while `new.order < cur.order` (an **unsigned** compare) and puts the new node
before the first node with `order <= new`. So the list is **descending**, the head (largest order) is drawn
first, and **larger order = further back; the smallest order is on top.** Ties: a node that is (re)inserted
goes **in front of** existing equal-order nodes in the list, so it is drawn first and ends up **below** them.
Every objSetDrawOrder or objSetDestination call re-inserts, even with an unchanged value. Negative orders
compare as huge unsigned numbers, so they are drawn first, at the very bottom.

### 3.3 Geometry and clipping (all classes)
For a child, dest = (x, y, w, h) = position + destRect extents. `d2:100061b0` clips dest to [0,W)×[0,H) of
ctx[3],ctx[4] (→ cx, cy, cw, ch). `d2:10006050` moves the source rect by (cx−x, cy−y) and takes
**size = min(source size − offset, clipped dest size)**. **There is no scaling anywhere outside FX_SMORPH**:
the extents only crop.

---

## 4. Per-class rendering (renderers chosen at prepare)

### 4.1 Sprite (`SprRender d2:10006260`)
- Frame = bmp[currentImage]. Source = **(0, 0, frameW, frameH)**: sprites ignore the view, and the decompile
  hides this, but the disassembly at `d2:10006280` zeroes it. Dest = (x, y) top-left with extents = seq w,h by
  default. There is no hotspot.
- Pixels always come from the **compressed stream** (bmp+0x3c). If the visible size equals the frame size it
  uses `p5:BlitSprite8 10002680 (dst, pitch, stream, w, h)`, otherwise `p5:ClipSprite8 10006580 (dst, pitch,
  stream, sx, sy, w, h)`.
- Opcodes (confirmed in p5 at the jump table `p5:10002b20`): 0 = skip n; 1 = n × dword-fill colour; 2 = n literal
  pixels; 3 = n pixels, k colours, then mask bytes read LSB-first a nibble at a time, ending at a 0 byte;
  4 = end of row (dst += pitch − w); 5 = end of image. **Transparency = the skip runs and clear mask bits only.
  The key colour is not used when drawing.**
- If the chosen target format is not READ_WRITE (spr flags bit 15 clear), the dest rect is first filled with
  the key colour (ColorFill8 call inside `d2:SprRender 10006260`). **[G] Every child of a surface negotiates READ_WRITE
  (`d2:10003cb0` sets bit 15), so a reimplementation should never pre-fill.**

### 4.2 FX_HORIZ_FLIP (sprites; also tiles via flip variants)
- Apply (params = NULL in the game, handle kept) → 0x405 → `d2:100040d0` sets flags bit 0 and the renderer
  `SprRenderHFlip d2:100064b0`. Active at once (fx active defaults to 1). `fxSetActive` → 0x409 →
  `d2:100043c0` toggles bit 0 and switches between SprRender and HFlip. Remove → 0x40b → back to SprRender.
  fxGetActive returns flags & 1.
- **Mirror axis = the frame's own box.** `p5:HFlipSprite8 10008df0` starts at dst + frameW and writes
  leftwards, so source column i lands at x + frameW − 1 − i. It is not mirrored about the sequence width or
  the sprite position.
- **Clipping (corrected 2026-10-18):** Dino2d `SprRenderHFlip` (`d2:100065b6..100065c5`) turns the clip offset into `sx' = frameW - visibleW - sx` before `p5:ClipHFlipSprite8` skips `sx'` source columns, so dest col `cx + j` shows src col `frameW - 1 - sx - j`: an ordinary crop of the mirror. The earlier "mirror of a crop" reading missed that step (it clipped the graveyard's ghost sprites at screen edges).
  game].**

### 4.3 Background (`BkgRender d2:10005210`)
- Source = **view (vx, vy, vw, vh)** in the current frame's pixel buffer. Dest = (x, y) with extents. Clipped
  as in §3.3. Then `d2:100056b0` wraps the source origin once into [0,W)×[0,H), and `d2:100058f0` splits the
  copy into up to 4 rects where the source crosses the right or bottom edge. **The bitmap tiles like a torus**:
  this is what makes `objAdjView` scrolling seamless.
- Blit: transparency mode 2 (set with hbmpSetTransparencyColor) and an RW target → `p5:CKeyBlit 100032c0 (dst,
  dpitch, src, spitch, w, h, key)`, which copies every pixel except the key. Otherwise `p5:FillBkg 10007c10`
  (an opaque copy).
- When the bitmap came from hbmpSetPointer, the game's buffer is read on every draw.

### 4.4 Grid and tiles (`GridRender d2:10005a30`)
- The world is cols·cellW × rows·cellH, and view/extents are in world pixels. World (wx, wy) → cell (wx/cellW,
  wy/cellH) → tile pixel (wx%cellW, wy%cellH). Full, edge and narrow cells are drawn by
  `p5:ASMDrawFullTiles/ClippedTiles/SkinnyTiles`.
- Each tile is drawn from its packed pixel copy (tile+4). If that is NULL the cell is skipped (`p5:100093cc`).
  Transparency comes from the bitmap trailer: 1 = opaque, 2 = key8 (`p5:100093d8` dispatches on it).
- The view does **not** wrap: there is no modulo and no wrap split. A cell that was never set draws the built-in
  default tile, **[G] probably empty**.
- The game's grid is one 640x148 tile repeated 12 times and moved by position only.

### 4.5 FX_SMORPH (the game uses it on backgrounds: `exe:402fa0`, `exe:403430`)
- **Params** = `{u32 mode, Row* table}` (`exe:525e10` = {0, &525e20}). mode 0 → `p5:SmorphOpaqueBitmapClip /
  SmorphPalBitmapClip`; any other value → the `…Wrap` versions (`d2:1000a860/1000a7a0`, `d2:BkgSmorphRender
  10009e40`). `Row = {s32 u0, v0, du, dv}`, **16.16 fixed point in source pixels**, one row per destination
  scanline. The game fills min(h,480) rows of {0, v0, du, 0}: each output line samples one source row,
  starting at x=0 and stepping du. It is a per-scanline zoom/squash, stepped over 30 frames with a moving
  destRect (`exe:403430`: objApplyEffect on every frame, objSetDestRect(x, y, w, h), srfDraw).
- **Source** = the background's own render output in describe mode: BkgRender with ctx = NULL returns a pointer
  to the view origin, or a wrapped scratch copy (`d2:10005210`, first branch). In other words, the vw×vh view
  is the source image.
- **Per pixel** (`p5:100180a0`): table += clipTop rows. For dest row r: u = u0 + clipLeft·du, v = v0 +
  clipLeft·dv. For i in [0, cw): sample `rowptr[v>>16][u>>16]`, then u += du, v += dv. **Clip mode**: pixels
  whose (u,v) lie outside [0,vw)×[0,vh) are left unwritten. The leading outside pixels are stepped over, and
  the row ends at the first sample after it enters that falls outside again (`p5:10018333…`). If du = dv = 0,
  the whole row is filled with one sample (`p5:100188ca`). Pal variants skip the key (pixel == key) when the
  source is transparent. Wrap variants take coordinates modulo the source size; the row-pointer table is
  doubled (`d2:1000a750`). **[G for the details of wrap]**
- Destination = the background's dest rect (position + extents) clipped to the surface. The table is indexed
  from the rect's top, so rows clipped off the top skip their entries.
- Inactive (fxSetActive 0) → `FxSmorphRender8 d2:1000a470` copies the source unchanged (FillBkg/CKeyBlit), the
  same as a plain BkgRender with no wrap.
- Which code path: the background rejects 0x405, so dmix looks up a registered effect DLL (`dm:10005940`), and
  Dino2d's `DinoEffects d2:10006bb0 → 10007190 → 10007210` installs the generic `FxSmorphRender8` wrapper.
  `BkgSmorphRender`/`SmorphBackground` feed the same blitter (with the view as the source origin), so either
  way the result is identical in clip mode.

### 4.6 FX_FULL_SCREEN / FX_RENDER_CALLBACK / FX_DDRAW_RENDER_CALLBACK (surfaces only)
`dm:1000a460` maps the effect stack to flags: RENDER = 1, DDRAW = 0x40, FULL_SCREEN = 0x10, MAP_CLUT8 = 0x20.
`dm:1000a5c0`/`a5e0` store the {fn, user} params. Removing an effect clears its bit (`dm:1000a990`).
FULL_SCREEN only selects exclusive 640x480x8 display mode (`dm:10003090`); its params are {w, h, fmt, 1}.
In ScummVM it is a no-op. The callback timing is in §3, steps 4 and 5.

---

## 5. Minimal reimplementation checklist
- An Object has {visible, order, x, y, ew, eh, view, cur, count, parent, children}. Surfaces hold a sorted
  child list (descending by order; a re-insert goes before its equals); draw from the head.
- srfDraw(main): if colour enabled → fill. For each visible child: sprite (§4.1/4.2), bkg (§4.3 / smorph §4.5),
  grid (§4.4), child surface (clear if enabled, its own children, then its render callback). Then the main
  surface's DDraw callback (the palette hook), then present.
- Groups forward Set/Adj calls in insertion order.
- Effects are a per-object list of {GUID, params, active}. Only HFLIP (sprites) and SMORPH (backgrounds) change
  pixels.

---

## 6. Ten most important open questions
1. **Smorph row termination**: the Clip loop seems to stop a row once a sample leaves the source after
   entering it. That needs checking against the 8 sign-case loops (`p5:100182fb..10018458`); the game only uses
   du>0, dv=0, which is the simplest case to confirm.
2. **Smorph transparency**: does the wrapper pick the Pal (keyed) variant for keyed backgrounds? `pMem[2]` is
   set from a format code in `d2:10007210` that wasn't traced.
3. **The HFlip clip quirk** (§4.2) is derived from the assembly. Confirm in game on a flipped Ned sprite that
   touches the screen edge.
4. **Format negotiation**: `d2:10003860` scoring wasn't traced. The spec assumes every child chooses
   READ_WRITE (so no key pre-fill and keyed bkg blits).
5. **The effect DLL registry lookup** (`dm:10005940`, HKLM key from `dm:100152f8`): if DinoEffects isn't
   registered, FX_SMORPH may fail at prepare (state -2 = background not drawn). Is the installer's registry
   state needed?
6. **Child-surface coordinates** (`dm:1000a220`) when the child's view or dest isn't (0,0,640,480). It only
   matters if the game ever moves the callback surface.
7. **Default grid tile** content (`d2:1000b6d0`/`1000b770`, grid +0x24/+0x2c) and the sentinel column: empty
   or opaque?
8. **ClipSprite8 vertical/horizontal skip details** and the meaning of the 'rows' field at stream+4. Its value
   isn't used by BlitSprite8.
9. **BkgDDRender vs BkgRender** (after bkgSetFlags 1): DDRender skips the pre-wrap `d2:100056b0`. Could a view
   origin ≥ W ever reach it? objAdjView keeps x < W, so probably not.
10. **objApplyEffect called every frame without a remove** (the `exe:403430` loop only removes when
   `DAT_00525dec` is set): do effect nodes stack up (one more shell per frame), and does the outermost shell
   win? It looks like nested wrappers would smorph an already-smorphed source. Count the nodes in a debugger,
   or model a list where only one SMORPH is active.
