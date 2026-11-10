# Nightmare Ned — M2 engine layer (resource slots, display objects, animation, collision, input, frame)

2026-10-17. Source: Ghidra decompiles in `out/decomp/`, plus disassembly dumped with a read-only
headless Ghidra pass where the decompiler lost stack arguments (marked **[asm]**), plus static
`.data` tables and the shipped data files. RDX calls (`obj*`, `spr*`, `hseq*`, `hbmp*`, `bkg*`,
`srf*`, `fx*`) are treated as black boxes. Guesses are marked **(guess)**.

Corrections to NOTES.md found while doing this:

* **`yX` layout:** the header is seven `u16` values, and `rate` is a `u16` at +0x0C. The frame
  table starts at +0x0E as `nframes` × `(u16 frame, u16 duration)`. NOTES reads `rate` as a `u32`,
  but its high half is really entry 0's frame index. 128 sequences in the data have `rate` =
  0x10018/0x20018/…, so their first frame is 1, 2, … (§3.1).
* **`eD` header +0x0A** (u16 [5]) is the **transparent colour index**, not an unknown field (§1.4).
* **`eD` rect sets:** the "two sets of 3 rects" are rects 0–2 for the normal sprite and rects
  3–5 for the horizontally flipped sprite. `FUN_0044ff40` picks rect index 3 when the slot's
  HORIZ_FLIP effect is active (§4.1).
* **The 426-entry table at 0x4a5578 is not a collision response table.** It holds per-slot
  **frame-event callbacks** for Ned's 426 area-1 slots. `FUN_004518e0` calls entry `[slot]` on
  every frame step. The default `FUN_00451370` plays the slot's sound on step 0 (§3.3).
* **`oO` (`.SST`) files are not motion paths.** They are **scene object placement tables**: area,
  slot, x, y, z, transparent colour and flip for each sprite or background. `oO` is also the
  in-memory "object list" type that hit/target scans iterate over (§4.4).
* **`dD` / `xX`** (0x4464/0x5878) are in-memory editor variants that only uncalled functions
  create (`FUN_00484fd0`, `FUN_004865c0`). The game data is all `eD`/`yX`, so the port can ignore
  the variant branches.

---

## 1. Resource slot system

### 1.1 Overview

The game loads every NAF resource through **request lists**: static `.data` arrays of 0x24-byte
entries, one list per scene, sub-scene or actor. Submitting a list queues each entry on a
**two-stage background loader**:

```
game thread                 I/O thread FUN_004588a0          decode thread FUN_00458be0
FUN_004586e0(naf,list,n,scene)
  FUN_00458380 (sync prep:   ->  queue A (500, DAT_004c6968,  ->  queue B (500, DAT_004c6170,
  xsdt/dsdt lookup, slot          sem DAT_004c6958)                sem DAT_004c6160)
  geometry, alloc 0x2c recs)      reads the raw ??ix blob           LZW-decodes (FUN_00489260),
                                  (mmio)                            then FUN_00458010(entry,1)
                                                                    builds the RDX objects, then
                                                                    entry->callback(entry)
```

`FUN_00455d50` creates both semaphores (max 500), two events and the critical sections
`DAT_004c6940` (A) and `DAT_004c6148` (B). Each worker waits on {quit event, its semaphore}.
`DAT_004c7164`/`DAT_004c7168` are spin "busy" flags that let `FUN_00455ca0` flush a queue safely.

**Port advice:** do it all synchronously. `FUN_00459170` and the waits in
`FUN_00459090`/`FUN_00459100` spin until bit 0x10 is set, so running the loader inline gives the
same results.

### 1.2 Request entry (0x24 bytes)

| off | type | meaning |
|---|---|---|
| +0x00 | u16 | **flags** (below) |
| +0x02 | u16 | pad |
| +0x04 | i32 | NAF **scene** id. The submit call overwrites it with its `scene` argument (`FUN_00458380`: `e->scene = param_4`) |
| +0x08 | i32 | **area** index into `DAT_004afcb0` (types 1 and 4). For type 2 it is the **transparent colour** (−1 = none). It is −1 for type 3 |
| +0x0C | i32 | resource **id** in the NAF index, which is also the **slot index** in the area (types 1 and 4) |
| +0x10 | i32 | **type**: 1 sprite (`xsix`+`dsix`+`spix`), 2 bitmap (`bmix`), 3 collision map (`cbix`), 4 sound (`auix`) |
| +0x14 | ptr | type 1: set to the slot record (or to the alias source's slot). Type 2: `BitmapRec**` destination variable. Type 3: `BC**` destination variable |
| +0x18 | ptr | NAF object, set at submit time |
| +0x1c | fn | completion callback `cb(entry)`, run on the decode thread. `FUN_0044fdf0` sets it on the last entry only |
| +0x20 | ptr | type 2: optional palette destination (0x404 bytes: a 4-byte header plus 256 × `rgbx`) |

**Flags** (from `FUN_004586e0`, `FUN_00458380`, both workers and `FUN_00458010`):

| bit | meaning |
|---|---|
| 0x01, 0x20 | I/O pending. Submit sets `|0x63`; the I/O thread clears 0x21 when the read succeeds |
| 0x02, 0x40 | decode pending. 0x40 means "forward to the decode queue" (otherwise the I/O thread calls `cb` directly); the decode thread clears 0x42 |
| 0x04 | I/O error. 0x08 is a decode error. `FUN_00459170` returns 5 if `flags & 0x0c` |
| 0x10 | **ready**: the RDX objects exist. `FUN_00458010` skips entries with `flags & 0x13` |
| 0x80 | **alias**: this sequence borrows another slot's frames (§1.5). `FUN_00458380` clears 0x90 first |

### 1.3 Functions

| addr | proposed name | signature / behaviour |
|---|---|---|
| `4586e0` | `res_load_list` | `(Naf*, Req*, n, scene)`. Calls `FUN_00458380(...,final=0)` for each entry, then pushes it to queue A (`flags = flags & ~0x0c | 0x63`, `e->naf = naf`). 95 callers |
| `4587a0` | `res_load_list_ex` | Same, but with `param_5 != 0` the entries go to the **front** of queue A in reverse order (priority load) |
| `458640` | `res_queue_decode` | Pushes entries straight to queue B (`flags | 0x42`), for data that is already read |
| `458380` | `res_prepare` | Synchronous prep, run twice: on submit (`final=0`) and on the I/O thread before the read (`final=1`). Type 1, final: the slot geometry (§1.5). Type 2: `*e->ptr = calloc(1, 0x2c)`. Type 4: zero slot +0x50..+0x60 |
| `4588a0` | I/O thread | type 1 (non-alias): `FUN_004578d0` reads `spix[scene,id]` into slot+0x4c; slot+0x24 = the blob's leading u32 (unpacked size); slot+0x30 = malloc(that). Type 2: `FUN_00457720` reads `bmix` into rec+0x28; w,h from the codec header → rec+0x12/+0x14; rec+0x20 = malloc(w·h). Type 3: `FUN_00457a80` reads `cbix` into `*e->ptr` (the buffer is size+4 and the data goes at +4), then `FUN_00487220` fixes it up. Type 4: `FUN_00457c40` reads `auix` into slot+0x5c; slot+0x54 = blob+0x12+cbSize (PCM); slot+0x58 = PCM length |
| `458be0` | decode thread | type 1: `FUN_00489260(blob+4 → slot+0x30)`, LZW. Type 2: decode the pixels into rec+0x20; if `e->pal`, copy 0x404 bytes of the codec palette (`FUN_004893a0(blob,0x40a,…)`). Then it calls `FUN_00458010(e,1)` and `e->cb(e)` |
| `458010` | `res_build_objects` | `(Req*, n)`. Type 1: `hseqCreate(nfr=+0x0e, w=+0x20, h=+0x22)` → +0x34. For each frame: `hbmpCreate(w,h)`, `hbmpSetTransparencyColor(+0x28)`, `hbmpSetCompressedImage(img, size)` and `hseqSetData(seq,i,bmp)`, where the images follow `u32 size[nfr]` in +0x30. Alias (0x80): the frames are copied from the source slot's hseq with `hseqGetData`/`hseqSetData`. Then +0x24 = w·h, `sprCreate` → +0x2c and `sprSetData(spr, hseq)`. Type 2: if h < 2 it is **palette only** (the pixel buffer is freed: NED92000's 8×1 bitmaps); else `hbmpCreate(w,h)` → rec+0x1c, the colour key, `hbmpSetPointer(pixels, pitch=w)`, `bkgCreate` → rec+0x18 and `bkgSetData`. Types 3 and 4 just set 0x10 |
| `459170` | `res_wait` | `(Req*)`: busy-waits until `flags & 0x10` (returns 0) or `flags & 0x0c` (returns 5). 96 callers |
| `459190` | `res_poll` | `(Req*, int *err)`: non-blocking; returns `(flags>>4)&1` and sets `*err = 5` on error |
| `459090` | `res_show_sprite` | `(Req*, z, visible, dest)` **[asm, stdcall imports]**. Type 1 only: wait, then `objSetDrawOrder(spr,z)`, `objSetDestination(spr,dest)` and `objSetVisibility(spr,visible)` |
| `459100` | `res_show_bitmap` | The same for type 2, on the `bkg` (rec+0x18) |
| `459000` | `res_attach_list` | `(Req*, n, dest)`: for every type 1/2 entry, `objSetDestination(obj,dest)` and `objSetVisibility(obj,0)` |
| `4591c0` | `res_free_packed` | `(Req*, n)`: frees slot+0x30 (the packed frames) for non-alias type 1 entries. No direct callers |
| `458dc0` | `res_free_list` | `(Req*, n)`, walked **backwards**. Type 1: deactivate and remove the fx (+0x38), hide and `sprDelete` (+0x2c), `hbmpDelete` every frame (non-alias), free +0x30, `hseqDelete` (+0x34), free +0x4c. Type 2: `hbmpDelete`, hide and `bkgDelete`, free the pixels, `FUN_00489450(rec+0x28)`, free the rec and set `*ptr = 0`. Type 3: `FUN_00487430` frees the BC. Type 4: `FUN_00455930` stops the voice, frees +0x5c and clears +0x54/+0x58/+0x60. It clears the entry flags. 95 callers |
| `455ca0` | `res_flush_queues` | Empties both queues; it takes the spin flags first |
| `486a30` | `seq_get_header` | `(yX*, &kind, &sprite, &a)` reads u16 [2],[3],[4]. It returns −3 for NULL |

### 1.4 The NAF object (`FUN_00456600`) and the lookup

The NAF object is an `int[]`. [0] HMMIO; [6] cached file position; [7] scene count; [8]
scene-id array; [9] first scene; [10] last scene; [0x0b] the `xsdt` chunk buffer; [0x0c] the
`dsdt` buffer; [0x0d] `xsix`; [0x0e] `dsix`; [0x0f] `spix`; [0x10] `bmix`; [0x11] `cbix`;
[0x12] `auix`. In memory an index is `{u32 slots; i32 *first; i32 *last; {u32 off,size} *ent;
u16 **perScene}`. The lookup (identical in `FUN_00458380` and `FUN_004578d0`/`7720`/`7a80`/`7c40`):

```
s    = scene - naf[9]
slot = ix->perScene[s][id - ix->first[s]]   // 0xFFFF -> error 10
off,size = ix->ent[slot]
// xsdt/dsdt: record = chunkbuf + off   (FUN_00458380 adds naf[0x0b]/[0x0c])
// spix/bmix/cbix/auix: mmioSeek(off) and read size bytes (cbix size+4)
```

**`eD` hit-box record** (`dsdt`), from the accessors `FUN_00485830`/`4855b0`/`485860`/`485700`/
`485450`/`4860d0`, all given as u16 indices:

| off | field | used by |
|---|---|---|
| +0x00 | magic `eD` (0x4465) | |
| +0x02 | ver 6 | |
| +0x04 | **nframes** → slot+0x0e | `FUN_004855b0` |
| +0x06/+0x08 | **w, h** → slot+0x20/+0x22 | `FUN_00485860` |
| +0x0A | **transparent colour** → slot+0x28 | `FUN_00485830` |
| +0x0C/+0x0E | **anchor x, y** | `FUN_00485700` |
| +0x10 + 0x68·f | frame f: `i16 offx, offy, offx_alt, offy_alt` | `FUN_00485450(box,f,&x,&y,alt,addx)`; alt returns `offx_alt+addx`, offy_alt |
| +0x18 + 0x68·f + 16·k | rect k (0–5): `i32 x0,y0,x1,y1`. x0 = −0x7fff means none. 0–2 normal, 3–5 flipped | `FUN_004860d0(box,f,k,int out[4])` |

### 1.5 The sprite slot record (100 = 0x64 bytes) — `DAT_004afcb0[area] + id*100`

Every field below is backed by a read or write in the cited functions. "OO" means it is filled from
an `oO`/`.SST` placement entry (`FUN_0043e460`), §4.4.

| off | type | meaning | evidence |
|---|---|---|---|
| +0x00 | i32 | **x**: world/anchor position (OO [3]). It is the reference point for placement | `430710`, `441330`, `43e460` |
| +0x04 | i32 | **y** (OO [4]) | same |
| +0x08 | i32 | **z / draw order** (OO [5], e.g. 100/200/2000) | `43e460` |
| +0x0c | i16 | ms per sequence tick = `1000/rate` (default rate 24 → 41). OO [10] overwrites it with 41. **The game never reads it**: deadlines use a hard-coded 0x29 (§3.2) | `458380`, `43e460` |
| +0x0e | i16 | **sprite frame count** (eD nframes) | `458380`, `458010` |
| +0x10 | i16 | **sequence length** (yX nframes = number of steps) | `458380`/`4869b0`; 198 compares `step < len` |
| +0x12 | u16 | **slot flags**: 0x01 play the sequence backwards (`4518e0`); 0x02 no HORIZ_FLIP effect (`44fd30`); 0x04 placed mirrored (OO [13]); 0x10/0x20 Ned-controller state bits, cleared with `&0xffcf` **(guess: "held", "locked")** | `4518e0`, `44fd30`, `43e460` |
| +0x14 | i16 | x offset added when facing one way, subtracted the other (OO [7]) | `0x4c7194` uses in Ned code |
| +0x16 | i16 | y offset (OO [8]) | `0x4c7196` |
| +0x18/+0x1a | i16 | extra x/y offset (Ned: `y += +0x1a`; a test for both being 0) **(guess: secondary attach point)** | `0x4c7198/9a` |
| +0x1c/+0x1e | i16 | x/y offset subtracted when Ned starts a special action (`44ee30`) **(guess: action origin)** | `0x4c719c/9e` |
| +0x20 | i16 | **w** (frame width; also used to mirror x: `x' = x - w + d`) | `458010`, `430710` |
| +0x22 | i16 | **h** | same, `455a50` (sound pan centre) |
| +0x24 | i32 | the unpacked spix size during load, then w·h | `4588a0`, `458010` |
| +0x28 | i16 | **transparent colour index** (eD [5]; OO [12] overrides it: 10, 177, 254) | `458380`, `43e460` |
| +0x2c | h | **RDX sprite object** (`sprCreate`) — what every `obj*` call targets | everywhere (92 refs) |
| +0x30 | ptr | packed frames: `u32 size[nfr]`, then the RDX images. Freed after the build or on free | `4588a0`, `458010`, `4591c0` |
| +0x34 | h | **hseq** (frame-bitmap sequence) | `458010`, `458dc0` |
| +0x38 | h | **FX_HORIZ_FLIP effect** handle; `fxSetActive(fx, facingLeft)` | `44fd30`, `44ee30`, `454920` |
| +0x3c | ptr | **`yX` sequence record** | `458380`; 31 refs |
| +0x40 | ptr | **`eD` hit-box record** (for an alias, the source's) | `458380`; 36 refs |
| +0x44 | i16 | **current sequence step** (−1 = before the start). 562 refs | `430890`, `4518e0` |
| +0x48 | u32 | **next-step deadline** in ms (0x7fffffff = frozen) | 160 refs |
| +0x4c | ptr | raw spix blob (freed after decode) | `4588a0`, `458be0` |
| +0x50 | ptr | playing **voice** (the 0x6c-byte DirectSound node from `FUN_0044d320`) | `455880` |
| +0x54 | ptr | **PCM data** (auix blob + 0x12 + cbSize). Non-zero means "the slot has a sound" | `4588a0`, `451370` |
| +0x58 | u32 | PCM byte length | `4588a0` |
| +0x5c | ptr | auix blob (`WAVEFORMATEX` at +0) | `4588a0`, `458dc0` |
| +0x60 | fn | end-of-sound callback for `FUN_00455800` | `455800`, `455870` |

**How (scene, id) reaches a slot** (type 1, `FUN_00458380` with `final=1`):

```
seq = xsdt_lookup(scene, id);  slot = &area[id];  slot->seq(+3c) = seq
(kind, spr, a) = seq header [2],[3],[4]
if spr == id:                                       // owns its frames
    box = dsdt_lookup(scene, spr); slot->box(+40) = box
    slot->key = box[5]; slot->nfr = box[2]; slot->w,h = box[3],box[4]
else:                                               // alias: reuse frames of area[spr]
    copy +28,+0e,+20,+22,+40 from area[spr]; e->flags |= 0x80; e->ptr = &area[spr]
slot->w*h -> +24;  slot->rate(+0c) = 1000 / (seq rate ? : 24);  slot->len(+10) = seq[5]
// I/O: spix(scene,id) (skipped for aliases) -> +4c ; decode -> +30 ; build -> hseq/spr
```

Types 1 and 4 can share one slot: Ned's list `0x4a63e0` loads id 35 as a sprite and id 35 as a
sound into the same record. The sound fields are +0x50..+0x60.

**The bitmap record** (0x2c, `calloc` in `458380`, pointed to by `*e->ptr`): +0x00 x, +0x04 y,
+0x08 z (OO), +0x0c (OO [10]), +0x0e/+0x10 (OO [7],[8]), **+0x12 w, +0x14 h**, +0x16 (OO
[12]), **+0x18 bkg object**, **+0x1c hbmp**, **+0x20 8-bit pixels**, +0x24 (`FUN_00489430`
codec field), +0x28 the raw `bmix` blob. Backgrounds are positioned with
`objSetPosition(rec[6], x+scrollX, y+scrollY)` (`FUN_00407c50`). Parallax layers instead use
`objAdjView(bkg, dx/3, dy/3)` or `/6` (`FUN_0043cb90`, `FUN_0041c5e0`, `FUN_00479050`).

### 1.6 Areas (`DAT_004afcb0`, 10 pointers to static `.bss` slot arrays)

Mapped by matching each NAF handle variable (`FUN_00456600` call + `FUN_00430c90` file index)
with the area field of the type 1/4 entries in its request lists:

| area | base | NAF(s) | max id seen | notes |
|---|---|---|---|---|
| 0 | NULL | – | – | `oO` entries with area 0 exist (UVULA.SST) **(guess: set at runtime)** |
| 1 | `0x4c7180` | ned00000 (Ned, global); one entry from 86000 | **426** slots | the frame-callback table `0x4a5578` has 426 entries; the Ned lists are `PTR_DAT_004afb98[23]` with counts at `0x4afbf8` |
| 2 | `0x50fc50` | ned99000 (S1 graveyard) | 484 | |
| 3 | `0x4ec5e8` | ned98000 (S4 attic) | 404 | |
| 4 | `0x5048a0` | ned95000, 96000, 97000 (S3 chalkboard, S6, S3) | 451 | shared: never loaded together |
| 5 | `0x4f6228` | ned93000, 94000 (S2, S7) | 421 | shared |
| 6 | `0x4d1838` | ned90000 (S5) | 344 | |
| 7, 8 | NULL | – | – | unused |
| 9 | `0x500638` | ned92000 (S0 menus) | 161 | |

Type 3 (`cbix`) and type 2 (`bmix`) never use an area. Their results go into per-scene globals
through `+0x14`. For example, the 0x9c-entry graveyard list `0x49ade0` stores BC maps 1..156 into
`DAT_004bac60[]`.

---

## 2. The display-object layer used by game logic

The game never draws by hand. Every visual is an RDX object (a sprite = slot+0x2c, a background =
rec+0x18) attached to the primary surface. Each tick it is positioned, shown or hidden and given a
frame, and then one `srfDraw` composes the frame (§6).

| addr | callers | proposed name | parameters → behaviour |
|---|---|---|---|
| `430710` | (core) | `slot_place` | **[asm]** 9 args `(area, slot, ref, i16 *outFrame, i16 *outDur, int pos[2], int noMirror, void (*xform)(int*), int relative)`. Pseudo-code below |
| `430850` | 198 | `slot_place_x` | `(area, slot, ref, outFrame, outDur, pos, noMirror, xform)` → `430710(..., relative=0)` **[asm]**. Ghidra wrongly marks it no-return |
| `430530` | 28 | `slot_place_nx` | `(area, slot, ref, outFrame, outDur, pos, noMirror)` → xform = NULL, relative = 0 **[asm]** |
| `430410` | 125 | `slot_place_dur` | `(area, slot, ref, outDur, pos, noMirror)`: the frame goes to a scratch variable, no xform, not relative **[asm]** |
| `430890` | 226 | `slot_switch` | `(area, newSlot, oldSlot)`. If newSlot > 0: step(+44) = 0 and deadline(+48) = 0. Hides oldSlot (if ≥ 0) and shows newSlot (if > 0). Returns newSlot. **This is the "play animation X instead of Y" primitive** |
| `430930` | 49 | `slot_switch_pre` | The same, but step = −1, so the first advance lands on step 0 |
| `430a30` | 20 | `slot_nudge` | `(area, slot, ?, dx, dy)` → `objAdjPosition(spr, dx, dy)` unless slot = −1 |
| `430440` | 32 | `slot_attach_pos` | `(area, slot, ref, int out[2], mirror)`: computes the same anchor-relative position as `slot_place`, but for the step's frame and **without** moving or setting the image (a query) |
| `4309c0` | 82 | `olist_add_sprite` | `(oO **list, area, slot, int noFlip)`: appends a 0x1c `oO` entry `{area, slot, 1, 0,0,0, kind=2, …, [0x1a] = (noFlip==0)}` with `FUN_00486ee0`. It registers a sprite as a hit/target candidate |
| `44eb00` | 74 | `ned_show` | `(visible)` → `objSetVisibility` of Ned's current display slot (`DAT_004c6018`, area 1) |
| `44ea50` | 58 | `ned_cur_slot` | returns `DAT_004c6018`, the area-1 slot shown now |
| `44e9c0` | 60 | `ned_enable` | `(on)` → `DAT_004a5574`. `FUN_00454920` returns at once when it is 0 |
| `44ee30` | 45 | `ned_play_action` | `(action, int *pos)`: copies the 0x3c-byte action record `0x4aeb68[action]` into Ned state 15, resets it (`FUN_00450760(15)`) and primes it (`FUN_004518e0`); state (`DAT_004a5548`) = 15. Then it positions the sprite, using the slot's +0x1c/+0x1e and the wrap mode (§2.2), sets the flip fx and the image. Actions 2/0x1b set `DAT_004c864a` to −40/−50; 0x3c toggles the facing |
| `454920` | 32 | `ned_tick` | `(BC_world*, input, int *facing (0x4c5750), int nedPos[2], now_ms, ctx)`: the **player controller**, §2.1 |
| `4506f0` | 29 | `ned_reset_idle` | If `DAT_004c7210`: finish any pending action callback (`DAT_004c57bc`), then reset to state 4 (idle) and show slot 1 |
| `450760` | 20 | `ned_state_reset` | `(state)`: rewinds Ned state record `state`. It walks its phase slot lists backwards (end, loop, hold, start) and sets the record's current slot and phase bit to the first valid one, with that slot's step = −1 |
| `44f650` | 28 | `ned_set_wrap1` | `(wrap, width, xform)`: tick unit = 33 ms (`DAT_004c4d48`=0x21); wrap mode 1 = x modulo `width`; `DAT_004c5738` = xform |
| `44f5f0` | – | `ned_set_wrap2` | `(on, ?, tileW, nTiles, xform)`: on = mode 2 (x wraps by `tileW*nTiles` past 0x302a) **and tick unit 41 ms**; off = mode 0 at 33 ms |
| `44fd00` | 24 | `ned_list_free` | `(i)` → `res_free_list(PTR_DAT_004afb98[i], DAT_004afbf8[i])` |
| `44fdf0` | 19 | `ned_list_load` | `(i, cb, int *done)`: puts `cb` (or 0) in the **last** entry's +0x1c, sets `*done = 0` and calls `res_load_list(ned00000, list, n, list[0].scene)` |
| `44fd30` | 19 | `ned_list_show` | `(i)`: for each sprite entry calls `res_show_sprite(e, z = DAT_004c56d4, …)`, and unless slot flag 0x02 applies HORIZ_FLIP (made inactive) and keeps it at +0x38 |
| `4500c0` | 19 | `ned_find_target` | `(?, i16 *outSlot, oO *list, i16 *found, int *dist, i16 *?)`: if the list is non-empty, starts from Ned's centre (+0x20/2, +0x22/2) and runs `FUN_0044ff40` over the list. That keeps the nearest visible kind-2 sprite **in front** of Ned (by facing), measured to its rect 0 (or 3 if flipped) centre with `FUN_004885a0` (distance). The default result is 0x2f **(guess: grab or zap aim)** |
| `450210` | 21 | `ned_copy_cfg` | `(dst)`: copies 31 dwords from `DAT_004c52e8` to `dst+0x30` **(guess: save Ned tuning/state into an actor record)** |
| `455880` | 160 | `snd_play` | `(Slot *s, Slot *stop)`: stops `stop`'s voice and `s`'s old voice, then `FUN_0044d320(fmt=+5c, pcm=+54, len=+58, …, &s->voice)` creates a DirectSound buffer (flags 0x100c2 = STATIC\|PAN\|VOLUME\|GETCURRENTPOSITION2), copies the PCM in and calls `Play(0,0,0)` (once). Returns 0 or an error |
| `455800` | 24 | `snd_play_cb` | `(Slot *s, Slot *stop, ?, cb)`: like `snd_play`, but `s->+60 = cb` and the voice end calls `FUN_00455870` → `cb(s)` |
| `455a50` | 31 | `snd_play_at` | `(Slot *s, Slot *stop)`: positional. It takes the slot's centre in screen space (through the xform `DAT_004c6140`) relative to (320,240): **pan** = clamp(5·dx, ±5000), **volume** = −2·max(\|dx\|,\|dy\|), floor −7500 (in DirectSound hundredths of a dB) |
| `455930` | 57 | `snd_stop` | `(Slot*)` → `FUN_0044d100(&s->voice)` (Stop, Release, unlink) |
| `445ed0` | 112 | `now_ms` | QPC·1000/freq (or `timeGetTime`) − `DAT_004c3b88`, the same clock the main loop passes in |
| `446c10` | 44 | `pal_apply` | `(rgbxPal4 *src, mode)`: copies `src+4+4i` (r,g,b) into the DDraw palette block `DAT_004c3730`, with flags = 4 (PC_NOCOLLAPSE). Modes: 10 = all 256; 11 = 10..245; 12 = 0..9 and 246..255 (the system colours); 13 = 43..245. Then first = 0, count = 256, dirty = 1 |
| `467c40` | 29 | `attic_room` | returns `DAT_0051ed50`, the current room index in the attic hub. `FUN_004680e0` updates it each tick by `PtInRect(Ned pos)` against the room rects in the 0x54-byte room table at `0x497948` (the exits are at `0x497938 + room*0x54`) |

`slot_place` (`FUN_00430710`) **[asm]**:

```
s = &area[slot]; r = &area[ref]
(frame, dur) = seq_step(s->seq, s->step)          // FUN_00486930
objSetCurrentImage(s->spr, frame)
(sax, say) = anchor(s->box); (rax, ray) = anchor(r->box)   // eD [6],[7]
(fox, foy) = frame_off(s->box, frame)                       // eD frame hdr [0],[1]
pos = relative ? s->pos + r->pos : r->pos                   // +00/+04
d   = rax - sax + fox
pos.x = noMirror ? pos.x - d : pos.x - s->w + d             // mirror about the right edge
pos.y += say - ray - foy
if (xform) xform(pos)                                       // world -> screen (scroll)
objSetPosition(s->spr, pos.x, pos.y)
```

Typical use: `slot_place_x(area, s, s, &f, &d, &p, 1, scrollFn)` puts slot `s` at its own stored
position, with its anchor applied. Using `ref ≠ slot` glues a sprite to another sprite's anchor
(for example a hat on Ned).

### 2.1 The Ned controller (`FUN_00454920`) in brief

Ned's actions are **state records**: `DAT_004c4d50[state]`, 0x3c bytes each. +0x00 is a phase
bitmask (0x20 hold, 0x40 end, 0x80 tail, 0x100 loop, 0x200 start, plus 0x10000000 and 0x20000000
modifiers). +0x04 is the current slot. +0x0c/+0x10.. a 5-slot start list; +0x18/+0x1a.. a 2-slot
loop pair; +0x1e/+0x20 the hold slot; +0x22/+0x24.. a 5-slot end list; +0x2e/+0x30.. a 5-slot
tail list. Every list is −1 terminated.

`FUN_004518e0(state, now, &finished)` steps the current slot by ±1 (by slot flag 0x01). When the
slot runs out it moves to the next slot of the phase or to the next phase. It then sets the
deadline `+0x48 = now + dur*unit` and calls the per-slot frame callback (§3.3).

Input handling (`uVar12 = input & 0xff`, `hi = input & 0xff00`): 0x100 → state 9/10; 0x800 →
state 10; 0x200 → state 0; 4 → state 5 (through `FUN_00452130`); 0x20 → state 6/0xd; 1 or 2 →
walk (`FUN_004546e0`, with the direction relative to the facing); nothing → state 4 (idle). After
30 s idle (`DAT_004a554c + 30000`), state 3 is a random fidget, chosen from 11 two-entry lists at
`0x4a63e0`; they load on demand and the previous one is freed. Per-state hooks live at
`DAT_004c56d8[state]`. The state numbers are **guesses** apart from 4 (idle) and 15 (scripted
action).

### 2.2 Coordinates

Ned's world position is an `int[2]` passed by pointer: `DAT_00525df8/fc` in S4/S5/S6/S2 and others,
`DAT_005245e8` in S1, `DAT_0051e178` in S3 sub 1, `DAT_004bcb20` in S7.

The **scroll offset** in the attic is `DAT_00525910/14`. The xform callbacks `FUN_004039e0` and
`FUN_00404ef0` do `p += (DAT_00525910, DAT_00525914)`, so screen = world + offset.
`FUN_00407c50` (the attic camera, called after `ned_tick`) adjusts the offset by bands of Ned's
screen x (for example near 0x1b8 = 440). It moves Ned with `objAdjPosition` and repositions every
background record `rec[6]` at `rec[0..1] + offset`.

The other scenes keep their own offset globals; that is the 6th argument of `ned_tick` (for
example `DAT_005201c8`, `DAT_00523448`) **(guess)**. The wrap modes in §2 make horizontally
looping levels possible.

---

## 3. Animation

### 3.1 The `yX` record (`xsdt`), verified from the accessors

| off (u16) | meaning | read by |
|---|---|---|
| +0x00 | magic `yX` (0x5879) | |
| +0x02 | ver 3 | |
| +0x04 | kind (1–9: 229/265/149/213/158/140/0/0/80) | `FUN_00486a30` only; **unused by the game (open)** |
| +0x06 | sprite: the `dsdt`/`spix` id that owns the frames (= own id unless aliased) | `458380` |
| +0x08 | a (always 1) | `486a30` |
| +0x0A | **nsteps** → slot+0x10 | `FUN_004869b0` |
| +0x0C | **rate** (always 24) | `FUN_00486bc0` |
| +0x0E + 4i | step i: **u16 frame, u16 duration** | `FUN_00486930(seq, i, &frame, &dur)`: returns −7 if i ∉ [0,nsteps) |

`FUN_00486930` uses `param_1[7 + 2i]` and `[8 + 2i]` (u16 index). The data confirms it: 128
sequences have a "u32 rate" of 0x10018 and up, which only makes sense if step 0 starts at frame
1+.

### 3.2 Timing

* **A tick is one main-loop iteration with no pending message.** WinMain (`FUN_00445f70`) passes
  `now = QPC*1000/freq - DAT_004c3b88` (or `timeGetTime()-base` when `QueryPerformanceFrequency`
  fails; `DAT_004a4824` = has QPC) to `FUN_0045a310(input, now)`. That calls the global hook
  `DAT_0051f760(input, now, &input)`, which may rewrite the input, and then the scene's m7
  (`record+0x28`).
* **Scene ticks throttle themselves to 41 ms** (≈ 24 fps): `if (now < last + 0x29) { Sleep(last
  + 0x29 - now); return; } last = now;`. This is in S4 `FUN_00404f10`, S3 `FUN_0046ea50`, S7
  `FUN_0042cf90` and S1 `FUN_0043cb90` (`next = now + 0x29`). The S0 menus use **83 ms**
  (`+0x53`, `FUN_00465f70`). Sub-scene ticks run inside the top-level tick's throttle.
* **The sequence duration unit is ms = dur × 41** (`0x29`) for scene sprites: the deadline is
  `+0x48 = now + (short)dur * 0x29` (`FUN_00432e20` and many others). For Ned it is `dur *
  DAT_004c4d48`: **33 ms** by default and 41 ms in wrap mode 2 (`FUN_0044f5f0`).
  The slot's `1000/rate` field (+0x0c) is never read.
* `trans_fps` (ned.ini) only controls the transition effects; it is not the game tick.

The per-slot step pattern (inlined at the call sites; for example `FUN_00422bf0` for slot
0x187):

```
if (playing && slot->deadline < now) {
    if (slot->step < slot->len - 1) slot->step++;   // or wrap to 0 to loop, or stop
    else  playing = 0 /* or switch slot via slot_switch() */;
    slot_place_x(area, id, id, &frame, &dur, &pos, 1, xform);   // sets image + position
    slot->deadline = now + dur * 41;
}
```

Looping, ping-pong and stopping are all decided by the caller; RDX `hseq` playback is not used for
timing. Freezing is done with `deadline = 0x7fffffff`.

### 3.3 Ned's frame-event table (`0x4a5578`, 426 × fn)

`FUN_004518e0` ends with `table[slot](slot, step, state)` on every step change. 392 entries are
`FUN_00451370`: on step 0, if the slot has a sound (+0x54), it plays it and stops the previous Ned
sound (`DAT_004c5734`). The 34 specials (for example `FUN_00451670` for slots 0x18, 0x19, 0x10c and
0x10f–0x114) play shared sounds such as footsteps at given steps (4, 6), guarded by flags. Since
the table sits after the code, the port can make it a 426-entry switch.

---

## 4. Collision

### 4.1 Sprite hit boxes (`eD`)

| addr | name | behaviour |
|---|---|---|
| `4860d0` | `box_rect` | `(eD*, frame, k, int out[4])`: copies rect k of the frame. 62 callers. The caller adds the sprite position and tests for overlap (often with `IntersectRect`) |
| `486130` | `box_hit` | `(eDa, fa, ka, xa, ya, eDb, fb, kb, xb, yb)` → 1 if both rects exist (x0 ≠ −0x7fff) and **strictly** overlap: `a.x0+xa < b.x1+xb && b.x0+xb < a.x1+xa && …y`. It has **no callers** (game code inlines the test); it is the reference semantics |
| `485450` | `box_frame_off` | frame offset (alt = the mirrored pair) |
| `485700` | `box_anchor` | eD [6],[7] |

The rect index convention: k = 0..2 for the unflipped sprite and k + 3 when the slot's HORIZ_FLIP
fx is active (`FUN_0044ff40`: `FUN_004860d0(box, frame, fxActive ? 3 : 0, …)`).

### 4.2 `BC` collision maps (`cbix`), layout from `FUN_00487220`, `FUN_00487f50`, `FUN_00487600`, `FUN_004876d0`, `FUN_0048a040` and the files

In memory (= file + 4: `FUN_00457a80` reads the file at buffer+4):

| mem off | file off | field |
|---|---|---|
| +0x00 | – | `u8 *mask`, fixed up to `base + 0x24 + 24*count` (`FUN_00487220`) |
| +0x04 | +0x00 | u16 ver 1 |
| +0x06 | +0x02 | magic `BC` (0x4342) |
| +0x08..+0x17 | +0x04 | `i32 x0,y0,x1,y1`: bounds (`FUN_00487f50`) |
| +0x18 | +0x14 | `i32` mask blob size (it is the `memmove` length in `FUN_00487600`) |
| +0x1c | +0x18 | i32 0 |
| +0x20 | +0x1c | `i16 count` (+pad) (`FUN_00487a40`) |
| +0x24 + 24i | +0x20 | **record**: `u32 type` (bit 31 = disabled; e.g. 0x401, 0x409, 0x408, 0x200), `i32 id` (e.g. 6000/6001 markers), `RECT {x0,y0,x1,y1}` (`FUN_00487a50`) |
| mask | | **`cC` 1-bit mask**: `u16 'cC' (0x4363), u16 1, i32 stride, i32 x0,y0,x1,y1`, then rows of `stride` bytes, MSB-first |

The records are named regions. Game code scans them by id or type, for example `FUN_00434de0`
looks for ids 6000/6001 and `FUN_0042c820` uses `IntersectRect` against Ned's box. The mask is
the **solid/floor bitmap**:

```
// FUN_0048a040(mask, x, y, &hit)     ('VC' 0x4356 variant: hit = (col[x] == y), u16 col[] at +0x18)
if (x0 <= x && x <= x1 && y0 <= y && y < y1)
    hit = mask[0x18 + (y-y0)*stride + (x-x0+7)/8] & bitTbl[(x-x0)%8]   // bitTbl 0x4b6dd0 = 80 40 .. 01
```

**[asm]** confirms the `(dx+7)/8` byte index (`LEA EAX,[EBX+7]; …; SAR EAX,3`), which looks like an
off-by-one against the bit index. It must be reproduced bit-exactly. Note that x1 is inclusive and
y1 exclusive.

| addr | name | behaviour |
|---|---|---|
| `4871e0` | `bc_new` | allocates a 0x3c empty BC (ver 1, `BC`). 21 callers |
| `487220` | `bc_fixup` | sets the mask pointer after the records; returns −6 if the magic is wrong |
| `487c50` | `bc_solid_at` | `(BC **, x, y)` → `FUN_0048a040(*bc->mask)`. 43 callers (Ned floor and wall probes) |
| `487f50` | `bc_bounds` | `(BC*, int out[4])` |
| `487600` | `bc_add_rect` | `(BC**, RECT*, type, id, int *outId)`: grows by 24 bytes, moves the mask up, appends |
| `4876d0` | `bc_del_rect` | `(BC**, id)` |
| `487430` | `bc_free` | |

### 4.3 The collision world (0x4c0 bytes, `FUN_00487250`) — the first argument of `ned_tick`

| off | field |
|---|---|
| +0x00 | last-hit map index (a cache that `FUN_00487d10` tries first) |
| +0x04 | map count (≤ 50) |
| +0x08 + 4i | per-map disabled flag |
| +0xd0 + 16i | per-map world bounds `x0,y0,x1,y1` |
| +0x3f0 | `VC` column-map (tested last) |
| +0x3f4 | user value (`FUN_00487400` set / `FUN_00487c90` get) **(guess: the current-floor BC or a mode)** |
| +0x3f8 + 4i | `BC*` per map |

| addr | name | behaviour |
|---|---|---|
| `4872a0` | `world_add_map` | `(W, BC**, x0,y0,x1,y1)`: a `VC` map goes to +0x3f0; otherwise appended (error −2 past 50). 48 callers |
| `487320` | `world_remove_map` | `(W, BC**)` |
| `487fc0` | `world_move_map` | `(W, BC**, RECT*)`: updates the world bounds, the BC bounds and the mask bounds (`FUN_0048a310`) |
| `487400` | `world_set_user` | see +0x3f4. 42 callers |
| `487d10` | `world_solid_at` | `(W, x, y)` → 1 if any enabled map whose bounds contain (x,y) has its mask bit set. With count == 1 it tests map 0 only. It tries the cached map first, then all of them, then the `VC` map. Callers: Ned's physics `FUN_00454080`, `455420`, `455550`, `453570`, plus `46c2a0`, `46bf10`, `46dd50` |

**The "426-entry response table" is gone:** `0x4a5578` is §3.3. No data-driven collision
response table exists; responses are coded in the scene and actor C code.

### 4.4 `oO` object lists and `.SST` files

`oO` = `{u16 'oO' (0x4f6f), u16 ver 1, i16 count, u16 pad, u8 reserved[0x104]}`; that header is
0x108 bytes and is all zero in every shipped file. **(guess: a char name[260] for the editor.)**
`count` entries of 0x1c bytes follow, and the allocation always holds one spare entry (size =
count·0x1c + 0x124). `.SST` files are this exact image: 0.SST is 740 bytes = 0x108 + 17·28.

Entry (14 × i16). The meanings come from `FUN_0043e460`, `FUN_00441330` and `FUN_004309c0` and are
checked against 95999001/98999002/UVULA/0.SST:

| idx | off | meaning |
|---|---|---|
| [0] | +0x00 | **area** (kind 2), or the NAF/area number for backgrounds (kind 0/1, for example 95, 98) |
| [1] | +0x02 | **slot / resource id** |
| [2] | +0x04 | 1 (sub-index for kind 0/1: `DAT_004ddb88[(area*15+slot)*100 + [2]]`) |
| [3],[4] | +0x06 | **x, y** → slot +0x00/+0x04 |
| [5] | +0x0a | **z** → slot +0x08 (100/200; backgrounds 1001/2000) |
| [6] | +0x0c | **kind**: 2 sprite slot; 0/1 bitmap record |
| [7],[8] | +0x0e | offsets → slot +0x14/+0x16 |
| [9],[10] | +0x12 | [9] is junk in files; [10] = 41 → slot +0x0c (ms/step), 24 on background entries |
| [11] | +0x16 | 0 |
| [12] | +0x18 | **transparent colour** → slot +0x28 (10, 177, 254) |
| [13] | +0x1a | **flip** → slot flags \|= 4 |

| addr | name | behaviour |
|---|---|---|
| `486cc0` | `olist_new` | calloc 0x124 bytes, `oO`, ver 1, count 0. 24 callers |
| `486d00` | `olist_free` | |
| `486ee0` | `olist_append` | `(oO**, entry[7 dwords])`: realloc to count·0x1c+0x124, then append |
| `486f50` | `olist_remove` | `(oO**, area, slot, [2])`: removes every match (72 callers) |
| `4870a0` | `olist_foreach` | `(oO*, cb, ctx)`: `cb(list, entry, ctx)` returns 2 = stop and return 2, 4 = delete this entry, anything else = continue. Returns 3 when done. 30 callers. Typical callbacks: `FUN_0043e460` (apply the placement to slots and bitmap records), `FUN_00441330` (place an area-5 slot at x,y + ctx offset, mirrored by +0x20, frame offset from eD) and `FUN_0044ff40` (the target scan) |
| `4871b0` | `olist_count` | |
| `486d20` | `olist_load_file` | `(path, oO**)`: reads the whole file; ver must be 1 |
| `45a560` | `sst_load` | `(areaIdx, scene, n, oO**)`: the file name is `"%02d%03d0%02d.sst"` from (`0x4afcd8[areaIdx]` = 99 − areaIdx, scene, n), under the data directory (`FUN_00430c70`). Examples: `99999001.SST`, `95999001.SST` |
| `45a4b0` | `sst_load_cached` | the same into the cache `DAT_004d17e8[n]`. Its decompiled format string `"%s%02d…"` is the neighbouring literal **(check)** |

There are also named SSTs (UVULA, PUBERTY, FALLTRAN, CREDIT, `9812SC02`, …), loaded by name.

---

## 5. Input → the `input` bitmask

`FUN_00446700`, called once per loop iteration from WinMain, **[asm]**-checked: each source
**replaces** the value; nothing is ORed together. The order is:

1. Joystick, `FUN_004885d0` (`joyGetPosEx(0)`, dwFlags 0xff; the first error disables it for good):
   X < 16000 → 0x01, X > 48000 → 0x02, Y < 16000 → 0x04, Y > 48000 → 0x20.
   **`dwButtonNumber`** (the *count* of buttons held, not the button mask) == 1 → 0x100, == 2 →
   0x200, == 3 → 0x800.
2. Keyboard, `FUN_004887e0` (DirectInput `GetDeviceState(256)` into `0x5221b8`; it re-`Acquire`s
   on loss): Left 0xCB → 0x01, Right 0xCD → 0x02, Up 0xC8 → 0x04, Down 0xD0 → 0x20, Space 0x39 →
   0x200, LShift/RShift 0x2A/0x36 → 0x100, LCtrl/RCtrl 0x1D/0x9D → 0x800.
3. For each of (1) and (2): `if (lo) v = lo;` and then, if any high bit is set, `v` = the single
   button constant (`DAT_004a4808/0c/10` = 0x100/0x200/0x800, priority 0x100 > 0x200 > 0x800).
   **A button therefore discards the directions** of the same device, and a keyboard result
   overrides the joystick result.
4. A raw key scan (`FUN_00488770`) overrides everything, last match winning: Z 0x2C → 0x400,
   C 0x2E → 0x1000, S 0x1F → 0x2000, A 0x1E → 0x4000, W 0x11 → 0x8000, O 0x18 → 0x10000,
   Esc 0x01 → 0x10000, Q 0x10 → 0x20000.

| bit | meaning (from consumers) |
|---|---|
| 0x01 / 0x02 | left / right (walk; `FUN_004546e0`) |
| 0x04 | up (state 5: jump or climb **(guess)**) |
| 0x20 | down (state 6/0xd: duck or climb down **(guess)**) |
| 0x100 | button 1 / Shift (state 9/10) |
| 0x200 | button 2 / Space (state 0). The S3 hook `FUN_00472a30` reads `input & 0x200` |
| 0x800 | button 3 / Ctrl (state 10). In the attic, 0x800 at the room edges is a door test (`FUN_00404f10`) |
| 0x400, 0x1000, 0x2000, 0x4000, 0x8000 | Z, C, S, A, W: consumed by scene code **(guess: debug or cheat keys; check)** |
| 0x10000 | O/Esc: WinMain calls `FUN_0045db30` (the options/pause screen, which loads NED86000) when `DAT_004c3b70` allows it; `FUN_00445f50(x)` sets that flag |
| 0x20000 | Q: if the current scene `FUN_0045a2e0()` is neither 0 nor −1, quit to scene 0 (`FUN_0045a0f0(0,-1)`, after `FUN_00475970`/`FUN_004759c0`) |

The tick does not run on a frame that has 0x10000 or 0x20000. When `DAT_0051dce4` is set (a video
is playing), WinMain calls `FUN_0045e060(0, now)` instead. When the window is inactive
(`DAT_004a4800 == 0`) it calls `WaitMessage`.

---

## 6. The render order per tick

* **One primary surface**: `DAT_004c3b54 = srfCreate(640, 480, 0)` (`FUN_004468f0`). It has
  `FX_DDRAW_RENDER_CALLBACK` → `FUN_00446a40` with the context `DAT_004c3730`. When `video full`
  is set it also gets `FX_FULL_SCREEN`; then `srfSetDestWindow` and `objPrepare`.
* **Palette**: `DAT_004c3730` = `{dirty, first, count, IDirectDrawPalette*, PALETTEENTRY[256]}`
  (the entries at `0x4c3740` are seeded from `GetSystemPaletteEntries`). `pal_apply`
  (`FUN_00446c10`) fills it and sets `dirty`. At render time `FUN_00446a40` creates the palette
  (`CreatePalette` 0x0c, or 0x4c when full screen, then `SetPalette`) or calls
  `SetEntries(0, first, count)` and clears `dirty`. **Port:** apply a pending palette just before
  presenting.
* **Composition is done entirely by RDX.** Every sprite and background is an object whose
  destination is `DAT_004c3b54` (`res_show_sprite`/`res_show_bitmap`/`res_attach_list`) and which
  has a draw order (slot+0x08 / OO z: larger z is assumed to be further back **(check against the
  dmix semantics)**). The tick only changes positions, images, visibility and fx, then calls
  **`srfDraw(DAT_004c3b54)` once**. It is the only surface that game code draws: 179 `srfDraw`
  sites, all on this handle as far as sampled. The other `srf*` users are `srfClearColor`/
  `srfSetColor` fills and the options screen (`FUN_0045db30` creates its own surface).
* A typical top-level tick (S4 attic, `FUN_00404f10`):

```
if (now < last+41) { Sleep(..); return 0; }  last = now
room = attic_room();  ned_screen = objGetPosition(Ned)        // door tests by input 1/2/0x800
FUN_00467bc0(now)            // attic_room update (PtInRect Ned pos)
ned_tick(world, input, &facing, &nedPos(0x525df8), now, scrollX)
FUN_00407c50(now)            // camera: adjust DAT_00525910/14, reposition backgrounds/props
if (!DAT_00525974) srfDraw(primary); else DAT_00525974 = 0    // skip one present
if (DAT_0052592c != -1) { FUN_00445f50(0); FUN_0045a0f0(DAT_0052592c, -1); }   // scene change
```

  The other scenes follow the same order: throttle → actor/scene logic → `ned_tick` → camera →
  `srfDraw` → a pending scene switch. Scrolling is done in one of two ways. (a) The attic moves
  every object by the scroll offset through the xform callbacks. (b) Parallax/backdrop scenes
  keep the objects fixed and shift the view inside a background with `objAdjView` (S1 graveyard,
  S5).
* **`FUN_00467c40`** is not a renderer. It returns the attic room index that tick logic uses
  (§2).

---

## 10 most important open questions

1. **dmix draw-order semantics.** Does a larger `objSetDrawOrder` value draw behind or in front?
   And how do sprite and background z (100/200 vs 1001/2000) interleave? This decides correct
   layering for every scene.
2. **`yX` kind (1–9).** Nothing in the game reads it (only `FUN_00486a30` fetches it). Confirm
   that it is editor-only, or find a reader in the RDX `hseq` path.
3. **Slot +0x10/+0x20 flag bits and +0x18/+0x1a, +0x1c/+0x1e offsets.** They are used heavily in
   Ned's controller (`FUN_00452130`, `FUN_004546e0`, `FUN_004530f0`, `FUN_00452350`). Their exact
   roles need one pass through those four functions.
4. **The Ned state numbering** (0, 3, 4, 5, 6, 9, 10, 0xd, 0xf, 0x12, 0x13, 0x15, plus
   `DAT_004c56d8[]` hooks). Map each state to its action (walk, jump, climb, zap, …) from the
   action table `0x4aeb68` and the per-state slot lists.
5. **The `BC` record types** (0x200, 0x401, 0x408, 0x409, …, bit 31 disabled) and well-known ids
   (6000/6001 …). Who interprets them (ladders, hazards, exits)? Survey all `FUN_00487a50` callers
   and tabulate the type → behaviour mapping.
6. **The `(dx+7)/8` mask indexing.** Verify against an actual level: render a `cC` mask with
   both formulas over its background, to rule out a deliberate one-pixel shift in the mask
   encoder.
7. **World +0x3f4 user field** (`FUN_00487400`/`FUN_00487c90`, 42 callers, set from
   `DAT_00525da8`) and the per-map disabled flags at +0x08. What toggles them? Probably
   floor-layer switching (front/back planes).
8. **Kind 0/1 `oO` entries and `DAT_004ddb88`.** That is the indexing `(area*15 + slot)*100 +
   [2]` into an array of bitmap-record pointers, and the meaning of [2] (layer?) and of 1001 vs
   2000 z. Also, which `.SST` is loaded by which scene (the `sst_load` callers) and whether area 0
   in UVULA.SST is valid.
9. **The `ned_tick` 6th argument and `DAT_004c5738`/`DAT_004c6140` xform callbacks per scene.**
   Confirm that the 6th argument is the scroll context, and list each scene's world → screen
   transform. Sound pan depends on it (`snd_play_at`).
10. **Timing fidelity.** Ned's steps use a 33 ms unit while scene ticks run every ≥41 ms, so Ned
    can lag behind its deadlines and advance only one step per tick. Check whether
    `FUN_004518e0` is called once per tick (frames get stretched) or loops until it catches up.
    This matters for matching the original animation speed in ScummVM.
