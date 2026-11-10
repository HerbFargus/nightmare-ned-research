# Nightmare Ned — M0 recon notes

2026-10-17. Engine name: **`nightmarened`**. Plan and milestones: [SCOPE.md](SCOPE.md).

## Tooling

| Tool | What it does |
|---|---|
| `tools/is3extract.py ARCHIVE [OUT] [--list] [--only S]` | InstallShield 3 `.z` lister/extractor (pure-Python blast). `extracted/` = `data32.z` + `dataw32.z`; `extracted/rdx/` = `RDXData.Z` |
| `tools/naf.py` | NAF reader + every codec: `Naf`, `lzw`, `container`, `background`, `sprite_frames`, `rdx_image`, `wave` |
| `tools/nafdump.py OUT NAF...` | dumps backgrounds/sprite frames to PNG, sounds to WAV, `seq.json`, `hit.json`, `cb/*.bin`, `index.json`. All 12 NAFs: **0 errors** (~1 min) into `out/naf/` |
| `tools/ghidra_all.bat` → `tools/ghidra_seed.bat` | Ghidra import + export, then a second pass that creates functions at `out/seeds.txt` (code pointers in `.data`/`.rdata` + post-padding starts). Result: **1,834 functions**, `out/functions.csv`, `out/decomp/<addr>.c`, `out/callgraph.csv` |
| `tools/ghidra_rdx.bat` | same for `Dino2d.dll` (361 fns) and `dmix.dll` (466 fns) → `out/rdx/<dll>/` |
| `out/scenes.json` | the scene/sub-scene method table parsed out of the 8 registration functions |

The first Ghidra pass found only 940 functions (328 KB), because most of the game is reached only through function-pointer tables. The seeded pass covers 533 KB of the 590 KB `.text`.

## NAF archives (`RIFF` form `NNAF`)

Loader: `FUN_00456600` (mmio). Chunks:

- **`head`**: 0x98 bytes, where `+8`/`+12` are the first and last scene numbers; then `u32 n` and `n` scene ids. Each `NNdt` chunk holds one scene's data, in that order.
- **`??ix` index** (`xsix dsix spix bmix cbix auix`): `u32 slots; i32 first[nscenes]; i32 last[nscenes]; {u32 off, u32 size}[slots];` then for each listed scene with `first >= 0` a `u16 slot[last-first+1]` (0xFFFF means none). **Offsets are absolute file offsets**, including for `xsdt`/`dsdt`. A resource is addressed as **(scene, id)**. Some indexes have 4–64 spare bytes at the end; their purpose is unknown and harmless.
- **`xsdt`**: `yX` animation sequences, all version 3: `u16 magic, ver, kind, sprite, a, nframes; u32 rate (0x18 = 24)`, then frame data (frame 0's duration, then `(frame, duration)` pairs).
- **`dsdt`**: `eD` hit boxes per sprite: a 16-byte header (`magic, ver 6, nframes, w, h, ?, anchor x, y`), then per frame 0x68 bytes = 8 header bytes + **two sets of 3 rects** (`i32 x0,y0,x1,y1`, where `x0 = -0x7fff` means none). The collision test is `FUN_00486130`; an in-memory `dD` variant picks set B. 171 sprites have no hit boxes.
- **`NNdt`**: bulk data.

### `cC` containers (sprite banks and backgrounds)

`'cC' u16 1, kind ('TRPS' sprite bank / 'KCAB' background), u16 na, u16 nb, codec FourCC, u32 hdrSize, u32 hdrOff, u32 dataOff, {u32 off, u32 size}[...]`. The exe's codec library (`FUN_00489260`) knows three codecs: **`LZ78`** (the only one used), `TIB9`, and raw.

**LZ78 is really LZW** (`FUN_0048a750`): MSB-first bit packing; codes start at 9 bits; `0x100` = end, `0x101` = widen the code by one bit, `0x102` = reset; the first free code is 0x103. It's in `naf.lzw`.

- **Backgrounds** (`bmix`): the header is `u16 w, h, bpp(8), ?, ?` followed by a 256-entry `(r, g, b, flags)` palette. The payload is `w*h` 8-bit pixels. Most are full scrolling backdrops (up to 2560×480 or 640×1427); others are tile sets (NED90000 has 45 tiles of 512×320, NED94000 has 160-wide strips, and NED95000 has 24 strips of 80×960 that form a 1920×960 level).
- **Sprite banks** (`spix`): a `u32 unpacked size` comes before the `cC`. The LZW payload is `u32 size[n]` followed by n **RDX compressed images**, where `n = offset of the first GUID / 4`.

### RDX compressed image (Dino2d `FUN_100018f0`)

`GUID 9c8a5a80-3718-11d0-bf20-00a0c91a2629`, then `u32 w, h, bpp(8), 0x0a, size, size, rows`, then opcodes starting at +44:

| op | bytes | meaning |
|---|---|---|
| `00 n` | 2 | skip n (transparent) |
| `01 n c c c c` | 6 | n × colour c |
| `02 n px[n]` | 2+n | literal |
| `03 n k col[k] mask… 00` | 3+k+m+1 | n pixels; opaque where a mask bit (LSB first) is set, taking colours in order; the mask bytes are **zero-terminated** |
| `04` | 1 | end of row (x must equal w) |
| `05` | 1 | end of image |

All **6,721 frames** in the game decode with exact row widths. Sprites carry no palette, so they use the scene background's palette.

### Other resources

- **Audio** (`auix`): 18-byte WAVEFORMATEX followed by PCM. There are 614 sounds: mostly 22050 Hz 8-bit mono, 12 at 44.1 kHz 16-bit, and a few others. Area music is in `SOUND/<area>002208.wav` inside `data32.z`.
- **`cbix`**: `BC` level collision maps. A header (world bounds, e.g. 1920×941) is followed by typed rect records (`type` like 0x401, `id`, `x0,y0,x1,y1`). The type indexes the 426-entry response table at `0x4a5578` (392 of the entries are the default handler `FUN_00451370`). `FUN_00487450` can also load a `BC` from a file, probably a dev path.
- **`.SST`** (40 files in `data32.z`): `oO` **motion-path** objects (`FUN_00486cc0` allocates 0x124 bytes; it has 24 callers spread across the scenes). They're named `%s%02d%03d0%02d.sst` (area prefix from the table at `0x4afcd8`, scene, index) and loaded on demand by `FUN_0045a4b0`. They are data, not scripts.
- **Video**: 78 × SMK2 640×480 (`Video::SmackerDecoder`).

## The executable

- An MSVC Win32 build; it uses Intel RDX (`Dino2d`: backgrounds, sprites, sequences, grids, tiles; `dmix`: surfaces, objects, groups, effects), Smacker, DirectSound, DirectInput, and `joyGetPosEx`. `WinMain` = `FUN_00445f70`.
- **Main loop:** PeekMessage, then every tick `FUN_0045a310(input, ms)` calls the global state hook `DAT_0051f760` (normally a no-op, `FUN_00472a20`; `FUN_00472a30` is a special mode) and then the **current scene's `m7` tick**. Timing comes from QueryPerformanceCounter or `timeGetTime`; `trans_fps` sets the transition frame rate.
- **Scene graph:** `FUN_00459360` registers a top-level scene: 11 methods (`m0`–`m10`) plus an id, stored as 0x38-byte records in `DAT_004c7170`. `FUN_00459690` adds sub-scenes. `FUN_0045a0f0(scene, sub)` switches scenes: it calls the old scene's `m7`/`m8` exit hooks, then the new scene's `+0x14`/`+0x18` (`m2`/`m3`, i.e. load and enter). `out/scenes.json` lists every method.

| scene | registered by | subs | clues |
|---|---|---|---|
| 0 | `4654b0` | – | `hatmandirtnap` pref; options/menu? (NED86000 = options screen art) |
| 1 | `43c140` | 8 (2 empty) | **graveyard**: `[Grave Videos]`, GRVA/GRVB/MASA/MASB SMKs, `trans_fps`, the Reaper/Tree/Pumpkin/... enemy records at `0x4a3318`. Sub 5 owns the only two `FX_SMORPH` users |
| 2 | `449f70` | 4 | `87040001.wav`, `8724tv01` |
| 3 | `471b80` | 2 | `8714`–`8720tv01` TV clips |
| 4 | `403a40` | – | **attic hub**: `InitialAtticScene`, `8702`/`8710`–`8713tv01` |
| 5 | `41de90` | 2 | `8705tv01`, `8742`/`8727`/`8728`/`8744` voice |
| 6 | `434830` | 4 | `8715`/`8746tv01`, CD/directory checks |
| 7 | `42f3e0` | – | `8745tv01`, `8721`/`8723` voice |

The scene numbers don't map one-to-one to NAF files: a scene loads several NAFs (`ned00000.naf` is shared), and NAF scene ids are per-file. M1 needs the scene ↔ NAF ↔ area mapping (the loader's callers are `44f710`, `445990`, `475300`, `4613d0`, `479ff0` and `45da60`). From the art: NED86000 = options, NED01000 = throat/uvula set, NED95000 = chalkboard level ("Ned Start Point"), NED97000 = dungeon corridor, NED98000 = junkyard tree, NED99000 = swirl sky.

- **It is a side-scrolling action platformer.** NED95000 is a 1920×960 chalkboard level with ladders, platforms and a "Ned Start Point", using typed collision rects, per-frame hit boxes, motion paths and joystick input. **There is no script VM.** All behaviour is C: scene methods, the actor classes below, and the collision response table.
- **Actor classes:** there are 22 six-slot vtables at `0x497a10`–`0x49819c` (~33 KB of methods), 9 seven-slot vtables at `0x4b2010`–`0x4b22d0` (~10 KB), 7 × 23-entry tables at `0x4ae578`–`0x4ae998` (~25 KB, 20 KB of that in `0x4ae998`), and 12 graveyard enemy records at `0x4a3318` (name, 3 methods, tuning).
- **FX_SMORPH** is used only in `FUN_00402fa0` and `FUN_00403430` (scene 1 sub 5). It builds a 480-row per-scanline offset table over 30 steps, so it's a horizontal wobble/warp transition. That's a simple scanline-offset blit and **no longer a risk**.
- The game has a built-in sprite-bank writer (`compression_add_frame/save`, "already exists, overwrite?"). It's a dev tool and won't be ported.

## Size

| | bytes | decompiled lines |
|---|---|---|
| whole `.text` | 590 KB | 91k |
| CRT + codec library (≥ `0x488000`) | ~46 KB | ~13k |
| **game code** (scenes, actors, collision, UI) | **~460 KB** | **~78k** |
| shared helpers among that (≥ 6 callers) | ~28 KB | |

Assigning functions by address to the nearest registered scene method gives (KB): S0 13, **S1 77** (graveyard + 6 subs), S2 47, S3 70, S4 18, S5 62, S6 75, S7 28, plus ~68 KB of unassigned engine-side code (NAF, sound, input, actors). That's roughly **6× Devil Manor's 12k lines of room logic**. RDX itself is not in the exe; we reimplement the 53 imported calls.

## M0 answers

1. **Logic:** all C, with no VM. `xsdt` is animation timing and `dsdt` is hit boxes.
2. **`cbix`:** level collision rects; the 4-character tags were the `cC`/`TRPS`/`KCAB`/`LZ78` container fields.
3. **`FX_SMORPH`:** one transition effect (scanline wobble). Trivial.
4. **Release:** US English, Win95, September 1997 build. No other versions seen yet.

## M1 (2026-10-17)

Engine skeleton is on branch `nightmarened`, commit `0c42a09fc1` (worktree `magic-school-bus/scummvm-nightmarened`, local only). Tooling is in `magic-school-bus/tools-nightmarened/` (`make.sh`, `boot.sh`, `play.sh`). The branch note is `NIGHTMARENED.md`.

- **Verified:** `nightmarened_checksums` and `tools/checksums.py` produce identical lists for all 7,742 backgrounds, sprite frames and sounds. The intro plays (DI → CAPERS → WINDP → INTRO; a frame-400 capture is correct). The attic, the chalkboard level and Ned sprites render with the right palettes.
- **File table** (`0x4a05d0`, 0x14 bytes per entry, resolved by `FUN_00430c90(index, buf)`; dumped to `out/filetable.json`): 0–11 are the NAFs, 12–87 SMKs, 81/121/124–134 area music WAVs, and 88–120 `.SST` files. The type field is 1 video, 2 data, 3 sound; the second field (1 or 2) looks like CD versus installed.
- **Scene → NAF** (each scene's `m2` load method): S0 → 92000, S1 → 99000, S2 (+ subs 0–2) → 93000, S3 → 97000 (sub 0 → **95000** chalkboard, sub 1 → 97000), S4 attic → 98000, S5 → 90000, S6 → 96000, S7 → 94000. 00000 (Ned, global) loads at start-up (`44f710`), 86000 (options) from `45da60`/`4613d0`, and 01000 (UI) from the intro and `479ff0`.
- **Intro** (`FUN_00445990`, skipped when `ned.ini [Intro Video] Ignore=1`): DI, then CAPERS (`445d00`), WINDP, INTRO. `FUN_00447420` is the "abort" check: Escape stops the rest. After the intro, WinMain calls `FUN_0045a0f0(0, -1)`, which enters scene 0.
- NED92000 (scene 0) holds only 8×1 palette bitmaps, so scene 0 is drawn entirely from sprites. The data quirk: a sprite bank's `cC` data size counts its own 4-byte prefix, so clamp it to the blob.

## M2 (2026-10-17)

Commits `30a660fef9` and `ae49611ede` on `nightmarened` (local). Two specs written for this milestone hold the detail: **[M2_ENGINE_LAYER.md](M2_ENGINE_LAYER.md)** (the request lists and loader, the 100-byte slot record, `slot_place`/`slot_switch`, Ned's controller in outline, timing, `BC`/`oO`, the input bitmask, the per-tick render order) and **[M2_RDX.md](M2_RDX.md)** (dmix/Dino2d object model, srfDraw, draw order, sprite/background/grid/smorph/flip rendering).

**Corrections to the M0 notes above** (those sections are kept as written; these override them):

- **NAF index bug (fixed in the tools and the engine):** *every* listed scene has a u16 slot table, even an empty one (`first = last = -1` still has 1 entry). Skipping those shifted every later scene's ids in multi-scene NAFs. All indexes now parse with zero leftover bytes, and 7,769 resources decode (up from 7,742). After the fix, 965 sequences own their frames, 271 are aliases of a sprite in the same scene, and 2 don't resolve.
- **`yX`:** seven u16 fields (`magic, ver, kind, sprite, 1, nsteps, rate`); `rate` is u16 at +0x0C; steps are `(u16 frame, u16 duration)` from +0x0E. `kind` is unused by the game.
- **`eD`:** header [5] is the transparent colour; rects 0–2 are for the normal sprite and 3–5 for the flipped one.
- **`0x4a5578`** is Ned's per-slot frame-event callback table (426 slots, mostly "play this slot's sound on step 0"), not collision.
- **`.SST` / `oO`** are **placement tables** (area, slot, sub, x, y, z, kind, offsets, ms/step, key, flip), not motion paths.
- **`BC`:** header, 24-byte `(type, id, rect)` records, then a 1-bit `cC` solid mask indexed with a quirky `(dx + 7) / 8` byte offset (copied exactly).
- **Timing:** scene ticks throttle to 41 ms (menus 83 ms); a sequence step lasts `duration × 41 ms` (Ned: × 33 ms, or 41 in wrap mode 2).
- **Draw order:** larger = further back; a re-insert goes below equal orders. srfDraw redraws everything every frame.

**Engine:** `rdx.cpp` (compositor), `resources.cpp` (slots, request lists read from NITENED.EXE via `ExeImage`), `data.cpp` (sequences, hit boxes, collision maps, placements), `display.cpp` (primary surface, palette modes with the Windows static colours, `slotPlace`/`slotSwitch`, collision overlay), `demo.cpp` (the attic built from list `0x497680` + `98999001.SST`: 179 objects and 9 collision maps, every sprite looping on the 41 ms tick; arrows scroll, F9 overlay).

**Not exercised yet** (no data path in the attic demo): FX_HORIZ_FLIP and its clip quirk, FX_SMORPH, grids, groups, child surfaces. Those come with the scenes that use them in M3. The demo looks up slot scenes by id, since the real lists for the attic's sub-rooms aren't wired up yet.

## M3 progress (2026-10-17)

Commits on `nightmarened` (local, not pushed): `476c404cb7` game state + scene graph + collision world; `09cc603a66` Ned's controller (agent port, ~2,300 lines); `38b626fc65` attic hub (scene 4, 22 rooms, ~6,900 lines) + the real WinMain loop. Porting rules: [PORTING.md](PORTING.md).

**Decompile fix:** Ghidra wrongly inferred that `0x430850` (slot_place_x, 198 callers) never returns, which cut the code after 408 calls. `tools/ghidra_rebuild.bat` rebuilds the project with "Non-Returning Functions - Discovered" off (`DisableNoReturn.java`) plus the seeding pass (`make_seeds.py`). `out/decomp` now has 1,828 functions; 196 of them gained 36 KB, and only ExitProcess/ExitThread remain no-return. The old export is kept in `out/decomp_pre_noreturn`. **The Ned port (`09cc603a66`) was written from the truncated decompile and must be re-checked** against the new `out/decomp` (diff `decomp_pre_noreturn` against `decomp` for Ned's functions, 0x44e9c0..0x455930). The attic agent had already re-decompiled its range correctly.

**Visions (hints module, `357774ed41`, merged in `7cc504d2b2`):** these are not tips. Each world has a shadow creature seen in three levels of vision (shadow, then half-revealed, then fully revealed with dialogue): graveyard (scene 1) an old man; attic (4) Ned's sister on skates; scenes 3/6 a boy with a basketball; scene 5 a toilet; scenes 2/7 an old woman/nurse. Each world has 6 trigger ids, of which 3 are enabled at random at new game; only enabled ones advance the level. Progress lives in `DAT_0051eb28[0..5]` (now `Hints::_progress`). Once all five worlds reach level 3, the game plays `end2.smk` (or clip 0x2f when `[5] == 8`), then the credits, then quits. While a vision plays, the WinMain input hook freezes Ned and it cannot be skipped (original behaviour). Test hooks: `nightmarened_hints_all`, `nightmarened_hint_progress`, `nightmarened_hint=<id>:<frames>`.

**Menus, options, saves (`7673691ee0`):** scene 0 is the **quilt**: five patches (graveyard = scene 1, "m" = 2, "s" = 3, attic = 4, "b" = 5). Left/Right rolls the quilt (QUILT/QUILTR.SMK), Up zooms in (X0000.SMK, then the world's picture for its vision level), Shift enters, Down zooms out. Coming back from a world plays the alarm-clock clip 8733..8741TV01 (one hour lost per return). The options screen is Ned's head: back, credits, music volume, quit, new game, load, keys help, save. Saves are `nightmarened.001..008` (the game's GAME01..08 body plus the hints block plus ScummVM's extended header), and they load from the launcher too. Cheat: ned.ini `hatmandirtnap=0x205` enables scene keys. Corrections: file-table 0x50/0x52 = QUILT/QUILTR.SMK, 0x82 = menu music; SmackGoto is 1-based; m6 is teardown at exit (0x45a350).

## M3 worlds (2026-10-18)

Every scene is ported and merged on `nightmarened` (latest merge `a85da5269b` + merge commit; local, not pushed). Each world was ported by an agent in its own worktree (`magic-school-bus/scummvm-nn-<name>`, built with `WT=<dir>` for the tools-nightmarened scripts), then merged here.

| scene | world | notes |
|---|---|---|
| 0 | the quilt (menus) | + options screen, ScummVM saves |
| 1 | graveyard | looping, Smacker-video backdrop seeked per tile; 11 creatures; subs: crypt (0), zombie cave (2), graves 3–5 (parlour, sofa, painting with FX_SMORPH zoom), dim room (7). 'VC' column collision maps added for its floor |
| 2 | hospital | dark room (0) → gurney ride (1) / mouth (scene 7) / attic; jar room (2); sub 3 empty |
| 3 | school detention block | 9 streamed rooms, wraps; sub 0 = chalkboard school, sub 1 = switchboard room |
| 4 | attic hub | 22 rooms, TV clips |
| 5 | bathroom & plumbing | wraps, 45 hand-placed tiles, walking bathtubs; subs: toilet hall (0), washroom (1) |
| 6 | playroom | fortune-teller picks 4 monster rooms (subs 0–3); entered from scene 3 |
| 7 | the mouth | biting jaw, monsters, cavities |

Shared modules from the ports: `hints.*` (visions), `media.*` (TV clips; `playClipWithMusic` = 0x47a6b0), `slotanim.*` + `slothelpers.*` (generic slot helpers), `puff.*` (zap puff 0x4770a0), `placements.*` (0x45a560/0x43e460). `tools-nightmarened/keepboth.py` resolves the usual registration conflicts.

**Smoke sweep:** all 24 scene/sub starts boot with no warnings (`magic-school-bus/nightmarened-tests/sweep/sheet.png`). Ghidra: `tools/ghidra_gaps.bat` recovered 57 functions no pointer reached (`out/new_gap_functions.txt`).

**Known open items:**
- **Pacing:** sub-scene ticks that were unthrottled in the original run at 41 ms.
- **Untested flows:** exits not reached by scripted input in several worlds (see each port's report in the session); ladders/hanging/ropes in play.
- **Not ported:** music fades; joystick in the options screen; 0x47a110 (Install_Level=0 still pictures).
- **Not done:** a full playthrough.
