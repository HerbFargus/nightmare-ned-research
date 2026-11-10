# Nightmare Ned — ScummVM engine scope

Draft, 2026-10-17. Decisions: the engine is named **`nightmarened`**, and the goal below is confirmed. **M0, M1 and M2 are done, and M3 (all scenes) is ported and merged; see [NOTES.md](NOTES.md).**

## M0 results (summary)

- **Every resource decodes** (`tools/nafdump.py`, 0 errors): 407 backgrounds, **6,721 sprite frames**, 614 sounds, 1,234 animation sequences, 1,063 hit-box sets, and the collision maps. The "LZ78" codec is really LZW. Sprites are Intel RDX compressed images; the opcodes came from `Dino2d.dll`, and every frame decodes at exact row width.
- **This is a side-scrolling action platformer**: scrolling levels up to 2560×480 or 1920×960, typed collision rects, per-frame hit boxes, motion paths (`.SST`) and a joystick.
- **There is no script VM.** The game is 8 top-level scenes with 20 sub-scenes (C method tables registered at start-up), about 40 actor classes behind vtables, and a collision-response table.
- **The code is big:** ~460 KB, about **78k decompiled lines** of game code, roughly 6× Devil Manor's room logic. Per scene it ranges from 13 to 77 KB.
- **`FX_SMORPH` is no longer a risk:** it's one scanline-wobble transition. Intel RDX is a small compositor (53 imported calls).
- **Revised estimate: 22–32 sessions.** M3 grows from 6–10 to 16–24 sessions.

## What we have

`reference-files/game-files/`: the retail Windows CD (Disney Interactive, 1997; the `CAPERS.SMK` logo suggests Creative Capers made it). It's a 640×480, 256-colour Win32 game built on DirectX 5, Intel RDX and Smacker. A web search found no existing reverse-engineering work and no ScummVM support.

| File | What it is |
|---|---|
| `data/data32.z` (60 MB) | **InstallShield 3** archive for the minimal install. It holds **`NITENED.EXE`** (the game), `SMACKW32.DLL`, `NED01000.NAF` + `NED99000.NAF` (**not loose on the CD**), 40 `.SST` files, 13 area music WAVs, and 5 `*T0071.SMK` videos |
| `data/data32_2.z` (106 MB) | the full-install archive: the same files plus copies of every loose NAF |
| `data/data/NED*.NAF` (10 loose + 2 in the archive) | resource archives, one per area (`00000` global, `01000` UI?, `86000`, `90000`–`99000`) |
| `data/video/*.SMK` (78, 312 MB) | Smacker **SMK2**, 640×480. Includes intro, endings, transitions and the `87xxTV01` TV clips |
| `rdx/RDXData.Z` | IS3 archive holding the Intel RDX runtime: **`Dino2d.dll`, `dmix.dll`**, rdxmmx/p5, mfc40, and Java classes |
| `ereg/`, `redist/` | e-registration and DirectX redistributables. We don't need them |

`tools/is3extract.py` is a pure-Python IS3 lister and extractor (a blast/DCL decoder). It got everything out with no size mismatches; the files are in `extracted/`. In the engine, `Common::InstallShieldV3` reads `data32.z` directly, so there's no install step.

### NITENED.EXE

- An MSVC Win32 PE with a 1997-09-16 timestamp. **`.text` is 0x93426 bytes (~590 KB of code)**, about twice the size of Devil Manor's. It's an optimized build that omits frame pointers (only 19 `push ebp` prologues), so it will decompile less cleanly. There are 57 switch jump tables. It has no RTTI, no MFC and no source-file strings, so functions have to be named by hand.
- **I found no scripting VM.** The strings point to hard-coded logic: per-scene video and WAV pairs (`87050001.wav` + `8705tv01.smk`), the graveyard enemy roster (Treater, Reaper, Pumpkin, Zombie, Ghoul, Mourners, Goblin, Coffin, Swamp Creature, Statue), `[Grave Videos]` ini keys, and `InitialAtticScene`. M0 has to confirm this.
- **It's a real-time game, not point-and-click.** It uses DirectInput keyboard and joystick (`joyGetPosEx`), `GetAsyncKeyState`, a `ShowCollisionRects` debug option, collision tests and a QueryPerformanceCounter timer. Faithful timing and collision are what make or break the port.
- The sprite codec belongs to the game itself: the `compression_load/get_frame/add_frame/save` functions handle the `SPRT`/`LZ78` blobs. The exe also has a sprite *writer* and an "overwrite file?" prompt, so a dev tool is probably still built in.
- Saves are `.SST` snapshots (`%s%02d%03d0%02d.sst`, `SaveLoadDir`), and some ship in `data32.z`, probably as per-area start states. Preferences live in `ned.ini` (`MusicVolume`, `trans_fps`, `video_full`, `RequireCD`, and a mystery `hatmandirtnap` key).

### NAF format (first look)

A NAF is a RIFF file of form `NNAF`. The chunks are:

- `head`: a version, an ID range (`0x63` = 99 slots?) and the Disney copyright.
- `xsdt` + `xsix`: records with magic `yX`, which look like **animation sequences** (a list of frame number + duration pairs, mostly 2 ticks).
- `dsdt` + `dsix`: records with magic `eD`, which look like **display objects**: positions, rects, draw order and frame references, using `0x8001` as "none".
- `00dt`…`16dt`: the bulk data, holding sprite banks (`cC` `SPRT` `LZ78` + an embedded 256-colour palette) and backgrounds.
- `spix`, `bmix`, `cbix`, `auix`: index tables for sprites, background bitmaps, an unknown type, and **audio** (sound effects and voice live inside the NAF).

The index chunks share a common layout: a count, an ID base (`0xD7`), an ID span, (offset, size) pairs, and an ID→slot remap table.

### Intel RDX: the part that needs reimplementing

The exe imports only **27 functions from Dino2d** (backgrounds, sprites, bitmap sequences, grids and tiles, transparency colour, compressed image, plus the `FX_HORIZ_FLIP`, `FX_SMORPH` and `FX_FULL_SCREEN` effects) and **26 from dmix** (surfaces, objects, groups, position/view/dest rect, draw order, visibility, current image, apply and remove effect). That is a small sprite compositor and maps easily onto `Graphics::ManagedSurface`. The risk is **`FX_SMORPH`** (a mesh morph or warp effect). If it's used in a visible way, I'll reverse it from `Dino2d.dll` (`FxSmorphRender8`).

### What ScummVM already gives us

`Video::SmackerDecoder` (SMK2), `Audio::makeWAVStream` (22050 Hz, 8-bit mono), `Common::InstallShieldV3`, `Common::INIFile`, and the save/load and keymapper infrastructure.

## Goal (proposed, to confirm)

Same model as Big Tuna, Magic School Bus and Devil Manor: a **new ScummVM engine that reimplements the game from the reverse-engineered exe**. It plays the CD start to finish, with ScummVM saves, keymapper/joystick support and the original options. It lives on its own branch of the `HerbFargus/scummvm` fork and merges into `scumm-llm` after playtesting. It never goes upstream (fork attribution rule). The aim is a faithful reimplementation, not a bit-for-bit port.

Proposed engine name: **`nightmarened`** (or `capers`, if M0 finds this is a reusable Creative Capers engine).

## Milestones

**M0 Recon** (1–2 sessions) — **DONE 2026-10-17**, see NOTES.md
- Load NITENED.EXE in Ghidra (`../ghidra`, native PE). Label the RDX, Smacker and DirectX imports, then name functions outward from them: the NAF loader (`NNAF`/chunk tags), the codec (`compression_*`), and the sound and video players.
- Decode every NAF chunk type: the sequences, display objects, LZ78 sprites + palettes, backgrounds, `cbix` and audio. Also decode `.SST` saves.
- Write `tools/nafdump.py`, which dumps every sprite and background to PNG and every sound to WAV.
- **Logic inventory:** find the scene/area dispatcher, list the per-area handlers with their sizes, and confirm that no script VM exists. Map the NAF numbers to game areas.
- Check `FX_SMORPH` usage.
- **Done when** every resource dumps cleanly and we have a logic inventory with a size estimate (this revises the estimate below).

**M1 Skeleton** (1 session) — **DONE 2026-10-17** (`0c42a09fc1`, see NOTES.md "M1"): detection (the CD files + `data32.z`), the NAF archive reader, the palette, the intro SMK, and a background drawn on screen.

**M2 RDX compositor + game loop** (1–2 sessions) — **DONE 2026-10-17** (`30a660fef9`, see NOTES.md "M2"): objects, groups, draw order, views, sequences and timers on a fixed tick, flipping, collision rects, and the `ShowCollisionRects` debug overlay.

**M3 Game logic** (the bulk, 6–10 sessions): Ned's movement and controls, then the attic hub and TV clips, then each nightmare area one at a time (the graveyard enemies, and so on), plus transitions and endings. Rewritten from the decompile as C++, area by area, the way Big Tuna was.

**M4 Sound, saves, options** (1–2 sessions): music per area, sound effects and voice from `auix`, ScummVM saves (mapping the SST state), volume options, and a keymapper/joystick mapping.

**M5 Playtest and fix** (1–2 sessions): start-to-finish test runs through the `tools/` test hook (never foreground input), then merge into `scumm-llm`.

**Estimate after M0: 22–32 sessions** (M1 1, M2 2, M3 16–24, M4 2, M5 2). M3 is large: about 78k decompiled lines. Port it in this order: Ned plus the shared actor classes and collision first, then the attic hub, then one world per batch (scene 1 graveyard ≈ 77 KB, scene 6 ≈ 75 KB, scene 3 ≈ 70 KB, scene 5 ≈ 62 KB, scene 2 ≈ 47 KB, scene 7 ≈ 28 KB, scene 0 ≈ 13 KB). Most world batches can run as parallel sessions once the actor and collision base exists.

**M1 also needs** the scene ↔ NAF ↔ area map (who loads which NAF), plus a first pass naming the actor vtables.

## Open questions

The four pre-M0 questions are answered in NOTES.md ("M0 answers"). The format notes above are the pre-M0 first look; NOTES.md is authoritative.
