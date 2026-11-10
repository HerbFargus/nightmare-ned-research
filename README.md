# Nightmare Ned: research notes

Notes and tools from reverse-engineering **Nightmare Ned** (Creative Capers / Disney Interactive, 1997, Windows): the NAF resource archives, the engine layer, the RDX data, and the InstallShield 3 archives the game ships in.

The ScummVM engine built from this work is on the `nightmarened` branch of the fork: https://github.com/HerbFargus/scummvm/tree/nightmarened (see NIGHTMARENED.md there).

## Notes

- `NOTES.md`: the formats and the engine
- `M2_ENGINE_LAYER.md`: the engine layer
- `M2_RDX.md`: the RDX data
- `SCOPE.md`: the plan the engine followed

## Tools

Python 3 unless noted; most need only the standard library.

- `tools/naf.py`: NAF archive reader (RIFF "NNAF")
- `tools/nafdump.py`: dump every resource in the NAF archives
- `tools/is3extract.py`: InstallShield 3 .z archive lister and extractor
- `tools/checksums.py`: resource checksums, as the engine computes them
- `tools/make_seeds.py`: function seeds for the Ghidra CreateFunctions script
- `tools/png8.py`: minimal 8-bit palette PNG writer

## Ghidra scripts

Headless Ghidra scripts and the batch files that ran them. Set GHIDRA to your Ghidra install; the batch files otherwise look for one beside the project.

- `tools/ghidra/CreateFunctions.java`
- `tools/ghidra/DisableNoReturn.java`
- `tools/ghidra/ExportDecomp.java`
- `tools/ghidra/ExportFunctions.java`
- `tools/ghidra/FixNoReturn.java`
- `tools/ghidra/ghidra_all.bat`
- `tools/ghidra/ghidra_fixnoreturn.bat`
- `tools/ghidra/ghidra_gaps.bat`
- `tools/ghidra/ghidra_rdx.bat`
- `tools/ghidra/ghidra_rebuild.bat`
- `tools/ghidra/ghidra_seed.bat`

## Not included

No game files, extracted assets, screenshots, or decompiled or disassembled
game code are in this repo. The tools work on your own copy of the game.

## About these notes

The research and the tools were written with an LLM (Claude), working from
the games themselves. They are published as a reference for how the formats
and the engine work. Check anything you rely on against the games.

The matching ScummVM engine on the fork is AI-written too and is not a ScummVM
contribution: ScummVM's AI guidelines do not allow AI-authored submissions.
Anyone writing a real engine should treat this repo as notes, not code to copy.

## Licence

GPL-3.0 (see LICENSE), the same as ScummVM.
