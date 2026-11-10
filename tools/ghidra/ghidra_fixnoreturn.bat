@echo off
rem Third Ghidra pass: clear the wrong no-return flag on 0x430850 (slot_place_x), refit bodies, re-export.
for %%I in ("%~dp0..\..") do set ROOT=%%~fI
if not defined GHIDRA for %%I in ("%~dp0..\..\..\ghidra\ghidra_12.1.4_PUBLIC") do set GHIDRA=%%~fI
call "%GHIDRA%\support\analyzeHeadless.bat" "%ROOT%\out\ghidra" NightmareNed -process NITENED.EXE ^
  -scriptPath "%ROOT%\tools\ghidra" -preScript FixNoReturn.java 430850 ^
  -postScript ExportFunctions.java "%ROOT%\out\functions.csv" -postScript ExportDecomp.java "%ROOT%\out" -max-cpu 8
