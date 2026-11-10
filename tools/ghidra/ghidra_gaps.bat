@echo off
rem Extra pass: create functions at out\seeds_gaps.txt (prologues in code gaps no pointer reaches), re-export.
for %%I in ("%~dp0..\..") do set ROOT=%%~fI
if not defined GHIDRA for %%I in ("%~dp0..\..\..\ghidra\ghidra_12.1.4_PUBLIC") do set GHIDRA=%%~fI
call "%GHIDRA%\support\analyzeHeadless.bat" "%ROOT%\out\ghidra" NightmareNed -process NITENED.EXE ^
  -scriptPath "%ROOT%\tools\ghidra" -preScript CreateFunctions.java "%ROOT%\out\seeds_gaps.txt" ^
  -postScript ExportFunctions.java "%ROOT%\out\functions.csv" -postScript ExportDecomp.java "%ROOT%\out" -max-cpu 8
