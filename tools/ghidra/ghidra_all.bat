@echo off
rem Full Ghidra pass over NITENED.EXE (native PE): import, analyse, export functions.csv, decomp\ and callgraph.csv.
rem   tools\ghidra\ghidra_all.bat
for %%I in ("%~dp0..\..") do set ROOT=%%~fI
if not defined GHIDRA for %%I in ("%~dp0..\..\..\ghidra\ghidra_12.1.4_PUBLIC") do set GHIDRA=%%~fI
if not exist "%ROOT%\out\ghidra" mkdir "%ROOT%\out\ghidra"
call "%GHIDRA%\support\analyzeHeadless.bat" "%ROOT%\out\ghidra" NightmareNed -import "%ROOT%\extracted\NITENED.EXE" -overwrite ^
  -scriptPath "%ROOT%\tools\ghidra" -postScript ExportFunctions.java "%ROOT%\out\functions.csv" ^
  -postScript ExportDecomp.java "%ROOT%\out" -max-cpu 8
