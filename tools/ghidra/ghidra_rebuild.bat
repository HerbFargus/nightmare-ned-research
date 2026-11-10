@echo off
rem Full rebuild of the NITENED.EXE Ghidra project without no-return inference:
rem import + analyse, seed functions reached only through pointers, export functions/decomp/callgraph.
rem   tools\ghidra\ghidra_rebuild.bat
for %%I in ("%~dp0..\..") do set ROOT=%%~fI
if not defined GHIDRA for %%I in ("%~dp0..\..\..\ghidra\ghidra_12.1.4_PUBLIC") do set GHIDRA=%%~fI
call "%GHIDRA%\support\analyzeHeadless.bat" "%ROOT%\out\ghidra" NightmareNed -import "%ROOT%\extracted\NITENED.EXE" -overwrite ^
  -scriptPath "%ROOT%\tools\ghidra" -preScript DisableNoReturn.java -postScript ExportFunctions.java "%ROOT%\out\functions.csv" -max-cpu 8
python -I "%ROOT%\tools\make_seeds.py" "%ROOT%"
call "%GHIDRA%\support\analyzeHeadless.bat" "%ROOT%\out\ghidra" NightmareNed -process NITENED.EXE ^
  -scriptPath "%ROOT%\tools\ghidra" -preScript CreateFunctions.java "%ROOT%\out\seeds.txt" ^
  -postScript ExportFunctions.java "%ROOT%\out\functions.csv" -postScript ExportDecomp.java "%ROOT%\out" -max-cpu 8
