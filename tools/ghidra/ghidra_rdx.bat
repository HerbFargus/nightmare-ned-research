@echo off
rem Ghidra pass over the Intel RDX DLLs: out\rdx\<dll>\functions.csv + decomp\.
for %%I in ("%~dp0..\..") do set ROOT=%%~fI
if not defined GHIDRA for %%I in ("%~dp0..\..\..\ghidra\ghidra_12.1.4_PUBLIC") do set GHIDRA=%%~fI
for %%D in (Dino2d dmix) do (
  if not exist "%ROOT%\out\rdx\%%D" mkdir "%ROOT%\out\rdx\%%D"
  call "%GHIDRA%\support\analyzeHeadless.bat" "%ROOT%\out\ghidra" RDX_%%D -import "%ROOT%\extracted\rdx\%%D.dll" -overwrite ^
    -scriptPath "%ROOT%\tools\ghidra" -postScript ExportFunctions.java "%ROOT%\out\rdx\%%D\functions.csv" ^
    -postScript ExportDecomp.java "%ROOT%\out\rdx\%%D" -max-cpu 8
)
