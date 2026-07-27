@echo off
setlocal

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
  echo vswhere.exe was not found. 1>&2
  exit /b 1
)

set "VSROOT="
for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%I"
if not defined VSROOT (
  echo Visual Studio with the x86 C++ toolchain was not found. 1>&2
  exit /b 1
)

call "%VSROOT%\VC\Auxiliary\Build\vcvars32.bat" >nul
if errorlevel 1 exit /b %errorlevel%

set "SOURCE_DIR=%~dp0."
set "OUTPUT_DIR=%SOURCE_DIR%\..\..\..\build\x86\hlib_harness"
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

cl.exe /nologo /std:c++17 /Od /Zi /EHsc /W4 /DUNICODE /D_UNICODE ^
  /I"%SOURCE_DIR%" "%SOURCE_DIR%\hlib_harness.cpp" ^
  /Fo:"%OUTPUT_DIR%\hlib_harness.obj" ^
  /Fe:"%OUTPUT_DIR%\hlib_harness.exe" ^
  /Fd:"%OUTPUT_DIR%\hlib_harness.pdb" ^
  /link bcrypt.lib version.lib
exit /b %errorlevel%
