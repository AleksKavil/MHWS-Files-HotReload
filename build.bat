@echo off
rem Build file_hotreload.dll with Visual Studio 2022 (MSVC C++ toolset, CMake and Ninja components).
rem Output: build\file_hotreload.dll
setlocal
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [error] vswhere.exe not found. Install Visual Studio 2022 or Build Tools with the C++ workload.
    exit /b 1
)
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS=%%i"
if not defined VS (
    echo [error] No Visual Studio installation with the MSVC x64 toolset was found.
    exit /b 1
)
call "%VS%\VC\Auxiliary\Build\vcvars64.bat" >nul || exit /b 1
set "PATH=%VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%VS%\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja;%PATH%"

cd /d "%~dp0"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo %* || exit /b 1
cmake --build build || exit /b 1
echo.
echo Built: %~dp0build\file_hotreload.dll
endlocal
