@echo off
REM Pear build script for Windows

REM Create build directory
if not exist build mkdir build
cd build

REM Configure with CMake
echo Configuring with CMake...
cmake -G "MinGW Makefiles" ..

REM Build
echo Building Pear...
mingw32-make

REM Check if build was successful
if %ERRORLEVEL% EQU 0 (
    echo Build successful! The executable is located at: build\pear.exe
    echo Run it with: pear.exe
) else (
    echo Build failed. Please check the error messages above.
    exit /b 1
)
