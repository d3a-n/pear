@echo off
setlocal enabledelayedexpansion

echo ===================================
echo Pear Windows Build Script
echo ===================================

:: Parse command line arguments
set BUILD_TYPE=Release
set BUILD_ARCH=x64
set BUILD_DIR=build
set USE_SYSTEM_SODIUM=OFF
set USE_SYSTEM_I2PD=OFF
set DISABLE_I2P=OFF
set ENABLE_VERBOSE_DEBUG=ON

:parse_args
if "%~1"=="" goto :args_done
if /i "%~1"=="--debug" set BUILD_TYPE=Debug
if /i "%~1"=="--release" set BUILD_TYPE=Release
if /i "%~1"=="--x86" set BUILD_ARCH=x86
if /i "%~1"=="--x64" set BUILD_ARCH=x64
if /i "%~1"=="--system-sodium" set USE_SYSTEM_SODIUM=ON
if /i "%~1"=="--system-i2pd" set USE_SYSTEM_I2PD=ON
if /i "%~1"=="--disable-i2p" set DISABLE_I2P=ON
if /i "%~1"=="--no-verbose-debug" set ENABLE_VERBOSE_DEBUG=OFF
if /i "%~1"=="--help" goto :show_help
shift
goto :parse_args

:show_help
echo Usage: build-windows.bat [options]
echo Options:
echo   --debug           Build with debug information
echo   --release         Build with optimizations (default)
echo   --x86             Build for 32-bit architecture
echo   --x64             Build for 64-bit architecture (default)
echo   --system-sodium   Use system-installed libsodium instead of embedded
echo   --system-i2pd     Use system-installed i2pd instead of embedded
echo   --disable-i2p     Disable I2P support
echo   --no-verbose-debug Disable verbose debug output
echo   --help            Show this help message
exit /b 0

:args_done

:: Check for required tools
where cmake >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo Error: CMake is not installed or not in PATH
    echo Please install CMake from https://cmake.org/download/
    exit /b 1
)

:: Check for vcpkg if using system libraries
if "%USE_SYSTEM_SODIUM%"=="ON" (
    echo Checking for system-installed libsodium...
    echo Note: You can install libsodium using vcpkg with:
    echo       vcpkg install libsodium:x64-windows
    echo       vcpkg integrate install
)

:: Determine generator based on available tools
set GENERATOR=

:: Check for Visual Studio
where cl >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo Found Visual Studio compiler
    if "%BUILD_ARCH%"=="x86" (
        set GENERATOR=Visual Studio 17 2022
        set GENERATOR_ARGS=-A Win32
    ) else (
        set GENERATOR=Visual Studio 17 2022
        set GENERATOR_ARGS=-A x64
    )
) else (
    :: Check for MinGW
    where gcc >nul 2>nul
    if %ERRORLEVEL% equ 0 (
        echo Found MinGW compiler
        if "%BUILD_ARCH%"=="x86" (
            set GENERATOR=MinGW Makefiles
            set GENERATOR_ARGS=
        ) else (
            set GENERATOR=MinGW Makefiles
            set GENERATOR_ARGS=
        )
    ) else (
        echo Error: No supported compiler found
        echo Please install Visual Studio or MinGW
        exit /b 1
    )
)

echo Build configuration:
echo   Build type: %BUILD_TYPE%
echo   Architecture: %BUILD_ARCH%
echo   Generator: %GENERATOR% %GENERATOR_ARGS%

:: Check if libsodium directory exists
echo.
echo Checking libsodium directory structure...
if not exist libsodium (
    echo Error: libsodium directory not found.
    echo Make sure you are running this script from the project root.
    exit /b 1
)

:: Check if i2pd directory exists
echo.
echo Checking i2pd directory structure...
if not exist i2pd (
    echo Error: i2pd directory not found.
    echo Make sure you are running this script from the project root.
    exit /b 1
)

:: Create build directory
if not exist %BUILD_DIR% mkdir %BUILD_DIR%
cd %BUILD_DIR%

:: Configure with CMake
echo.
echo Configuring project with CMake...
cmake .. -G "%GENERATOR%" %GENERATOR_ARGS% ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    -DCMAKE_INSTALL_PREFIX=install ^
    -DUSE_SYSTEM_SODIUM=%USE_SYSTEM_SODIUM% ^
    -DUSE_SYSTEM_I2PD=%USE_SYSTEM_I2PD% ^
    -DDISABLE_I2P=%DISABLE_I2P% ^
    -DENABLE_VERBOSE_DEBUG=%ENABLE_VERBOSE_DEBUG%

if %ERRORLEVEL% neq 0 (
    echo Error: CMake configuration failed
    exit /b 1
)

:: Build the project
echo.
echo Building project...
cmake --build . --config %BUILD_TYPE%

if %ERRORLEVEL% neq 0 (
    echo Error: Build failed
    exit /b 1
)

:: Install the project
echo.
echo Installing project...
cmake --install . --config %BUILD_TYPE%

if %ERRORLEVEL% neq 0 (
    echo Error: Installation failed
    exit /b 1
)

echo.
echo ===================================
echo Build completed successfully!
echo ===================================
echo.
echo The executable is located at:
if "%GENERATOR:~0,14%"=="Visual Studio " (
    echo   %BUILD_DIR%\%BUILD_TYPE%\pear.exe
) else (
    echo   %BUILD_DIR%\pear.exe
)

cd ..
endlocal
