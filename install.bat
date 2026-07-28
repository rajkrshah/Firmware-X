@echo off
REM ============================================
REM  FirmwareX Installer for Windows
REM  Firmware Analysis Tool v1.0.0
REM ============================================
echo.
echo  ====================================================
echo   FirmwareX - Firmware Analysis Tool
echo   Windows Installer v1.0.0
echo  ====================================================
echo.

REM ── Check Node.js ──────────────────────────────────────
echo  [*] Checking prerequisites...
echo.
where node >nul 2>nul
if %errorlevel% neq 0 (
    echo  [!] Node.js is NOT installed.
    echo.
    echo  [*] Please install Node.js 18+ using one of these methods:
    echo.
    echo      Option 1: Download from https://nodejs.org/
    echo      Option 2: Run: winget install OpenJS.NodeJS.LTS
    echo.
    echo  [*] After installing Node.js, run this installer again.
    echo.
    pause
    exit /b 1
)

REM ── Show versions ──────────────────────────────────────
for /f "tokens=*" %%i in ('node -v') do set NODE_VER=%%i
for /f "tokens=*" %%i in ('npm -v') do set NPM_VER=%%i
echo  [+] Node.js %NODE_VER% found
echo  [+] npm %NPM_VER% found
echo.

REM ── Check Node.js version (need >=18) ──────────────────
for /f "tokens=1 delims=v." %%a in ("%NODE_VER%") do set NODE_MAJOR=%%a
if "%NODE_MAJOR%"=="" (
    for /f "tokens=2 delims=v." %%a in ("%NODE_VER%") do set NODE_MAJOR=%%a
)

REM ── Install npm dependencies ───────────────────────────
echo  [*] Installing npm dependencies...
echo.
call npm install --no-audit --no-fund
if %errorlevel% neq 0 (
    echo.
    echo  [!] npm install failed! Please check the error above.
    echo  [*] Try running: npm install --verbose
    pause
    exit /b 1
)
echo.
echo  [+] Dependencies installed successfully
echo.

REM ── Setup library files ────────────────────────────────
echo  [*] Setting up client-side libraries...

if not exist "public\lib" (
    mkdir "public\lib"
    echo  [+] Created public\lib directory
)

REM Copy fflate (try multiple locations)
if exist "node_modules\fflate\umd\index.js" (
    copy /Y "node_modules\fflate\umd\index.js" "public\lib\fflate.min.js" >nul 2>&1
    echo  [+] fflate library copied
) else if exist "node_modules\fflate\dist\fflate.umd.js" (
    copy /Y "node_modules\fflate\dist\fflate.umd.js" "public\lib\fflate.min.js" >nul 2>&1
    echo  [+] fflate library copied
) else (
    echo  [!] Warning: fflate UMD build not found. Some features may not work.
    echo  [*] Creating placeholder...
    echo // fflate placeholder - install manually if needed > "public\lib\fflate.min.js"
)

REM Copy JSZip
if exist "node_modules\jszip\dist\jszip.min.js" (
    copy /Y "node_modules\jszip\dist\jszip.min.js" "public\lib\jszip.min.js" >nul 2>&1
    echo  [+] JSZip library copied
) else (
    echo  [!] Warning: JSZip not found. ZIP extraction may not work.
    echo // JSZip placeholder > "public\lib\jszip.min.js"
)

echo.

REM ── Verify installation ────────────────────────────────
echo  [*] Verifying installation...
node -e "try{require('./modules/file-detector');console.log('  [+] Modules: OK')}catch(e){console.log('  [!] Modules: '+e.message)}"
node -e "try{require('express');console.log('  [+] Express: OK')}catch(e){console.log('  [!] Express: '+e.message)}"
node -e "try{require('chalk');console.log('  [+] Chalk: OK')}catch(e){console.log('  [!] Chalk: '+e.message)}"
node -e "try{require('commander');console.log('  [+] Commander: OK')}catch(e){console.log('  [!] Commander: '+e.message)}"
echo.

REM ── Success ────────────────────────────────────────────
echo  ====================================================
echo   Installation Complete!
echo  ====================================================
echo.
echo   Start Web UI:
echo     npm start
echo     (Opens http://localhost:3000 in your browser)
echo.
echo   CLI Usage:
echo     node cli.js --help
echo     node cli.js detect firmware.bin
echo     node cli.js analyze firmware.bin
echo     node cli.js entropy firmware.bin
echo     node cli.js strings firmware.bin
echo     node cli.js hexdump firmware.bin
echo     node cli.js decrypt firmware.enc --method xor --key "FF"
echo     node cli.js disasm firmware.elf --auto
echo     node cli.js extract firmware.zip --output ./extracted
echo     node cli.js info firmware.elf --sections
echo     node cli.js convert firmware.hex
echo     node cli.js security firmware.bin
echo.
echo  ====================================================
echo.
pause
