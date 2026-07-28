@echo off
REM ============================================
REM  FirmwareX — Git Repository Setup
REM ============================================
echo.
echo  FirmwareX — Git Repository Setup
echo  =================================
echo.

REM Check if git is installed
where git >nul 2>nul
if %errorlevel% neq 0 (
    echo  [!] Git is NOT installed.
    echo.
    echo  Install Git using one of these methods:
    echo    1. Download from: https://git-scm.com/download/win
    echo    2. Run: winget install Git.Git
    echo.
    echo  After installing, restart your terminal and run this script again.
    pause
    exit /b 1
)

echo  [+] Git found: 
git --version
echo.

REM Initialize repository
echo  [*] Initializing Git repository...
git init
echo.

REM Configure (optional, won't overwrite if already set)
git config user.name >nul 2>nul
if %errorlevel% neq 0 (
    echo  [*] Setting default Git user...
    git config user.name "FirmwareX Developer"
    git config user.email "developer@firmwarex.local"
)

REM Stage all files
echo  [*] Staging all project files...
git add -A
echo.

REM Show status
echo  [*] Repository status:
git status --short
echo.

REM Initial commit
echo  [*] Creating initial commit...
git commit -m "feat: Initial release of FirmwareX v1.0.0

- 11 analysis modules (file-detector, layer-engine, archive-extractor,
  binary-parser, hex-decoder, entropy-analyzer, string-extractor,
  hex-viewer, disassembler, decryption-engine, security-analyzer)
- CLI tool with 11 commands (detect, analyze, entropy, strings,
  hexdump, decrypt, disasm, extract, info, convert, security)
- Premium Web UI with 8 tabs including Security dashboard
- Cross-platform installers (Windows bat/ps1, Linux bash)
- Support for 40+ firmware formats and 15+ CPU architectures
- Security scanner: credentials, private keys, API keys, backdoors,
  vulnerable functions (CWE), weak crypto, default credentials"
echo.

REM Create main branch
git branch -M main 2>nul

echo.
echo  ====================================================
echo   Git Repository Initialized Successfully!
echo  ====================================================
echo.
echo   To push to GitHub:
echo     1. Create a new repo at https://github.com/new
echo     2. Run:
echo        git remote add origin https://github.com/YOUR_USERNAME/FirmwareX.git
echo        git push -u origin main
echo.
echo   To push to GitLab:
echo     git remote add origin https://gitlab.com/YOUR_USERNAME/FirmwareX.git
echo     git push -u origin main
echo.
pause
