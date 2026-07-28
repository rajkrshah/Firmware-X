# ============================================
#  FirmwareX Installer for Windows (PowerShell)
#  Firmware Analysis Tool v1.0.0
# ============================================

$ErrorActionPreference = "Stop"

function Write-Banner {
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "  ║                                                   ║" -ForegroundColor Cyan
    Write-Host "  ║   " -ForegroundColor Cyan -NoNewline
    Write-Host "FirmwareX" -ForegroundColor White -NoNewline
    Write-Host " — Firmware Analysis Tool          ║" -ForegroundColor Cyan
    Write-Host "  ║   Windows PowerShell Installer v1.0.0             ║" -ForegroundColor Cyan
    Write-Host "  ║                                                   ║" -ForegroundColor Cyan
    Write-Host "  ╚═══════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Message, [string]$Status = "info")
    switch ($Status) {
        "ok"      { Write-Host "  [" -NoNewline; Write-Host "+" -ForegroundColor Green -NoNewline; Write-Host "] $Message" }
        "error"   { Write-Host "  [" -NoNewline; Write-Host "!" -ForegroundColor Red -NoNewline; Write-Host "] $Message" }
        "warning" { Write-Host "  [" -NoNewline; Write-Host "!" -ForegroundColor Yellow -NoNewline; Write-Host "] $Message" }
        "info"    { Write-Host "  [" -NoNewline; Write-Host "*" -ForegroundColor Cyan -NoNewline; Write-Host "] $Message" }
    }
}

# ── Banner ───────────────────────────────────────────────
Write-Banner

# ── Check Node.js ────────────────────────────────────────
Write-Step "Checking prerequisites..." "info"
Write-Host ""

$nodeExists = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeExists) {
    Write-Step "Node.js is NOT installed!" "error"
    Write-Host ""
    Write-Host "  Would you like to install Node.js via winget? (Y/N): " -NoNewline -ForegroundColor Yellow
    $choice = Read-Host
    
    if ($choice -eq 'Y' -or $choice -eq 'y') {
        Write-Step "Installing Node.js LTS via winget..." "info"
        try {
            winget install OpenJS.NodeJS.LTS --accept-package-agreements --accept-source-agreements
            Write-Host ""
            Write-Step "Node.js installed! Please restart this script." "ok"
            Write-Host ""
            Write-Host "  IMPORTANT: Close and reopen PowerShell, then run:" -ForegroundColor Yellow
            Write-Host "    .\install.ps1" -ForegroundColor Cyan
        } catch {
            Write-Step "winget install failed: $($_.Exception.Message)" "error"
            Write-Host ""
            Write-Host "  Please install Node.js manually from:" -ForegroundColor Yellow
            Write-Host "    https://nodejs.org/" -ForegroundColor Cyan
        }
        Write-Host ""
        exit 1
    } else {
        Write-Host ""
        Write-Host "  Please install Node.js 18+ from:" -ForegroundColor Yellow
        Write-Host "    https://nodejs.org/" -ForegroundColor Cyan
        Write-Host "    or: winget install OpenJS.NodeJS.LTS" -ForegroundColor Cyan
        Write-Host ""
        exit 1
    }
}

# Show versions
$nodeVer = node -v
$npmVer = npm -v
Write-Step "Node.js $nodeVer found" "ok"
Write-Step "npm v$npmVer found" "ok"
Write-Host ""

# ── Install npm dependencies ─────────────────────────────
Write-Step "Installing npm dependencies..." "info"
Write-Host ""

try {
    npm install --no-audit --no-fund 2>&1 | ForEach-Object { Write-Host "    $_" -ForegroundColor Gray }
    Write-Host ""
    Write-Step "Dependencies installed successfully" "ok"
} catch {
    Write-Step "npm install failed: $($_.Exception.Message)" "error"
    Write-Host ""
    Write-Host "  Try running: npm install --verbose" -ForegroundColor Yellow
    exit 1
}

Write-Host ""

# ── Setup library files ──────────────────────────────────
Write-Step "Setting up client-side libraries..." "info"

$libDir = Join-Path $PSScriptRoot "public\lib"
if (-not (Test-Path $libDir)) {
    New-Item -ItemType Directory -Path $libDir -Force | Out-Null
    Write-Step "Created public\lib directory" "ok"
}

# Copy fflate
$fflateSource = Join-Path $PSScriptRoot "node_modules\fflate\umd\index.js"
$fflateDest = Join-Path $libDir "fflate.min.js"
if (Test-Path $fflateSource) {
    Copy-Item $fflateSource $fflateDest -Force
    Write-Step "fflate library copied" "ok"
} else {
    $fflateAlt = Join-Path $PSScriptRoot "node_modules\fflate\dist\fflate.umd.js"
    if (Test-Path $fflateAlt) {
        Copy-Item $fflateAlt $fflateDest -Force
        Write-Step "fflate library copied (alt path)" "ok"
    } else {
        Write-Step "fflate UMD build not found — some features may be limited" "warning"
    }
}

# Copy JSZip
$jszipSource = Join-Path $PSScriptRoot "node_modules\jszip\dist\jszip.min.js"
$jszipDest = Join-Path $libDir "jszip.min.js"
if (Test-Path $jszipSource) {
    Copy-Item $jszipSource $jszipDest -Force
    Write-Step "JSZip library copied" "ok"
} else {
    Write-Step "JSZip not found — ZIP features may be limited" "warning"
}

Write-Host ""

# ── Verify installation ─────────────────────────────────
Write-Step "Verifying installation..." "info"

$checks = @(
    @{ Name = "Modules";   Cmd = "require('./modules/file-detector')" },
    @{ Name = "Express";   Cmd = "require('express')" },
    @{ Name = "Chalk";     Cmd = "require('chalk')" },
    @{ Name = "Commander"; Cmd = "require('commander')" }
)

foreach ($check in $checks) {
    try {
        $result = node -e "try{$($check.Cmd);process.exit(0)}catch(e){process.exit(1)}" 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Step "$($check.Name): OK" "ok"
        } else {
            Write-Step "$($check.Name): FAILED" "warning"
        }
    } catch {
        Write-Step "$($check.Name): FAILED" "warning"
    }
}

Write-Host ""

# ── Success ──────────────────────────────────────────────
Write-Host "  ╔═══════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║         Installation Complete!                    ║" -ForegroundColor Green
Write-Host "  ╚═══════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "  Start Web UI:" -ForegroundColor White
Write-Host "    npm start" -ForegroundColor Cyan
Write-Host "    (Opens http://localhost:3000 in your browser)" -ForegroundColor Gray
Write-Host ""
Write-Host "  CLI Usage:" -ForegroundColor White
Write-Host "    node cli.js --help" -ForegroundColor Cyan
Write-Host "    node cli.js detect firmware.bin" -ForegroundColor Cyan
Write-Host "    node cli.js analyze firmware.bin" -ForegroundColor Cyan
Write-Host "    node cli.js entropy firmware.bin" -ForegroundColor Cyan
Write-Host "    node cli.js strings firmware.bin" -ForegroundColor Cyan
Write-Host "    node cli.js hexdump firmware.bin" -ForegroundColor Cyan
Write-Host "    node cli.js decrypt firmware.enc --method xor --key `"FF`"" -ForegroundColor Cyan
Write-Host "    node cli.js disasm firmware.elf --auto" -ForegroundColor Cyan
Write-Host "    node cli.js extract firmware.zip --output ./extracted" -ForegroundColor Cyan
Write-Host "    node cli.js info firmware.elf --sections" -ForegroundColor Cyan
Write-Host "    node cli.js convert firmware.hex" -ForegroundColor Cyan
Write-Host "    node cli.js security firmware.bin" -ForegroundColor Cyan
Write-Host ""
