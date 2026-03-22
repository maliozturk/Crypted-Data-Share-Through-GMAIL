param(
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

python scripts/generate_icon.py

if (-not $SkipTests) {
    $env:QT_QPA_PLATFORM = "offscreen"
    pytest
}

pyinstaller --noconfirm crypted_mail.spec
