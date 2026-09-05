param(
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$buildArgs = @("-ExecutionPolicy", "Bypass", "-File", "$PSScriptRoot\build_windows.ps1")
if ($SkipTests) {
    $buildArgs += "-SkipTests"
}
& powershell @buildArgs

$iscc = Get-Command iscc -ErrorAction SilentlyContinue
if (-not $iscc) {
    $defaultIscc = Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
    if (Test-Path $defaultIscc) {
        $iscc = $defaultIscc
    }
}
if (-not $iscc) {
    $userIscc = Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe"
    if (Test-Path $userIscc) {
        $iscc = $userIscc
    }
}

if (-not $iscc) {
    throw "Inno Setup compiler (iscc) is not installed or not on PATH. Install Inno Setup to build setup.exe."
}

# The version is single-sourced from src/crypted_mail/__init__.py and passed
# in here, so the .iss never hardcodes it.
$version = (python "$PSScriptRoot\get_version.py").Trim()
$fileVersion = (python "$PSScriptRoot\get_version.py" --file-version).Trim()
if (-not $version) { throw "Could not resolve version from src/crypted_mail/__init__.py" }
Write-Host "Building Crypted Mail $version (file version $fileVersion)"

& $iscc "/DAppVersion=$version" "/DAppFileVersion=$fileVersion" installer\crypted_mail.iss
# $ErrorActionPreference = "Stop" does not catch native exe failures.
if ($LASTEXITCODE -ne 0) { throw "ISCC failed with exit code $LASTEXITCODE" }

Write-Host "Installer written to dist\installer\CryptedMail-Setup-$version.exe"
