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

& $iscc installer\crypted_mail.iss
