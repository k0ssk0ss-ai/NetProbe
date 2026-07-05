# Build the NetProbe gomobile binding (Windows).
#   .\integration\bind.ps1 android   -> netprobe.aar   (needs Android NDK)
# iOS binding requires macOS + Xcode and cannot be built on Windows.
param([string]$Target = "android")

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")   # repo root

if (-not (Get-Command gomobile -ErrorAction SilentlyContinue)) {
    Write-Host "gomobile not found. Install it:"
    Write-Host "  go install golang.org/x/mobile/cmd/gomobile@latest"
    Write-Host "  go install golang.org/x/mobile/cmd/gobind@latest"
    Write-Host "  gomobile init"
    exit 1
}

switch ($Target) {
    "android" {
        gomobile bind -target=android -androidapi=21 -o netprobe.aar ./lib/mobile
        Write-Host "Built netprobe.aar"
    }
    "ios" {
        Write-Host "iOS binding requires macOS + Xcode. Build it on a Mac with ./integration/bind.sh ios"
        exit 1
    }
    default { Write-Host "usage: .\integration\bind.ps1 [android|ios]"; exit 1 }
}
