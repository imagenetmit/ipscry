param(
    # Version stamped into the binary (main.appVersion). Defaults to the current
    # git tag/describe, falling back to "dev" outside a git checkout.
    [string]$Version
)

$ErrorActionPreference = "Stop"

if (-not $Version) {
    try {
        $Version = (& git -C $PSScriptRoot describe --tags --always --dirty 2>$null)
    } catch {
        $Version = $null
    }
    if (-not $Version) { $Version = "dev" }
}

$outDir = Join-Path $PSScriptRoot "dist"
New-Item -ItemType Directory -Force $outDir | Out-Null

$env:GOOS = "windows"
$env:GOARCH = "amd64"

if (Get-Command windres -ErrorAction SilentlyContinue) {
    windres -O coff -o (Join-Path $PSScriptRoot "versioninfo.syso") (Join-Path $PSScriptRoot "VERSIONINFO.rc")
    Write-Host "Generated versioninfo.syso"
} else {
    Write-Warning "windres not found; building without embedded VERSIONINFO metadata"
}

go test ./...
go build -trimpath -ldflags "-X main.appVersion=$Version" -o (Join-Path $outDir "ipscry.exe") .

Write-Host "Built $outDir\ipscry.exe (version $Version)"
