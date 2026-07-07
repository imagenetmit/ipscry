param(
    # Version stamped into the binary (main.appVersion). Defaults to the current
    # git tag/describe, falling back to "dev" outside a git checkout.
    [string]$Version,

    # Optional path to windres.exe, x86_64-w64-mingw32-windres.exe, or a MinGW
    # toolchain root containing one of those binaries under bin\.
    [string]$WindresPath
)

$ErrorActionPreference = "Stop"

function Resolve-Windres {
    param([string]$Path)

    $names = @("windres.exe", "x86_64-w64-mingw32-windres.exe", "windres")

    if ($Path) {
        $resolvedPath = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
        if (-not $resolvedPath) {
            Write-Warning "WindresPath not found: $Path"
            return $null
        }

        $item = Get-Item -LiteralPath $resolvedPath.Path
        if (-not $item.PSIsContainer) {
            return $item.FullName
        }

        $candidateDirs = @(
            $item.FullName,
            (Join-Path $item.FullName "bin"),
            (Join-Path $item.FullName "mingw64\bin"),
            (Join-Path $item.FullName "ucrt64\bin"),
            (Join-Path $item.FullName "clang64\bin")
        )

        foreach ($dir in $candidateDirs) {
            foreach ($name in $names) {
                $candidate = Join-Path $dir $name
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    return $candidate
                }
            }
        }

        Write-Warning "No windres executable found under $($item.FullName)"
        return $null
    }

    foreach ($name in $names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) { return $command.Source }
    }

    return $null
}

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

$windres = Resolve-Windres $WindresPath
if ($windres) {
    & $windres -O coff -o (Join-Path $PSScriptRoot "versioninfo.syso") (Join-Path $PSScriptRoot "VERSIONINFO.rc")
    Write-Host "Generated versioninfo.syso using $windres"
} else {
    Write-Warning "windres not found; building without embedded VERSIONINFO metadata. Install a MinGW-w64 toolchain with binutils, then pass -WindresPath or add its bin directory to PATH."
}

go test ./...
go build -trimpath -ldflags "-X main.appVersion=$Version" -o (Join-Path $outDir "ipscry.exe") .

Write-Host "Built $outDir\ipscry.exe (version $Version)"
