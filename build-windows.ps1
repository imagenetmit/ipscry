param(
    # Version stamped into the binary (main.appVersion). Defaults to the current
    # git tag/describe, falling back to "dev" outside a git checkout.
    [string]$Version,

    # Optional path to windres.exe, x86_64-w64-mingw32-windres.exe, or a MinGW
    # toolchain root containing one of those binaries under bin\.
    [string]$WindresPath
)

$ErrorActionPreference = "Stop"

function Get-VersionInfoParts {
    param([string]$Version)

    $s = $Version.TrimStart("v")
    if ($s -match "^(\d+)\.(\d+)\.(\d+)(?:-(\d+)-g)?") {
        $build = if ($Matches[4]) { [int]$Matches[4] } else { 0 }
        return @{
            Major  = [int]$Matches[1]
            Minor  = [int]$Matches[2]
            Patch  = [int]$Matches[3]
            Build  = $build
            String = "$($Matches[1]).$($Matches[2]).$($Matches[3])"
        }
    }

    return @{
        Major  = 0
        Minor  = 0
        Patch  = 0
        Build  = 0
        String = $s
    }
}

function New-VersionInfoRc {
    param([string]$Version)

    $parts = Get-VersionInfoParts $Version
    $fileVersion = "$($parts.Major),$($parts.Minor),$($parts.Patch),$($parts.Build)"
    $versionString = $parts.String

    return @"
1 VERSIONINFO
FILEVERSION $fileVersion
PRODUCTVERSION $fileVersion
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "Internal"
            VALUE "FileDescription", "Local Network Inventory Scanner"
            VALUE "FileVersion", "$versionString"
            VALUE "InternalName", "ipscry"
            VALUE "OriginalFilename", "ipscry.exe"
            VALUE "ProductName", "Ipscry"
            VALUE "ProductVersion", "$versionString"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"@
}

function Get-WindresCandidateDirs {
    param([string]$Root)

    $dirs = @(
        $Root,
        (Join-Path $Root "bin"),
        (Join-Path $Root "mingw64\bin"),
        (Join-Path $Root "ucrt64\bin"),
        (Join-Path $Root "clang64\bin")
    )

    if (Test-Path -LiteralPath $Root -PathType Container) {
        Get-ChildItem -LiteralPath $Root -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $dirs += (Join-Path $_.FullName "mingw64\bin")
            $dirs += (Join-Path $_.FullName "bin")
        }
    }

    return $dirs
}

function Find-WindresInDirs {
    param([string[]]$Dirs)

    $names = @("windres.exe", "x86_64-w64-mingw32-windres.exe", "windres")
    foreach ($dir in $Dirs) {
        foreach ($name in $names) {
            $candidate = Join-Path $dir $name
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                return $candidate
            }
        }
    }

    return $null
}

function Resolve-Windres {
    param([string]$Path)

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

        $found = Find-WindresInDirs (Get-WindresCandidateDirs $item.FullName)
        if ($found) { return $found }

        Write-Warning "No windres executable found under $($item.FullName)"
        return $null
    }

    foreach ($name in @("windres.exe", "x86_64-w64-mingw32-windres.exe", "windres")) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) { return $command.Source }
    }

    foreach ($root in @("C:\dev\mingw", "C:\msys64", "C:\mingw64")) {
        $found = Find-WindresInDirs (Get-WindresCandidateDirs $root)
        if ($found) { return $found }
    }

    return $null
}

if (-not $Version) {
    try {
        $latestTag = (& git -C $PSScriptRoot tag -l "v*.*.*" --sort=-v:refname 2>$null | Select-Object -First 1)
        if ($latestTag) {
            $Version = $latestTag.TrimStart("v")
        } else {
            $Version = (& git -C $PSScriptRoot describe --tags --always --dirty 2>$null)
        }
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
    $versionInfoRc = Join-Path $PSScriptRoot "versioninfo.generated.rc"
    $peVersion = (Get-VersionInfoParts $Version).String
    New-VersionInfoRc $Version | Set-Content -Path $versionInfoRc -Encoding ASCII
    & $windres -O coff -o (Join-Path $PSScriptRoot "versioninfo.syso") $versionInfoRc
    Write-Host "Generated versioninfo.syso using $windres (PE version $peVersion)"
} else {
    Write-Warning "windres not found; building without embedded VERSIONINFO metadata. Install a MinGW-w64 toolchain with binutils, then pass -WindresPath or add its bin directory to PATH."
}

go test ./...
go build -trimpath -ldflags "-X main.appVersion=$Version" -o (Join-Path $outDir "ipscry.exe") .

Write-Host "Built $outDir\ipscry.exe (version $Version)"
