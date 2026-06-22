$ErrorActionPreference = "Stop"

$dir = "C:\ProgramData\ipscry"
$exe = Join-Path $dir "ipscry.exe"
$json = Join-Path $dir "scan.json"
$csv = Join-Path $dir "scan.csv"
$log = Join-Path $dir "scan.log"

New-Item -ItemType Directory -Force $dir | Out-Null

if (-not (Test-Path $exe)) {
    throw "ipscry.exe not found at $exe"
}

& $exe scan --local --timeout 750ms --concurrency 128 --json $json --csv $csv --log $log

Write-Host "JSON: $json"
Write-Host "CSV:  $csv"
Write-Host "Log:  $log"
