param(
    [Parameter(Mandatory = $true)]
    [string]$CertificateName,

    [string]$Path = "$PSScriptRoot\dist\ipscry.exe",
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $Path)) {
    throw "Executable not found: $Path"
}

signtool sign /fd SHA256 /tr $TimestampUrl /td SHA256 /n $CertificateName $Path

$signature = Get-AuthenticodeSignature $Path
$signature | Format-List

if ($signature.Status -ne "Valid") {
    throw "Signature status is $($signature.Status), expected Valid"
}
