# Development

This document is for people building, testing, or changing Ipscry from source.
For normal use, see [`README.md`](README.md).

## Prerequisites

- [Go 1.26](https://go.dev/dl/) or newer.
- Git.
- Windows for full local behavior checks.
- Optional: `windres` for Windows version metadata.
- Optional: `signtool` for local Authenticode signing.

Ipscry is Windows-oriented, but most builds and tests run on any platform. The
Windows-only MAC lookup is isolated behind build tags in `mac_windows.go` and
`mac_other.go`.

## Build From Source

```bash
git clone https://github.com/imagenetmit/ipscry.git
cd ipscry
go build ./...
go test ./...
```

Build a Windows executable:

```powershell
go build -trimpath -o ipscry.exe .
```

The release build script writes `dist\ipscry.exe`, sets `GOOS=windows` and
`GOARCH=amd64`, runs tests, stamps `main.appVersion`, and embeds
`VERSIONINFO.rc` when `windres` is available:

```powershell
.\build-windows.ps1 -Version 1.2.3
```

If `windres` is not on `PATH`, pass either the executable or a MinGW toolchain
directory:

```powershell
.\build-windows.ps1 -Version 1.2.3 -WindresPath C:\mingw64
```

## Test And Format

Before opening a pull request, run:

```bash
gofmt -l .
go vet ./...
go test ./... -count=1
```

`gofmt -l .` should print no files.

Network-facing code should be tested with local listeners, `httptest`, or
in-memory fakes instead of live hosts.

## Project Constraints

Ipscry currently uses only the Go standard library. Do not add third-party
dependencies unless there is a clear need and it has been discussed first.

Changes must preserve the security posture. Do not add:

- raw sockets, SYN scans, or packet-capture drivers
- runtime downloads or self-update in the default path
- credential submission, exploitation, or vulnerability probing
- persistence, hidden execution, or script-wrapper launchers

Runtime metadata must remain offline. Port and MAC vendor data are embedded in
the binary.

## Embedded Data

Port metadata lives in [`data/ports.csv`](data/ports.csv). It is the source for
the default scan ports and the service/vendor labels in JSON and CSV output.

MAC vendor data is embedded as [`data/mac_vendors.csv.gz`](data/mac_vendors.csv.gz).
Regenerate it after updating the IEEE export:

```powershell
go run tools/gendata/main.go mac-vendors-export.json data/mac_vendors.csv.gz
```

`mac-vendors-export.json` is intentionally ignored because it is regeneration
input, not release source.

## Signing

`VERSIONINFO.rc` contains Windows version metadata. `build-windows.ps1` compiles
it into `versioninfo.syso` automatically when `windres` is available.

For local signing with a certificate in the Windows certificate store:

```powershell
.\sign-windows.ps1 -CertificateName "Certificate Subject Name"
Get-AuthenticodeSignature .\dist\ipscry.exe
```

The GitHub release workflow signs release assets through Azure Artifact Signing
when the required repository secrets are configured.

## Pull Requests

1. Create a topic branch from `main`.
2. Make focused commits.
3. Run format, vet, and tests.
4. Open a pull request using the template.

Security-sensitive reports should follow [`SECURITY.md`](SECURITY.md) instead
of a public issue.
