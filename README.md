# Ipscry

Ipscry is a small Windows-oriented local network inventory scanner designed for
on-demand NinjaRMM execution. It uses normal TCP connect attempts only and writes
auditable JSON, CSV, and log artifacts.

## Build

Install Go 1.22 or newer, then build a normal uncompressed Windows executable:

```powershell
go build -trimpath -o ipscry.exe .
```

## Run

Recommended conservative NinjaRMM command:

```powershell
C:\ProgramData\ipscry\ipscry.exe scan --local --timeout 750ms --concurrency 128 --json C:\ProgramData\ipscry\scan.json --csv C:\ProgramData\ipscry\scan.csv --log C:\ProgramData\ipscry\scan.log
```

Or deploy `ninjarmm-run.ps1` with `ipscry.exe` already staged at
`C:\ProgramData\ipscry\ipscry.exe`.

Explicit CIDR:

```powershell
C:\ProgramData\ipscry\ipscry.exe scan 192.168.1.0/24
```

Default ports:

```text
21,22,23,25,53,80,110,135,139,143,443,445,
515,554,587,631,993,995,1433,1883,3306,3389,
5432,5900,8000,8008,8080,8443,8883,9100
```

## Port selection

`--ports` accepts a named profile, an explicit list, or ranges:

```text
--ports common          # the default set above
--ports web             # 80,443,631,8000,8008,8080,8443
--ports windows         # 135,139,445,1433,3389,5985,5986
--ports db              # 1433,3306,5432
--ports 22,80,443       # explicit list
--ports 8000-8100,9100  # ranges plus single ports
```

Add `--progress` to print periodic scan progress to stderr (off by default so
NinjaRMM logs stay clean).

## Name resolution

For each discovered host the hostname is resolved through a layered fallback,
because no single method covers every device:

1. **Reverse DNS (PTR)** — authoritative FQDN when a record exists.
2. **SMB/NTLM** (when 445 or 139 is open) — an anonymous SMB2 negotiation reads the
   computer name the server advertises in its NTLM challenge. No credentials are
   sent. This resolves modern Windows hosts that have NetBIOS-over-TCP/IP disabled
   and no PTR record — the common "discovered but unnamed" case.
3. **NetBIOS node status** (UDP/137) — for older SMB/Windows devices that still
   answer `nbtstat`-style queries.

## MAC vendor lookup (opt-in)

`--mac-vendor` enriches each host with its hardware MAC address and the vendor that
owns the OUI:

```powershell
C:\ProgramData\ipscry\ipscry.exe scan --local --mac-vendor
```

- MAC addresses come from the OS ARP table (Windows `SendARP`), so they are only
  available for hosts on the **local subnet** — the default `--local` case. Routed
  hosts reached via an explicit CIDR will have no MAC.
- Vendor names come from the free **macvendorlookup.com** API. To stay within its
  fair-use policy, ipscry queries **once per unique OUI** (caching results) and
  **serializes requests with a one-second minimum gap**.
- It is **off by default**. Enable it for interactive/ad-hoc inventory; leave it off
  for unattended NinjaRMM runs that should stay fully offline.

## Internal Signing

`VERSIONINFO.rc` contains the intended Windows version metadata. Compile it into
a `.syso` resource on the build workstation if your build environment supports a
Windows resource compiler, then run the normal Go build:

```powershell
windres -O coff -o versioninfo.syso VERSIONINFO.rc
go build -trimpath -o ipscry.exe .
```

`build-windows.ps1` does this automatically when `windres` is available, and stamps
the version into the binary from the current git tag (override with `-Version`):

```powershell
.\build-windows.ps1 -Version 1.2.3
```

Use an internal Authenticode code-signing certificate with the Code Signing EKU:

```text
1.3.6.1.5.5.7.3.3
```

Sign the executable after building:

```powershell
.\sign-windows.ps1 -CertificateName "Your Internal Code Signing Cert Name"
```

Verify on a managed endpoint:

```powershell
Get-AuthenticodeSignature C:\ProgramData\ipscry\ipscry.exe
```

Expected status:

```text
Valid
```

## AV/EDR Posture

Ipscry intentionally avoids raw sockets, SYN scans, packet capture drivers,
runtime downloads, credential checks, vulnerability probes, persistence, hidden
execution, and script wrappers. Keep the binary path and hash stable per release
if your managed AV/EDR supports allowlisting.

Name resolution issues a standard, unauthenticated SMB2 negotiation to 445 (the
same exchange `nmap -sV` / `smb-os-discovery` performs) to read the advertised
computer name. No credentials are submitted and no SMB share is accessed; it is a
read-only protocol negotiation over an ordinary TCP socket.

The optional `--mac-vendor` flag is the one feature that contacts the internet (the
macvendorlookup.com API). It is **off by default** so the standard configuration
remains fully self-contained and offline. When enabled, only MAC OUIs leave the
host, deduplicated and rate-limited.
