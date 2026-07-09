# Ipscry

[![CI](https://github.com/imagenetmit/ipscry/actions/workflows/ci.yml/badge.svg)](https://github.com/imagenetmit/ipscry/actions/workflows/ci.yml)
[![Go Reference](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![Platform](https://img.shields.io/badge/platform-windows-0078D6?logo=windows&logoColor=white)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Ipscry is a small Windows network inventory scanner. It finds hosts on a local
network, checks common TCP ports, and reports hostnames, MAC vendors, service
labels, banners, HTTP metadata, TLS certificate subjects, and optional SNMP
details.

Ipscry uses ordinary TCP connect attempts only. It does not use raw sockets, SYN
scans, packet-capture drivers, credential checks, exploit probes, runtime
downloads, or external lookup APIs.

> [!IMPORTANT]
> Only scan networks you own or are explicitly authorized to assess. See
> [Responsible Use](#responsible-use) and [SECURITY.md](SECURITY.md).

## Download

Download the latest Windows build from the
[GitHub releases page](https://github.com/imagenetmit/ipscry/releases).

Use the `ipscry-windows-amd64.zip` archive for a normal download. It contains:

- `ipscry.exe`
- `README.md`
- `LICENSE`
- `SECURITY.md`
- `CHANGELOG.md`

You can also download `ipscry.exe` directly from the release assets.

## Quick Start

Run a scan from PowerShell:

```powershell
.\ipscry.exe scan
```

With no target, Ipscry scans the active local `/24` network.

Scan a specific CIDR:

```powershell
.\ipscry.exe scan 192.168.1.0/24
```

Show the version:

```powershell
.\ipscry.exe version
```

## Output

By default, Ipscry prints results to the console and does not write files.

Write JSON, CSV, or a log only when you pass an output path:

```powershell
.\ipscry.exe scan 192.168.1.0/24 -j scan.json -C scan.csv -L scan.log
```

Post the JSON report to a webhook after the scan:

```powershell
.\ipscry.exe scan 192.168.1.0/24 -w https://example.test/webhook
```

The JSON and CSV outputs include full service labels, vendor metadata, HTTP
details, redirects, MAC vendor names, and probe errors when available.

## Live Terminal UI

Interactive scans open a live terminal UI by default. It shows scan progress,
live host rows, latency, open ports, hostnames, MAC addresses, and watch status.

Useful keys:

- `Enter` exits after the scan completes.
- `c`, `j`, and `t` export CSV, JSON, or TXT from the finished scan.
- `p` toggles auto-ping.
- `s` toggles a background rescan every 3 minutes.
- `r` starts a manual rescan.
- `a` toggles ARP-dead rows.
- Arrow keys, PageUp, PageDown, Home, and End scroll the host list.

The TUI is automatically disabled when you pass `-j`, `-C`, `-L`, or `-w`, or
when there is no interactive terminal. Use `-N` or `--no-tui` to disable it
explicitly.

TUI mode is limited to `/22` and smaller targets. `/23` and `/22` scans ask for
confirmation first; larger targets should be split into smaller ranges or run
with `--no-tui`.

## Common Options

```text
ipscry scan [CIDR] [options]

Target:
  no CIDR              scan the active local /24
  192.168.1.0/24      scan an explicit range

Output:
  -j, --json PATH      write JSON report
  -C, --csv PATH       write CSV report
  -L, --log PATH       write audit log
  -w, --webhook URL    POST JSON report after scan
  -P, --progress-webhook URL
                       POST JSON progress events during the scan

Display:
  -N, --no-tui         disable the live terminal UI
  -m, --mac-format colon|none|dash
                       choose MAC address formatting
  -a, --arp-dead       include offline hosts from the local ARP cache
  -R, --arp-detail     show ARP State/Alias/Index columns in the TUI
      --aip            print an Advanced IP Scanner-style results table

Scanning:
  -p, --ports LIST     common, web, windows, db, 22,80,443, or 8000-8100
  -t, --timeout DURATION
                       per-port timeout, such as 250ms or 1s
  -c, --concurrency N  port-scan concurrency, 1-2048
  -s, --snmp-community STRING
                       SNMP v2c community for optional SNMP enrichment
  -H, --http-timeout DURATION
                       second-pass timeout for HTTP/HTTPS page retrieval
```

## What Ipscry Collects

For each discovered host, Ipscry can report:

- IP address
- hostname from reverse DNS, anonymous SMB2/NTLM negotiation, or NetBIOS
- MAC address and offline MAC vendor lookup for local-subnet hosts
- open TCP ports and service labels
- common product/vendor metadata from the embedded port database
- HTTP status, server header, title, and redirects
- TLS certificate subject
- SNMP v2c system name and description when available
- a simple device-type guess based on observed services

MAC vendor and port metadata are embedded in the binary. Ipscry does not call an
external API at runtime.

## Port Selection

By default, Ipscry scans every port listed in [`data/ports.csv`](data/ports.csv).
That file is the source for both the default port list and the service/vendor
metadata compiled into the release.

`--ports` accepts named profiles, lists, and ranges:

```text
--ports common          # all ports in data/ports.csv (default)
--ports web             # HTTP/HTTPS and common alternate web ports
--ports windows         # SMB, RDP, WinRM, and common Windows services
--ports db              # SQL Server, MySQL/MariaDB, PostgreSQL
--ports 22,80,443       # explicit list
--ports 8000-8100,9100  # ranges plus single ports
```

## Responsible Use

Ipscry is for authorized network inventory. Scanning networks without permission
may be illegal and is outside the intended use of this project.

Name resolution may perform an unauthenticated SMB2 negotiation to read the
computer name a server advertises. No credentials are sent and no SMB share is
accessed.

## Development

Build, test, data regeneration, release, and contribution notes live in
[`DEVELOPMENT.md`](DEVELOPMENT.md).

## License

Released under the [MIT License](LICENSE).
