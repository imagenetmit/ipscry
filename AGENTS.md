## Learned User Preferences

- Prefer embedded static datasets over external API lookups; optimize for small binary footprint and O(1) lookup speed.
- Default scan ports must come from embedded `data/ports.csv`; do not maintain a separate hardcoded port list.
- Port reference data should list factual vendor/product associations per port, not risk ratings or usage assumptions.
- Do not include `ninjarmm-run.ps1` or other RMM helper scripts in the published project surface.
- Keep the Go codebase stdlib-only with zero third-party dependencies unless explicitly approved.
- When Dependabot config references missing repo labels, remove the invalid label entries rather than creating labels.
- Do not edit plan files in `.cursor/plans/` when implementing attached plans.
- Provide short single-letter CLI aliases alongside long flags (e.g. `-c`, `-j`, `-C`, `-w`).
- Default scan output is console-only; write JSON, CSV, log, or POST JSON via webhook only when `-j`, `-C`, `-L`, or `-w` is passed with a path or URL.
- Do not hardcode deployment or artifact directories (e.g. ProgramData); RMM runners pass explicit output paths on the command line.
- Console and TUI use abbreviated compact cell labels; JSON and CSV artifacts retain full values.

## Learned Workspace Facts

- `ipscry` is a stdlib-only Go 1.26 Windows network inventory scanner using connect-only TCP (no raw sockets or SYN scans).
- GitHub repository: `imagenetmit/ipscry`; MIT license; CI and release workflows pin Go 1.26.4.
- Embedded lookup data lives in `data/ports.csv` and `data/mac_vendors.csv.gz` via `go:embed` in `dataset.go`; `tools/gendata/main.go` regenerates MAC data from gitignored `mac-vendors-export.json`.
- MAC vendor lookup is always-on and fully offline; the `--mac-vendor` flag and macvendorlookup.com API were removed.
- Embedded port CSV schema is `port,service,vendors`; default and `--ports common` scan all CSV ports (~92); `portCatalog` in code drives probe flags (HTTP/TLS/banners) only.
- Primary scan connect-tests every IP × configured port; ICMP/ping does not gate TCP port discovery.
- Port `vendors` appear in JSON and CSV output; console table keeps compact `port/service` cells.
- Optional stdlib-only TUI is on by default for interactive runs; disable with `-N` / `--no-tui` (`tui.go`, `term.go`); blocks targets larger than `/22` (`/23` and `/22` need confirmation); ARP detail via `-R` / `--arp-detail`; watch keys `p`/`s`/`r` for auto-ping, 3m scan, and full re-scan.
- Default scan timeout is 250ms (`-t` / `--timeout`); port-scan concurrency defaults to 1024 (CLI-valid range 1–2048).
- `-w` / `--webhook URL` POSTs the same indented JSON as `-j` after scan completes; disables TUI like `-j`, `-C`, and `-L`.
- Console table column order is IP, MAC, Latency, then Hostname; MAC format defaults to colon-separated (`--mac-format colon|none|dash`).
- Designed for authorized local network inventory and on-demand RMM deployment, with conservative AV/EDR posture.
