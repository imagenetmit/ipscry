## Learned User Preferences

- Prefer embedded static datasets over external API lookups; optimize for small binary footprint and O(1) lookup speed.
- Port reference data should list factual vendor/product associations per port, not risk ratings or usage assumptions.
- Do not include `ninjarmm-run.ps1` or other RMM helper scripts in the published project surface.
- Keep the Go codebase stdlib-only with zero third-party dependencies unless explicitly approved.
- When Dependabot config references missing repo labels, remove the invalid label entries rather than creating labels.
- Do not edit plan files in `.cursor/plans/` when implementing attached plans.
- Provide short single-letter CLI aliases alongside long flags (e.g. `-c`, `-j`, `-C`).
- Default scan output is console-only; write JSON, CSV, or log only when `-j`, `-C`, or `-L` is passed with a path.
- Do not hardcode deployment or artifact directories (e.g. ProgramData); RMM runners pass explicit output paths on the command line.

## Learned Workspace Facts

- `ipscry` is a stdlib-only Go 1.26 Windows network inventory scanner using connect-only TCP (no raw sockets or SYN scans).
- GitHub repository: `imagenetmit/ipscry`; MIT license; CI and release workflows pin Go 1.26.4.
- Embedded lookup data lives in `data/ports.csv` and `data/mac_vendors.csv.gz` via `go:embed` in `dataset.go`.
- MAC vendor lookup is always-on and fully offline; the `--mac-vendor` flag and macvendorlookup.com API were removed.
- `tools/gendata/main.go` regenerates `data/mac_vendors.csv.gz` from `mac-vendors-export.json` (gitignored source).
- Embedded port CSV schema is `port,service,vendors`; `portCatalog` still drives probe flags and scan profiles.
- Port `vendors` appear in JSON and CSV output; console table keeps compact `port/service` cells.
- Default port-scan concurrency is 1024 (CLI-valid range 1–2048).
- Console table column order is IP, MAC, Latency, then Hostname; MAC format defaults to colon-separated (`--mac-format colon|none|dash`).
- Designed for authorized local network inventory and on-demand RMM deployment, with conservative AV/EDR posture.
