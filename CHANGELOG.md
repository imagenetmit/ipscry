# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
for tagged releases.

## [Unreleased]

## [0.1.1] - 2026-07-07

### Changed

- Reworked project documentation for public release: the README now focuses on
  downloading and running Ipscry, with build and contribution notes moved to
  `DEVELOPMENT.md`.
- Removed checked-in local/private artifacts from the public source tree.
- TUI mode rejects targets larger than `/22` and prompts for confirmation on `/23`
  and `/22` scans because large result sets overwhelm the terminal UI.
- Removed redundant CLI flags `--local`, `--progress`, and `--tui`; local /24 is
  the default target, stderr progress and the TUI are chosen automatically, and
  `-N`/`--no-tui` remains the explicit TUI opt-out.
- Embedded static port-service and MAC vendor datasets replace external API lookups.
  MAC vendor enrichment is now always on (offline, local subnet only).
- Removed the `--mac-vendor` flag; vendor lookup uses embedded OUI data.
- Added `vendors` field to port results in JSON and CSV output.
- Updated the project Go version to Go 1.26, with CI and release builds pinned
  to Go 1.26.4.

## [0.1.0] - 2026-06-22

### Added

- Project documentation and GitHub community health files.
- Windows-oriented local network inventory scanner.
- Connect-only TCP port scanning with configurable timeout, concurrency, and
  named port profiles.
- Hostname enrichment through reverse DNS, anonymous SMB2/NTLM negotiation, and
  NetBIOS node status.
- Lightweight service metadata collection for banners, HTTP responses, and TLS
  certificate subjects.
- Optional SNMP v2c system group enrichment.
- Optional local-subnet MAC vendor lookup with deduplicated, rate-limited API
  calls.
- JSON, CSV, and UTC audit log artifacts.
- Windows build, version metadata, and Authenticode signing helper scripts.

[Unreleased]: https://github.com/imagenetmit/ipscry/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/imagenetmit/ipscry/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/imagenetmit/ipscry/releases/tag/v0.1.0
