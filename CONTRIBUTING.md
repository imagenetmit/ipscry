# Contributing to Ipscry

Thanks for your interest in improving Ipscry. This document explains how to set up
a development environment, the standards changes are held to, and how to propose
changes.

## Code of Conduct

By participating in this project you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Prerequisites

- [Go 1.26](https://go.dev/dl/) or newer.
- Git.
- (Optional, Windows) `windres` for embedding version metadata and `signtool`
  for Authenticode signing.

Ipscry is Windows-oriented but builds and tests run on any platform — the
Windows-only `SendARP` MAC lookup is isolated behind build tags
(`mac_windows.go` / `mac_other.go`).

## Getting started

```bash
git clone https://github.com/imagenetmit/ipscry.git
cd ipscry
go build ./...
go test ./...
```

## Development workflow

1. Create a topic branch from `main`.
2. Make your change with focused commits.
3. Make sure the project stays green:

   ```bash
   gofmt -l .        # should print nothing
   go vet ./...
   go test ./... -count=1
   ```

4. Open a pull request using the template, describing the change and how you
   tested it.

## Coding standards

- Run `gofmt` (or `go fmt ./...`); CI rejects unformatted code.
- Keep imports at the top of the file.
- Prefer the standard library. Ipscry currently has **zero third-party
  dependencies** — please keep it that way unless there is a compelling reason,
  and raise it in an issue first.
- Add or update tests for behavior changes. Network-facing code should be tested
  with `httptest`/in-memory fakes rather than live hosts (see `main_test.go`).

## Preserve the security posture

Ipscry deliberately avoids behavior that trips managed AV/EDR. Changes **must
not** introduce:

- raw sockets, SYN scans, or packet-capture drivers;
- runtime downloads or self-update in the default code path;
- credential submission, exploitation, or vulnerability probing;
- persistence, hidden execution, or script-wrapper launchers.

Ipscry makes no external API calls at runtime. All port and MAC vendor metadata
is embedded in the binary.

## Reporting bugs and requesting features

Use the [issue templates](.github/ISSUE_TEMPLATE). For security-sensitive
reports, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
