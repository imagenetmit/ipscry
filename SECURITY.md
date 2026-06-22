# Security Policy

## Supported versions

Ipscry is distributed from the `main` branch and tagged releases. Security fixes
are applied to the latest release; please upgrade to the most recent version
before reporting an issue.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report privately using GitHub's
[private vulnerability reporting](https://github.com/imagenetmit/ipscry/security/advisories/new)
("Report a vulnerability" under the repository's **Security** tab). If that is
unavailable, contact the maintainers directly.

When reporting, please include:

- a description of the issue and its impact;
- steps to reproduce or a proof of concept;
- affected version(s) and platform.

We aim to acknowledge reports within a few business days and will coordinate a
fix and disclosure timeline with you.

## Scope and intended use

Ipscry performs **connect-only** TCP scans and read-only protocol negotiations
for the purpose of inventorying networks **you own or are explicitly authorized
to assess**. It intentionally avoids raw sockets, SYN scans, packet capture,
credential submission, exploitation, and persistence.

Using Ipscry to scan networks without authorization is outside the intended use
of this software and may be illegal. The maintainers accept no liability for
misuse.

## Security-relevant design notes

- The only feature that contacts the internet is the opt-in `--mac-vendor`
  lookup, which is **off by default**. When enabled, only deduplicated,
  rate-limited MAC OUIs leave the host.
- TLS probes use `InsecureSkipVerify` deliberately — Ipscry inventories
  certificate subjects and must not trust or depend on remote identity. No data
  is transmitted to those endpoints beyond the standard handshake/GET.
- All free-text fields gathered from the network are sanitized to a single line
  and length-bounded before being written to artifacts.
