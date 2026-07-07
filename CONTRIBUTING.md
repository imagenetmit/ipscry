# Contributing

Thanks for your interest in improving Ipscry. Start with
[`DEVELOPMENT.md`](DEVELOPMENT.md) for build, test, data, signing, and pull
request notes.

## Code of Conduct

By participating in this project you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md).

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

## Standards

Keep changes focused, formatted, tested, and consistent with the project
constraints in [`DEVELOPMENT.md`](DEVELOPMENT.md).

## Reporting bugs and requesting features

Use the [issue templates](.github/ISSUE_TEMPLATE). For security-sensitive
reports, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
