# gateway-sdk-go

The public Go client and verifier for the Konsulin gateway: enrollment and key
rotation, identity registration/resolution/linking, approval tickets, listings,
payments, webhook enqueue/sync/status/result, inbound callback verification
middleware, federation identity hashing, and the JWE envelope. Stdlib-only
runtime, MIT licensed — `go get github.com/konsulin-care/gateway-sdk-go`.

## Status

Pre-v0.1.0: repository skeleton. Package structure, docs, and tooling are in
place; the implementation lands in the phase tasks under
[docs/tasks/](docs/tasks/). The requirements live in the PRD:
[PROPOSAL.md](PROPOSAL.md).

## Development setup

```sh
mise install      # Go, golangci-lint, lefthook, govulncheck
mise run hooks    # install lefthook pre-commit and pre-push
mise run qc       # quality gate (format, lint, vet, lines, secret, deps, test, vuln)
go test ./...     # offline unit tests, zero network
```

## Contributing

See [AGENTS.md](AGENTS.md) for contract authority, navigation, security
invariants, boundaries, and conventions. Runnable recipes (enrollment, signed
calls, callback middleware, direct exchange, federation pepper) come in phase 4.
