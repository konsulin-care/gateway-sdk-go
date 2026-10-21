# testdata/golden — read-only mirror of the gateway golden vectors

These files are a **verbatim, read-only mirror** of the gateway repository's
golden vectors. This repo never edits them locally: regeneration happens only
at the gateway, and the full set flows here by mirroring
(`scripts/mirror-golden.sh`, phase 1). Either side drifting turns one CI red
(golden-vector lockstep, ADR-004).

## Mirrored files (PRD §11)

- `gateway-jwks.json`
- `ks-access.json`, `ks-approval.json`, `ks-delivery.json`,
  `ks-event-service-result.json`, `ks-party.json`, `ks-result.json`
- `settlement-expired-buyer.json`, `settlement-expired-provider.json`,
  `settlement-paid-buyer.json`, `settlement-paid-provider.json`
- `testonly-party-private.key` — the test-only party key so the SDK can prove
  byte-exact `ks-party` signing (SDK-AUTH-C01)

## Never mirrored

- `testonly-gateway-signing-private.key` stays in the gateway repo only; the
  SDK verifies with public JWKS (`gateway-jwks.json`). The gateway signing key
  is never mirrored into this repository.

## Notes

- The gateway's own `testdata/golden/README.md` is instructions, not a vector —
  it stays gateway-side.
- `testonly-party-private.key` is deliberately un-ignored in `.gitignore`;
  every other `*.key`/`*.pem` in the repo stays ignored.

Related requirements: SDK-AUTH-C01, SDK-VERIFY-C01, SDK-ID-C01, SDK-ENV-C01.
