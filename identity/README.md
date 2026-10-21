# identity

**Purpose**: identity normalization and federation hashing — email
(lowercase + trim), phone (E.164), `HMAC-SHA256(normalized, pepper)` rendered
as standard base64 of exactly 32 bytes or the `N/A` marker (gateway `hashfmt`
convention, gateway ADR-005), plus format validation so malformed hashes never
reach the wire.

**Allowed imports** (PRD §7 dependency rules): standard library, `wire`.

**Related requirements**: SDK-ID-001, SDK-ID-002, SDK-ID-C01.

**Planned files**:
- `normalize.go` — email/phone normalization
- `hash.go` — HMAC hash + `hashfmt` validation (constant-time compares)
- `identity_test.go` — shared fixture vectors (inputs → expected hashes for a fixed pepper)

**Built by**: `docs/tasks/02-inbound-trust.md`.
