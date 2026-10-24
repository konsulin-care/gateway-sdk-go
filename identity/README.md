# identity

**Purpose**: identity normalization and federation hashing — email
(lowercase + trim), phone (E.164 digits, no '+'),
`HMAC-SHA256(normalized, pepper)` rendered
as standard base64 of exactly 32 bytes or the `N/A` marker (gateway `hashfmt`
convention, gateway ADR-005), plus format validation so malformed hashes never
reach the wire.

**Allowed imports** (PRD §7 dependency rules): standard library, `wire`.

**Related requirements**: SDK-ID-001, SDK-ID-002, SDK-ID-C01.

**Files**:
- `doc.go` — package doc (allowed imports, requirement IDs)
- `normalize.go` — email/phone normalization (phone → E.164 digits, no '+')
- `hash.go` — HMAC hash + `hashfmt` validation (constant-time compares)
- `identity_test.go` — normalization, hashing, `N/A` marker, shared-vector tests
- `testdata/vectors.json` — shared fixture vectors: fixed test pepper + input → expected hash rows

**Built by**: `docs/tasks/02-inbound-trust.md`.
