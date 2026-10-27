package parties

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/konsulin-care/gateway-sdk-go/auth"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// The enrollment attempt bounds (SDK-RETRY-001/002): three attempts of
// one logical enroll, a fixed backoff when the gateway sends no
// Retry-After, and a cap on a gateway-supplied Retry-After so one call
// never stalls.
const (
	enrollMaxAttempts = 3
	enrollBackoff     = 100 * time.Millisecond
	enrollMaxBackoff  = 2 * time.Second
)

// EnrollInput carries the caller inputs of one logical enrollment
// (SDK-API-001).
type EnrollInput struct {
	// PartyID is the id being enrolled; travels in the URL path and as
	// the proof claim iss.
	PartyID string
	// EnrollmentToken is the single-use token delivered out of band by
	// the operator.
	EnrollmentToken string
	// EncPublicKey is the optional X25519 encryption key in the
	// registration encoding (base64.StdEncoding); empty omits it.
	EncPublicKey string
}

// enrollmentBuilder builds one attempt's body and proof from that
// attempt's claims — the Ed25519 default or the ES256 opt-in.
type enrollmentBuilder func(claims auth.PartyClaims) (auth.EnrollmentRequest, error)

// Enroll registers the party's Ed25519 key at POST /v1/parties/{id}/enroll
// (SDK-API-001, SDK-AUTH-002). The request carries the auth.BuildEnrollment
// body verbatim, the proof as "Authorization: Bearer", and one
// Idempotency-Key generated for the logical call; a retryable failure
// (wire.Retryable) is retried within enrollMaxAttempts with a fresh jti
// proof per attempt (SDK-AUTH-003) and identical body bytes under the
// same key. Enroll sends its own HTTP request because the enrollment PoP
// proof — a ks-party+jwt with body_sha256 bound to the body — cannot be
// produced by the client's request signing path.
// Parameters: ctx is the call context; in is the enrollment input; key is
// the Ed25519 private key whose public half is registered.
// Returns: the decoded EnrollPartyResponse, or an error — a terminal
// gateway failure surfaces as *wire.Error (SDK-CLIENT-003). Never panics.
func (c *Client) Enroll(ctx context.Context, in EnrollInput, key ed25519.PrivateKey) (*wire.EnrollPartyResponse, error) {
	return c.enroll(ctx, in, func(claims auth.PartyClaims) (auth.EnrollmentRequest, error) {
		return auth.BuildEnrollment(auth.EnrollmentInput{
			Claims:          claims,
			EnrollmentToken: in.EnrollmentToken,
			EncPublicKey:    in.EncPublicKey,
		}, key)
	})
}

// EnrollES256 is Enroll for the explicit opt-in ES256 key (SDK-AUTH-002):
// identical route, retry, and idempotency semantics; only the body alg
// and the proof header alg become ES256.
// Parameters: ctx is the call context; in is the enrollment input; key is
// the opt-in ES256Key wrapping the P-256 private key being registered.
// Returns: the decoded EnrollPartyResponse, or an error. Never panics.
func (c *Client) EnrollES256(ctx context.Context, in EnrollInput, key auth.ES256Key) (*wire.EnrollPartyResponse, error) {
	return c.enroll(ctx, in, func(claims auth.PartyClaims) (auth.EnrollmentRequest, error) {
		return auth.BuildEnrollmentES256(auth.EnrollmentInput{
			Claims:          claims,
			EnrollmentToken: in.EnrollmentToken,
			EncPublicKey:    in.EncPublicKey,
		}, key)
	})
}

// enroll is the shared logical-call loop for Enroll and EnrollES256: one
// Idempotency-Key for the call, up to enrollMaxAttempts attempts, each
// attempt signing fresh claims (fresh jti, SDK-AUTH-003) over the same
// body bytes. A 2xx decodes the party response; a retryable failure
// backs off (honouring a delta-seconds Retry-After, capped) and retries;
// anything else returns the *wire.Error.
func (c *Client) enroll(ctx context.Context, in EnrollInput, build enrollmentBuilder) (*wire.EnrollPartyResponse, error) {
	if in.PartyID == "" {
		return nil, fmt.Errorf("parties: enroll: party id must not be empty")
	}
	key, err := newIdempotencyKey()
	if err != nil {
		return nil, err
	}
	target := c.base + "/v1/parties/" + url.PathEscape(in.PartyID) + "/enroll"
	for attempt := 1; ; attempt++ {
		res, err := c.enrollAttempt(ctx, in.PartyID, target, key, build)
		if err != nil {
			return nil, err
		}
		if res.ok {
			return res.out, nil
		}
		if attempt >= enrollMaxAttempts || !wire.Retryable(res.werr.Status, res.werr.Code) {
			return nil, res.werr
		}
		if err := sleepCtx(ctx, res.delay); err != nil {
			return nil, err
		}
	}
}

// enrollOutcome is one enrollment attempt's classification: a decoded
// 2xx response (ok with out set), or a decoded gateway error (werr) with
// the backoff to wait before retrying it (delay).
type enrollOutcome struct {
	out   *wire.EnrollPartyResponse
	werr  *wire.Error
	delay time.Duration
	ok    bool
}

// enrollAttempt executes one enrollment attempt: build fresh claims
// (fresh jti), build the body and proof, send, then classify the
// result. A 2xx decodes into out; anything else decodes the error
// envelope and computes the capped Retry-After backoff. Transport and
// read failures are terminal for the attempt loop (fail closed).
func (c *Client) enrollAttempt(ctx context.Context, partyID, target, key string, build enrollmentBuilder) (enrollOutcome, error) {
	claims, err := attemptClaims(partyID)
	if err != nil {
		return enrollOutcome{}, err
	}
	built, err := build(claims)
	if err != nil {
		return enrollOutcome{}, err
	}
	status, body, header, err := c.sendEnroll(ctx, target, key, built)
	if err != nil {
		return enrollOutcome{}, err
	}
	if status >= 200 && status <= 299 {
		var out wire.EnrollPartyResponse
		if err := json.Unmarshal(body, &out); err != nil {
			return enrollOutcome{}, fmt.Errorf("parties: enroll: decode response body: %w", err)
		}
		return enrollOutcome{out: &out, ok: true}, nil
	}
	return enrollOutcome{
		werr:  wire.DecodeError(status, body),
		delay: retryDelay(header, enrollBackoff),
	}, nil
}

// sendEnroll performs one enrollment attempt: POST the exact body bytes
// with the Bearer proof and the call's Idempotency-Key. Transport and
// read failures are terminal for the attempt loop (fail closed).
func (c *Client) sendEnroll(ctx context.Context, target, key string, built auth.EnrollmentRequest) (int, []byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(built.Body))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("parties: enroll: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+built.Proof)
	req.Header.Set("Idempotency-Key", key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("parties: enroll: %s %s: %w", http.MethodPost, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("parties: enroll: read response body: %w", err)
	}
	return resp.StatusCode, body, resp.Header, nil
}

// attemptClaims builds one attempt's ks-party+jwt claims: aud gateway,
// iss the enrolled party id, iat now, exp at the maximum lifetime, and a
// fresh jti (SDK-AUTH-003) — the body built from these claims is
// claims-independent, so retries send identical bytes.
func attemptClaims(partyID string) (auth.PartyClaims, error) {
	jti, err := auth.NewJti()
	if err != nil {
		return auth.PartyClaims{}, fmt.Errorf("parties: enroll: %w", err)
	}
	now := time.Now().Unix()
	return auth.PartyClaims{
		Aud: "gateway", Iss: partyID,
		Iat: now, Exp: now + auth.MaxPartyLifetime, Jti: jti,
	}, nil
}

// retryDelay picks the backoff before the next enrollment attempt: a
// gateway Retry-After in delta-seconds wins (capped at enrollMaxBackoff),
// else the fixed fallback.
func retryDelay(header http.Header, fallback time.Duration) time.Duration {
	secs, err := strconv.Atoi(header.Get("Retry-After"))
	if err != nil || secs < 0 {
		return fallback
	}
	return min(time.Duration(secs)*time.Second, enrollMaxBackoff)
}

// sleepCtx waits for d or until ctx is done; a cancelled context aborts
// the wait and returns the context error.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// newIdempotencyKey generates one fresh Idempotency-Key for one logical
// enroll (SDK-CLIENT-002, ADR-011): 16 crypto/rand bytes laid out as a
// UUIDv4 (version/variant nibbles set), formatted lowercase hex with
// dashes. Entropy failure fails the call instead of weakening the key.
func newIdempotencyKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("parties: generate idempotency key: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
