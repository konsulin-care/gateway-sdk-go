package conformance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/konsulin-care/gateway-sdk-go/auth"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// negativeIdempotencyReplay requires one key plus one body to replay
// byte-identically, and a conflicting body to deny 422 GW-HOOK-008.
// Every probe mints a fresh party token through syncProbe, so the three
// probes also carry distinct jtis and pass a gateway enforcing
// single-use party jti replay.
func negativeIdempotencyReplay(ctx context.Context, env *Env) error {
	const name = "idempotency-replay"
	service := env.listingService()
	first, err := json.Marshal(wire.SyncWebhookRequest{
		To: env.PartyID, Service: service, Payload: json.RawMessage(`{"n":1}`),
	})
	if err != nil {
		return named(name, err)
	}
	conflict, err := json.Marshal(wire.SyncWebhookRequest{
		To: env.PartyID, Service: service, Payload: json.RawMessage(`{"n":2}`),
	})
	if err != nil {
		return named(name, err)
	}
	idem, err := auth.NewJti()
	if err != nil {
		return named(name, err)
	}
	const path = "/v1/webhooks/sync"
	s1, b1, err := syncProbe(ctx, env, path, idem, first)
	if err != nil {
		return named(name, err)
	}
	if s1 < 200 || s1 > 299 {
		return named(name, fmt.Errorf("first sync status %d, want 2xx", s1))
	}
	s2, b2, err := syncProbe(ctx, env, path, idem, first)
	if err != nil {
		return named(name, err)
	}
	if s2 != s1 || !bytes.Equal(b1, b2) {
		return named(name, fmt.Errorf("replay status %d (want %d) or body not byte-identical", s2, s1))
	}
	s3, b3, err := syncProbe(ctx, env, path, idem, conflict)
	if err != nil {
		return named(name, err)
	}
	return named(name, expectDeny(s3, b3, http.StatusUnprocessableEntity, "GW-HOOK-008"))
}

// syncProbe issues one sync webhook probe with a freshly minted party
// token: each probe carries a fresh jti, so the replay case's three
// probes pass single-use party jti enforcement instead of tripping the
// 401 replay deny on probes two and three.
//
// Parameters: ctx bounds the request; env is the conformance target
// env; path is the sync route path; idem is the shared idempotency key;
// body is the marshalled sync request.
// Returns: the response status, the bounded response body, and any
// transport failure.
func syncProbe(ctx context.Context, env *Env, path, idem string, body []byte) (int, []byte, error) {
	tok, err := partyToken(env, wire.TypParty)
	if err != nil {
		return 0, nil, err
	}
	return probe(ctx, env, http.MethodPost, path, tok, idem, body)
}
