package envelope

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// boundBinding returns the binding every bound-envelope test seals with.
func boundBinding() Binding {
	return Binding{
		From:    "party-seller",
		To:      "party-recipient",
		Service: "consultation",
	}
}

// boundExpectations returns the expectations matching boundBinding.
func boundExpectations() Expectations {
	return Expectations{
		From:    "party-seller",
		To:      "party-recipient",
		Service: "consultation",
	}
}

// openBound opens compact with the shared offline harness: background
// context, nil replay cache, and wall clock — freshness and nonce checks
// are not part of this requirement yet.
func openBound(compact string, d Decrypter, exp Expectations) ([]byte, error) {
	return OpenBound(context.Background(), compact, d, exp, nil, time.Now)
}

// wrapperOf opens compact with raw Open and parses the wrapper, so tests
// can pin the sealed wrapper fields independently of OpenBound.
func wrapperOf(t *testing.T, compact string, d Decrypter) boundWrapper {
	t.Helper()
	plaintext, err := Open(compact, d)
	require.NoError(t, err)
	var wrapper boundWrapper
	require.NoError(t, json.Unmarshal(plaintext, &wrapper))
	return wrapper
}

// TestSealBoundOpenBoundRoundTrip pins the SDKP-001 happy path: a payload
// sealed through SealBound with a binding opens through OpenBound back to
// the original data bytes when the wrapper matches the expectations.
func TestSealBoundOpenBoundRoundTrip(t *testing.T) {
	recipient := newRecipient(t)
	payload := pepperShapedPayload()

	compact, err := SealBound(payload, "bound-kid", recipient.PublicKey(), boundBinding())
	require.NoError(t, err)

	data, err := openBound(compact, recipient, boundExpectations())
	require.NoError(t, err)
	assert.Equal(t, payload, data,
		"SealBound followed by OpenBound must return the original data bytes")
}

// TestSealBoundGeneratesIatAndNonce pins the wrapper defaults: a binding
// with a zero IssuedAt seals an iat of the seal time in Unix seconds, and
// an empty Nonce is replaced by a fresh >=128-bit random base64url value
// that differs between seals.
func TestSealBoundGeneratesIatAndNonce(t *testing.T) {
	recipient := newRecipient(t)

	before := time.Now()
	compact, err := SealBound([]byte("payload"), "bound-kid", recipient.PublicKey(), boundBinding())
	require.NoError(t, err)
	after := time.Now()

	wrapper := wrapperOf(t, compact, recipient)
	assert.Equal(t, boundVersion, wrapper.V, "the wrapper must carry the current version")
	assert.GreaterOrEqual(t, wrapper.Iat, before.Unix(), "zero IssuedAt must seal as the seal time")
	assert.LessOrEqual(t, wrapper.Iat, after.Unix(), "zero IssuedAt must seal as the seal time")
	require.NotEmpty(t, wrapper.Nonce, "an empty Nonce must be generated at seal time")
	assert.LessOrEqual(t, len(wrapper.Nonce), 64, "the nonce must stay within the 64-char wire limit")
	assert.GreaterOrEqual(t, len(wrapper.Nonce), 22, "a >=128-bit base64url nonce is at least 22 chars")

	second, err := SealBound([]byte("payload"), "bound-kid", recipient.PublicKey(), boundBinding())
	require.NoError(t, err)
	assert.NotEqual(t, wrapper.Nonce, wrapperOf(t, second, recipient).Nonce,
		"every seal must generate a fresh nonce")
}

// TestOpenBoundRejectsMismatchedBinding pins the fail-closed binding
// checks in order: a wrapper whose v is not 1, or whose to, from, or
// service differs from the Expectations, is rejected with nil data.
func TestOpenBoundRejectsMismatchedBinding(t *testing.T) {
	recipient := newRecipient(t)
	exp := boundExpectations()

	// sealWrapper seals an arbitrary wrapper value as the JWE plaintext.
	sealWrapper := func(t *testing.T, wrapper boundWrapper) string {
		t.Helper()
		plaintext, err := json.Marshal(wrapper)
		require.NoError(t, err)
		compact, err := Seal(plaintext, "bound-kid", recipient.PublicKey())
		require.NoError(t, err)
		return compact
	}
	// sealBound seals a binding through SealBound.
	sealBound := func(t *testing.T, binding Binding) string {
		t.Helper()
		compact, err := SealBound([]byte(`{"amount":100}`), "bound-kid", recipient.PublicKey(), binding)
		require.NoError(t, err)
		return compact
	}

	good := boundWrapper{
		V:       boundVersion,
		From:    "party-seller",
		To:      "party-recipient",
		Service: "consultation",
		Iat:     time.Now().Unix(),
		Nonce:   "m8TqmKz0qNqKz0qNqKz0qA",
		Data:    []byte(`{"amount":100}`),
	}

	cases := map[string]func(t *testing.T) string{
		"v zero": func(t *testing.T) string {
			w := good
			w.V = 0
			return sealWrapper(t, w)
		},
		"v other than 1": func(t *testing.T) string {
			w := good
			w.V = 2
			return sealWrapper(t, w)
		},
		"to differs": func(t *testing.T) string {
			binding := boundBinding()
			binding.To = "party-attacker"
			return sealBound(t, binding)
		},
		"from differs": func(t *testing.T) string {
			binding := boundBinding()
			binding.From = "party-attacker"
			return sealBound(t, binding)
		},
		"service differs": func(t *testing.T) string {
			binding := boundBinding()
			binding.Service = "other-service"
			return sealBound(t, binding)
		},
	}
	for name, seal := range cases {
		t.Run(name, func(t *testing.T) {
			compact := seal(t)
			data, err := openBound(compact, recipient, exp)
			assert.Error(t, err, "a wrapper failing the %s check must be rejected", name)
			assert.Nil(t, data, "a rejected wrapper must return nil data")
		})
	}
}

// TestOpenBoundRejectsOversizedData pins the data-size cap: a wrapper
// whose raw data exceeds 524288 bytes is rejected with nil data.
func TestOpenBoundRejectsOversizedData(t *testing.T) {
	recipient := newRecipient(t)

	payload := make([]byte, maxBoundDataBytes+1)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	compact, err := SealBound(payload, "bound-kid", recipient.PublicKey(), boundBinding())
	require.NoError(t, err)

	data, err := openBound(compact, recipient, boundExpectations())
	assert.Error(t, err, "data beyond the cap must be rejected")
	assert.Nil(t, data, "an oversized wrapper must return nil data")
}
