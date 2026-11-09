package wire_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/konsulin-care/gateway-sdk-go/client"
	"github.com/konsulin-care/gateway-sdk-go/gatewaytest"
	"github.com/konsulin-care/gateway-sdk-go/verify"
	"github.com/konsulin-care/gateway-sdk-go/wire"
)

var _ wire.ReplayCache = (*gatewaytest.ReplayCache)(nil)

// TestReplayScopes asserts the scope constant values and verify aliases.
func TestReplayScopes(t *testing.T) {
	assert.Equal(t, "jti", wire.ScopeJTI)
	assert.Equal(t, "webhook_id", wire.ScopeWebhookID)
	assert.Equal(t, "nonce", wire.ScopeNonce)
	assert.Equal(t, wire.ScopeJTI, verify.ScopeJTI)
	assert.Equal(t, wire.ScopeWebhookID, verify.ScopeWebhookID)
}

// TestReplayCacheSharedAcrossPackages asserts one cache satisfies all users.
func TestReplayCacheSharedAcrossPackages(t *testing.T) {
	mc := verify.NewMemoryReplayCache(nil)
	var rc wire.ReplayCache = mc
	require.NotNil(t, rc)
	assert.NotNil(t, client.WithReplayCache(mc))
	assert.NotNil(t, verify.WithReplayCache(mc))
	var gc wire.ReplayCache = gatewaytest.NewReplayCache()
	assert.NotNil(t, gc)
}
