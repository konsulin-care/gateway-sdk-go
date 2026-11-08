package wire

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseExternalIDValid(t *testing.T) {
	party, domain, opaque, err := ParseExternalID("pty-a:listing:lst-1")
	require.NoError(t, err)
	assert.Equal(t, "pty-a", party)
	assert.Equal(t, "listing", domain)
	assert.Equal(t, "lst-1", opaque)
}

func TestParseExternalIDInvalid(t *testing.T) {
	for _, in := range []string{"", "a", "a:b", "a:b:c:d", ":b:c", "a::c", "a:b:", "::"} {
		_, _, _, err := ParseExternalID(in)
		assert.ErrorIs(t, err, ErrInvalidExternalID, in)
	}
}
