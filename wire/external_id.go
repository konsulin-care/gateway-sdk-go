package wire

import (
	"errors"
	"strings"
)

// ErrInvalidExternalID reports a malformed party:domain:opaque external id.
var ErrInvalidExternalID = errors.New("wire: invalid external id")

// ParseExternalID splits a full external id of the form party:domain:opaque
// (GWP-004). It requires exactly three non-empty ':'-separated parts.
// It returns the party, domain, and opaque parts, or ErrInvalidExternalID.
func ParseExternalID(full string) (party, domain, opaque string, err error) {
	parts := strings.Split(full, ":")
	if len(parts) != 3 {
		return "", "", "", ErrInvalidExternalID
	}
	for _, p := range parts {
		if p == "" {
			return "", "", "", ErrInvalidExternalID
		}
	}
	return parts[0], parts[1], parts[2], nil
}
