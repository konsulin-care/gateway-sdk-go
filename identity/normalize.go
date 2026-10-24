package identity

import (
	"fmt"
	"strings"
)

// NormalizeEmail canonicalizes an email identity field per SDK-ID-001:
// surrounding whitespace is trimmed and the address is lowercased. The result
// contains exactly one '@' with a non-empty local part and a non-empty domain
// that has no leading, trailing, or consecutive dots.
//
// Parameters:
//   - raw: the email as supplied by the caller.
//
// Return value: the normalized email, or an error if the input is malformed.
// A rejected input never produces a value.
func NormalizeEmail(raw string) (string, error) {
	email := strings.ToLower(strings.TrimSpace(raw))
	at := strings.Index(email, "@")
	if at <= 0 || at != strings.LastIndex(email, "@") || at == len(email)-1 {
		return "", fmt.Errorf("identity: malformed email %q: want exactly one '@' with non-empty local and domain", raw)
	}
	domain := email[at+1:]
	if strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") {
		return "", fmt.Errorf("identity: malformed email %q: domain %q has empty label", raw, domain)
	}
	return email, nil
}

// NormalizePhone canonicalizes a phone identity field per SDK-ID-001 to E.164
// digits: surrounding whitespace and every non-digit character (including a
// leading '+') are stripped. The result must be 10 to 15 digits and must not
// start with '0' (the country prefix is expected in international form, e.g.
// "+62 812-3456-7890" normalizes to "6281234567890").
//
// Parameters:
//   - raw: the phone as supplied by the caller.
//
// Return value: the digit-only normalized phone without '+', or an error if
// the digit count or leading-digit rule is violated. A rejected input never
// produces a value.
func NormalizePhone(raw string) (string, error) {
	var digits strings.Builder
	for _, r := range strings.TrimSpace(raw) {
		if r >= '0' && r <= '9' {
			_, _ = digits.WriteRune(r)
		}
	}
	normalized := digits.String()
	if len(normalized) < 10 || len(normalized) > 15 {
		return "", fmt.Errorf("identity: malformed phone %q: want 10..15 digits, got %d", raw, len(normalized))
	}
	if strings.HasPrefix(normalized, "0") {
		return "", fmt.Errorf("identity: malformed phone %q: leading zero, want international form without '+'", raw)
	}
	return normalized, nil
}
