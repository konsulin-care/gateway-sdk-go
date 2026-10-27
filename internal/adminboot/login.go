package adminboot

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/konsulin-care/gateway-sdk-go/wire"
)

// Client performs the minimal admin bootstrap calls the conformance
// runner needs for setup: login, party creation, enrollment tokens,
// capability grants, and party revocation. It stays internal and is
// never part of the public client (PRD §5). The client holds no
// logger and never logs credentials, tokens, or bodies — errors carry
// only path context and the gateway envelope (PRD §8).
type Client struct {
	// base is the gateway base URL (scheme://host[:port], no trailing
	// slash).
	base string
	// hc is the HTTP client every request is issued through.
	hc *http.Client
}

// New builds a Client for the gateway at baseURL.
//
// Parameters: baseURL is the gateway base URL; hc is the HTTP client
// to issue requests through (nil selects http.DefaultClient).
// Returns: the ready Client.
func New(baseURL string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{base: strings.TrimRight(baseURL, "/"), hc: hc}
}

// loginRequest is the POST /v1/admin/auth/login body: username and
// password only — this development-mode bootstrap sends no TOTP field
// (the gateway TOTP secret is unset).
type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// loginResponse is the Bruno success shape of the admin login: the
// admin bearer token, its scheme, and its lifetime in seconds.
type loginResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
	ExpiresIn int    `json:"expires_in"`
}

// Login posts the operator username and password to
// POST /v1/admin/auth/login and returns the admin bearer token.
// Password-only: no TOTP field is sent (development-mode gateway,
// secret unset). A non-2xx response surfaces as *wire.Error (a 401
// carries GW-ADMIN-001); the credentials never appear in the returned
// error or any log.
//
// Parameters: ctx is the call context; username and pass are the
// operator credentials.
// Returns: the admin bearer token, or the failure.
func (c *Client) Login(ctx context.Context, username, pass string) (string, error) {
	payload, err := json.Marshal(loginRequest{Username: username, Password: pass})
	if err != nil {
		return "", fmt.Errorf("adminboot: login: encode request: %w", err)
	}
	var resp loginResponse
	if err := c.post(ctx, "/v1/admin/auth/login", "", payload, &resp); err != nil {
		return "", err
	}
	if resp.Token == "" {
		return "", fmt.Errorf("adminboot: login: response carried no token")
	}
	return resp.Token, nil
}

// post issues one admin POST through the client: bearer is sent as
// "Authorization: Bearer" when non-empty, payload as the JSON body
// when non-empty, and a 2xx response decodes into out (nil skips the
// decode). Any non-2xx response returns the wire error envelope as
// *wire.Error (SDK-WIRE-003). The request payload is never echoed into
// errors or logs.
//
// Parameters: ctx is the call context; path is the request path off
// the base URL; bearer is the admin token or "" for login; payload is
// the request body; out receives the decoded 2xx body when non-nil.
// Returns: nil on 2xx, or the failure (a gateway error as *wire.Error).
func (c *Client) post(ctx context.Context, path, bearer string, payload []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("adminboot: build request %s: %w", path, err)
	}
	if len(payload) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("adminboot: %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("adminboot: read %s response: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return wire.DecodeError(resp.StatusCode, body)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			return fmt.Errorf("adminboot: decode %s response: %w", path, err)
		}
	}
	return nil
}
