// Package rypt is a minimal client for the envelope half of the rypt.dev API:
// wrap and unwrap of data keys. Paste text never goes to rypt; only data keys
// do.
package rypt

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client calls one rypt key with one API key.
type Client struct {
	base  string
	keyID string
	token string
	http  *http.Client
}

// New returns a client for the rypt key keyID at baseURL (normally
// https://api.rypt.dev), authenticating with token (ry_…).
func New(baseURL, keyID, token string) *Client {
	return &Client{
		base:  strings.TrimRight(baseURL, "/"),
		keyID: keyID,
		token: token,
		http:  &http.Client{Timeout: 15 * time.Second},
	}
}

// Error is rypt's error envelope, returned for any non-2xx response.
type Error struct {
	Status    int    `json:"-"`
	Code      string `json:"error"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("rypt: %d %s: %s (request %s)", e.Status, e.Code, e.Message, e.RequestID)
}

// Wrap has rypt generate a 32-byte data key and returns it with its wrapped
// form. aad binds the wrapped key to its context: Unwrap must be given the same.
func (c *Client) Wrap(ctx context.Context, aad []byte) (dek, wrapped []byte, err error) {
	var resp struct {
		DEK     []byte `json:"dek"`
		Wrapped []byte `json:"wrapped"`
	}
	if err := c.post(ctx, "wrap", map[string]any{"aad": aad}, &resp); err != nil {
		return nil, nil, err
	}
	if len(resp.DEK) != 32 || len(resp.Wrapped) == 0 {
		return nil, nil, fmt.Errorf("rypt: wrap returned a %d-byte key and %d-byte wrapped form", len(resp.DEK), len(resp.Wrapped))
	}
	return resp.DEK, resp.Wrapped, nil
}

// Unwrap returns the data key inside wrapped.
func (c *Client) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	var resp struct {
		DEK []byte `json:"dek"`
	}
	if err := c.post(ctx, "unwrap", map[string]any{"wrapped": wrapped, "aad": aad}, &resp); err != nil {
		return nil, err
	}
	if len(resp.DEK) != 32 {
		return nil, fmt.Errorf("rypt: unwrap returned a %d-byte key, want 32", len(resp.DEK))
	}
	return resp.DEK, nil
}

// post sends body to /v1/keys/{key}/{op}. []byte values marshal as standard
// padded base64, which is what rypt expects.
func (c *Client) post(ctx context.Context, op string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/keys/"+c.keyID+"/"+op, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("rypt %s: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("rypt %s: %w", op, err)
	}
	if resp.StatusCode/100 != 2 {
		e := &Error{Status: resp.StatusCode}
		if json.Unmarshal(data, e) != nil || e.Code == "" {
			e.Code, e.Message = "unexpected_response", http.StatusText(resp.StatusCode)
		}
		return e
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("rypt %s: decoding response: %w", op, err)
	}
	return nil
}
