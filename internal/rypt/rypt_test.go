package rypt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

const keyID = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"

// fake implements wrap/unwrap by prefixing the AAD, enough to check that the
// client sends and decodes the right fields.
func fake(t *testing.T) *httptest.Server {
	dek := bytes.Repeat([]byte{7}, 32)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ry_test" {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized", "message": "no", "request_id": "r1"})
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q", r.Header.Get("Content-Type"))
		}
		var req struct {
			Wrapped []byte `json:"wrapped"`
			AAD     []byte `json:"aad"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch r.URL.Path {
		case "/v1/keys/" + keyID + "/wrap":
			_ = json.NewEncoder(w).Encode(map[string][]byte{"dek": dek, "wrapped": append([]byte("W:"), req.AAD...)})
		case "/v1/keys/" + keyID + "/unwrap":
			if !bytes.Equal(req.Wrapped, append([]byte("W:"), req.AAD...)) {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_ciphertext", "message": "bad", "request_id": "r2"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string][]byte{"dek": dek})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestWrapUnwrap(t *testing.T) {
	srv := fake(t)
	defer srv.Close()
	c := New(srv.URL+"/", keyID, "ry_test")
	ctx := context.Background()

	dek, wrapped, err := c.Wrap(ctx, []byte("ctx-a"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.Unwrap(ctx, wrapped, []byte("ctx-a"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapped key differs from wrapped key")
	}

	_, err = c.Unwrap(ctx, wrapped, []byte("ctx-b"))
	var e *Error
	if !errors.As(err, &e) || e.Status != 400 || e.Code != "invalid_ciphertext" || e.RequestID != "r2" {
		t.Fatalf("Unwrap with wrong AAD: %v", err)
	}
}

func TestAuthError(t *testing.T) {
	srv := fake(t)
	defer srv.Close()
	_, _, err := New(srv.URL, keyID, "ry_wrong").Wrap(context.Background(), nil)
	var e *Error
	if !errors.As(err, &e) || e.Status != 401 || e.Code != "unauthorized" {
		t.Fatalf("got %v, want 401 unauthorized", err)
	}
}

func TestNonJSONError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}))
	defer srv.Close()
	_, _, err := New(srv.URL, keyID, "ry_test").Wrap(context.Background(), nil)
	var e *Error
	if !errors.As(err, &e) || e.Status != 502 || e.Code != "unexpected_response" {
		t.Fatalf("got %v, want 502 unexpected_response", err)
	}
}
