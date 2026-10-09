package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/altcha-org/altcha-lib-go"
)

const testKey = "test-hmac-key"

func withAltcha(c *Config) { c.AltchaKey, c.AltchaMaxNumber = testKey, 1000 }

// solve answers a challenge the way the browser widget does and returns the
// base64 JSON payload it would put in the form.
func solve(t *testing.T, c altcha.Challenge) string {
	t.Helper()
	sol, err := altcha.SolveChallenge(c.Challenge, c.Salt, altcha.Algorithm(c.Algorithm), int(c.MaxNumber), 0, nil)
	if err != nil || sol == nil {
		t.Fatalf("solving challenge: %v", err)
	}
	return encodePayload(t, altcha.Payload{
		Algorithm: c.Algorithm, Challenge: c.Challenge, Number: int64(sol.Number), Salt: c.Salt, Signature: c.Signature,
	})
}

func encodePayload(t *testing.T, p altcha.Payload) string {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

func (h *harness) challenge() altcha.Challenge {
	h.t.Helper()
	rec := h.get("/altcha")
	if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
		h.t.Fatalf("GET /altcha: %d, Cache-Control %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	var c altcha.Challenge
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		h.t.Fatal(err)
	}
	return c
}

func TestAltchaForm(t *testing.T) {
	h := newHarness(t, withAltcha)

	rec := h.get("/")
	if !strings.Contains(rec.Body.String(), `<altcha-widget challenge="/altcha"`) {
		t.Fatal("form has no ALTCHA widget")
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "worker-src 'self'") {
		t.Fatalf("form CSP does not allow the widget: %q", csp)
	}

	form := url.Values{"content": {"verified"}, "expiry": {"1d"}}
	if rec := h.post("/", form); rec.Code != http.StatusBadRequest {
		t.Fatalf("form without ALTCHA answer: %d, want 400", rec.Code)
	}
	if len(h.pastes.pastes) != 0 {
		t.Fatal("paste stored without an ALTCHA answer")
	}

	form.Set("altcha", solve(t, h.challenge()))
	if rec := h.post("/", form); rec.Code != http.StatusSeeOther {
		t.Fatalf("form with a solved challenge: %d %s", rec.Code, rec.Body)
	}
	rec = h.post("/", form)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "verified") {
		t.Fatalf("replayed answer: %d, want 400 with the content kept", rec.Code)
	}
	if len(h.pastes.pastes) != 1 {
		t.Fatalf("%d pastes stored, want 1", len(h.pastes.pastes))
	}
}

func TestAltchaRejects(t *testing.T) {
	h := newHarness(t, withAltcha)
	c := h.challenge()
	good := solve(t, c)
	var p altcha.Payload
	raw, _ := base64.StdEncoding.DecodeString(good)
	_ = json.Unmarshal(raw, &p)

	wrongNumber := p
	wrongNumber.Number++
	wrongSig := p
	wrongSig.Signature = strings.Repeat("0", len(p.Signature))
	for name, payload := range map[string]string{
		"garbage":      "not base64!",
		"wrong number": encodePayload(t, wrongNumber),
		"wrong sig":    encodePayload(t, wrongSig),
	} {
		form := url.Values{"content": {"x"}, "expiry": {"1d"}, "altcha": {payload}}
		if rec := h.post("/", form); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, rec.Code)
		}
	}

	// A challenge signed with another key is refused.
	other := newVerifier("other-key", 1000, time.Minute)
	oc, _ := other.challenge(time.Now())
	form := url.Values{"content": {"x"}, "expiry": {"1d"}, "altcha": {solve(t, oc)}}
	if rec := h.post("/", form); rec.Code != http.StatusBadRequest {
		t.Errorf("foreign challenge: %d, want 400", rec.Code)
	}
}

func TestAltchaExpired(t *testing.T) {
	v := newVerifier(testKey, 1000, time.Minute)
	c, err := v.challenge(time.Now().Add(-2 * time.Minute)) // expired a minute ago
	if err != nil {
		t.Fatal(err)
	}
	if v.verify(solve(t, c), time.Now()) {
		t.Fatal("expired challenge accepted")
	}
}

func TestAltchaReplayForgottenAfterExpiry(t *testing.T) {
	v := newVerifier(testKey, 1000, time.Minute)
	now := time.Now()
	c, _ := v.challenge(now)
	if !v.verify(solve(t, c), now) {
		t.Fatal("fresh answer refused")
	}
	if len(v.used) != 1 {
		t.Fatalf("%d answers remembered, want 1", len(v.used))
	}
	c2, _ := v.challenge(now)
	v.verify(solve(t, c2), now.Add(2*time.Minute)) // prunes the first
	if _, ok := v.used[c.Signature]; ok {
		t.Fatal("expired answer still remembered")
	}
}

func TestAltchaLeavesAPIAlone(t *testing.T) {
	h := newHarness(t, withAltcha)
	h.createAPI("", "from curl, no widget")
}

func TestAltchaOff(t *testing.T) {
	h := newHarness(t, nil)
	rec := h.get("/")
	if strings.Contains(rec.Body.String(), "altcha") {
		t.Fatal("ALTCHA widget shown with no key configured")
	}
	if strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src") {
		t.Fatal("form CSP allows scripts with ALTCHA off")
	}
	if rec := h.get("/altcha"); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /altcha with ALTCHA off: %d, want 404", rec.Code)
	}
}
