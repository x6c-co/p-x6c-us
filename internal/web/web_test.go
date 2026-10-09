package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/x6c-co/p-x6c-us/internal/ids"
	"github.com/x6c-co/p-x6c-us/internal/keyring"
	"github.com/x6c-co/p-x6c-us/internal/store"
)

const base = "https://p.example"

// memPastes mimics store.Store's semantics in memory.
type memPastes struct {
	mu     sync.Mutex
	pastes map[string]store.Paste
}

func (m *memPastes) CreatePaste(_ context.Context, p store.Paste) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.pastes[p.ID]; ok {
		return store.ErrDuplicateID
	}
	m.pastes[p.ID] = p
	return nil
}

func (m *memPastes) Paste(_ context.Context, id string, now time.Time) (*store.Paste, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.pastes[id]
	if !ok || (!p.ExpiresAt.IsZero() && !p.ExpiresAt.After(now)) {
		return nil, store.ErrNotFound
	}
	return &p, nil
}

func (m *memPastes) DeletePaste(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.pastes[id]
	delete(m.pastes, id)
	return ok, nil
}

func (m *memPastes) Ping(context.Context) error { return nil }

// keyStore and wrapper give keyring.Load an in-memory store and a
// pass-through "rypt".
type keyStore struct{ keys []store.DataKey }

func (k *keyStore) DataKeys(context.Context) ([]store.DataKey, error) { return k.keys, nil }
func (k *keyStore) AddDataKey(_ context.Context, d store.DataKey) error {
	k.keys = append(k.keys, d)
	return nil
}

type wrapper struct{}

func (wrapper) Wrap(context.Context, []byte) ([]byte, []byte, error) {
	dek := make([]byte, 32)
	rand.Read(dek)
	return dek, dek, nil
}
func (wrapper) Unwrap(_ context.Context, w, _ []byte) ([]byte, error) { return w, nil }

type harness struct {
	t      *testing.T
	pastes *memPastes
	now    time.Time
	h      http.Handler
}

func newHarness(t *testing.T, mod func(*Config)) *harness {
	t.Helper()
	ring, err := keyring.Load(context.Background(), &keyStore{}, wrapper{})
	if err != nil {
		t.Fatal(err)
	}
	gen, _ := ids.New("uuid", 0)
	h := &harness{t: t, pastes: &memPastes{pastes: map[string]store.Paste{}}, now: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	cfg := Config{
		Pastes: h.pastes, Ring: ring, IDs: gen, BaseURL: base, MaxBytes: 1024,
		CreateBurst: 100, CreateEvery: time.Second,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now: func() time.Time { return h.now },
	}
	if mod != nil {
		mod(&cfg)
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.h = s.Handler()
	return h
}

func (h *harness) do(req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.h.ServeHTTP(rec, req)
	return rec
}

func (h *harness) get(path string) *httptest.ResponseRecorder {
	return h.do(httptest.NewRequest(http.MethodGet, path, nil))
}

func (h *harness) post(path string, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return h.do(req)
}

func (h *harness) api(query string, body []byte) *httptest.ResponseRecorder {
	return h.do(httptest.NewRequest(http.MethodPost, "/api/paste"+query, bytes.NewReader(body)))
}

// createAPI makes a paste through the API and returns its path.
func (h *harness) createAPI(query, content string) string {
	h.t.Helper()
	rec := h.api(query, []byte(content))
	if rec.Code != http.StatusCreated {
		h.t.Fatalf("API create: %d %s", rec.Code, rec.Body)
	}
	return strings.TrimPrefix(strings.TrimSpace(rec.Body.String()), base)
}

func TestFormCreateAndView(t *testing.T) {
	h := newHarness(t, nil)
	rec := h.post("/", url.Values{"content": {"a <b>\r\nline 2"}, "expiry": {"1d"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	path := rec.Header().Get("Location")

	rec = h.get(path)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "a &lt;b&gt;\nline 2") {
		t.Fatalf("view: %d, want escaped content in\n%s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("paste page is cacheable")
	}

	rec = h.get("/raw" + path)
	if rec.Code != 200 || rec.Body.String() != "a <b>\nline 2" {
		t.Fatalf("raw: %d %q (CRLF should become LF)", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("raw Content-Type = %q", ct)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.HasPrefix(csp, "sandbox") {
		t.Errorf("raw CSP = %q", csp)
	}
}

func TestStoredAsCiphertext(t *testing.T) {
	h := newHarness(t, nil)
	h.createAPI("", "the secret text")
	for _, p := range h.pastes.pastes {
		if bytes.Contains(p.Ciphertext, []byte("secret")) {
			t.Fatal("plaintext found in stored ciphertext")
		}
	}
}

func TestAPICreate(t *testing.T) {
	h := newHarness(t, nil)
	rec := h.api("?expiry=1h", []byte("from curl\n"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	u := strings.TrimSpace(rec.Body.String())
	if !strings.HasPrefix(u, base+"/") || rec.Header().Get("Location") != u {
		t.Fatalf("body %q, Location %q", u, rec.Header().Get("Location"))
	}
	path := strings.TrimPrefix(u, base)
	if got := h.get("/raw" + path).Body.String(); got != "from curl\n" {
		t.Fatalf("raw = %q", got)
	}
	h.now = h.now.Add(time.Hour)
	if rec := h.get(path); rec.Code != http.StatusNotFound {
		t.Fatalf("after expiry: %d, want 404", rec.Code)
	}
}

func TestNeverExpires(t *testing.T) {
	h := newHarness(t, nil)
	path := h.createAPI("?expiry=never", "forever")
	if p := h.pastes.pastes[strings.TrimPrefix(path, "/")]; !p.ExpiresAt.IsZero() {
		t.Fatalf("stored expiry %v, want the zero time", p.ExpiresAt)
	}
	rec := h.get(path)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "never expires") {
		t.Fatalf("view: %d, want a page saying it never expires", rec.Code)
	}
	h.now = h.now.AddDate(100, 0, 0)
	if got := h.get("/raw" + path); got.Code != 200 || got.Body.String() != "forever" {
		t.Fatalf("raw a century later: %d %q", got.Code, got.Body)
	}

	rec = h.post("/", url.Values{"content": {"form forever"}, "expiry": {"never"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("form create with never: %d", rec.Code)
	}
	if !strings.Contains(h.get("/").Body.String(), `<option value="never">Never</option>`) {
		t.Fatal("form has no Never option")
	}
}

func TestBurnAfterRead(t *testing.T) {
	h := newHarness(t, nil)
	rec := h.post("/", url.Values{"content": {"burn me"}, "expiry": {"1d"}, "burn": {"on"}})
	if rec.Code != http.StatusCreated || strings.Contains(rec.Body.String(), "burn me") {
		t.Fatalf("create: %d, want 201 with a link and no content", rec.Code)
	}
	var path string
	for id := range h.pastes.pastes {
		path = "/" + id
	}
	if !strings.Contains(rec.Body.String(), base+path) {
		t.Fatal("created page does not show the paste link")
	}

	// GETs (link previews) must not reveal or burn it.
	for range 2 {
		rec = h.get(path)
		if rec.Code != 200 || strings.Contains(rec.Body.String(), "burn me") {
			t.Fatalf("GET: %d, want the confirm page without content", rec.Code)
		}
	}
	rec = h.post(path, nil)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "burn me") {
		t.Fatalf("reveal: %d %s", rec.Code, rec.Body)
	}
	if rec := h.post(path, nil); rec.Code != http.StatusNotFound {
		t.Fatalf("second reveal: %d, want 404", rec.Code)
	}
	if rec := h.get("/raw" + path); rec.Code != http.StatusNotFound {
		t.Fatalf("raw after reveal: %d, want 404", rec.Code)
	}
}

func TestBurnViaRaw(t *testing.T) {
	h := newHarness(t, nil)
	path := h.createAPI("?burn=1", "once")
	if got := h.get("/raw" + path); got.Code != 200 || got.Body.String() != "once" {
		t.Fatalf("first raw: %d %q", got.Code, got.Body)
	}
	if got := h.get("/raw" + path); got.Code != http.StatusNotFound {
		t.Fatalf("second raw: %d, want 404", got.Code)
	}
}

func TestRevealOfNormalPasteRedirects(t *testing.T) {
	h := newHarness(t, nil)
	path := h.createAPI("", "keep")
	if rec := h.post(path, nil); rec.Code != http.StatusSeeOther {
		t.Fatalf("%d, want 303", rec.Code)
	}
	if rec := h.get(path); rec.Code != 200 {
		t.Fatalf("paste gone after POST: %d", rec.Code)
	}
}

func TestRejects(t *testing.T) {
	h := newHarness(t, nil)
	tests := []struct {
		name  string
		query string
		body  []byte
		want  int
	}{
		{"empty", "", nil, 400},
		{"whitespace", "", []byte(" \n\t"), 400},
		{"too large", "", bytes.Repeat([]byte("a"), 1025), 413},
		{"not utf-8", "", []byte{0xff, 0xfe, 'a'}, 400},
		{"nul byte", "", []byte("a\x00b"), 400},
		{"bad expiry", "?expiry=forever", []byte("a"), 400},
	}
	for _, tt := range tests {
		if rec := h.api(tt.query, tt.body); rec.Code != tt.want {
			t.Errorf("%s: %d, want %d", tt.name, rec.Code, tt.want)
		}
	}
	if len(h.pastes.pastes) != 0 {
		t.Fatalf("%d pastes stored from rejected requests", len(h.pastes.pastes))
	}
	// Exactly the limit is fine.
	h.createAPI("", strings.Repeat("a", 1024))

	rec := h.post("/", url.Values{"content": {strings.Repeat("a", 4000)}, "expiry": {"1d"}})
	if rec.Code != 413 {
		t.Fatalf("oversized form: %d, want 413", rec.Code)
	}
	rec = h.post("/", url.Values{"content": {"keep me"}, "expiry": {"bogus"}})
	if rec.Code != 400 || !strings.Contains(rec.Body.String(), "keep me") {
		t.Fatalf("rejected form should be re-shown with its content: %d", rec.Code)
	}
}

func TestNotFound(t *testing.T) {
	h := newHarness(t, nil)
	for _, p := range []string{"/nope", "/raw/nope", "/a.b", "/raw/a.b"} {
		if rec := h.get(p); rec.Code != http.StatusNotFound {
			t.Errorf("GET %s: %d, want 404", p, rec.Code)
		}
	}
}

func TestDuplicateIDRetries(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.IDs = &seqIDs{ids: []string{"same", "same", "other"}} })
	if p := h.createAPI("", "one"); p != "/same" {
		t.Fatalf("first paste at %s", p)
	}
	if p := h.createAPI("", "two"); p != "/other" {
		t.Fatalf("second paste at %s, want /other after a clash", p)
	}
	if got := h.get("/raw/other").Body.String(); got != "two" {
		t.Fatalf("retried paste reads %q", got)
	}
}

type seqIDs struct{ ids []string }

func (s *seqIDs) New() string { id := s.ids[0]; s.ids = s.ids[1:]; return id }

func TestRateLimit(t *testing.T) {
	newReq := func(remote, realIP string) *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/paste", strings.NewReader("x"))
		req.RemoteAddr = remote + ":1234"
		if realIP != "" {
			req.Header.Set("X-Real-Ip", realIP)
		}
		return req
	}
	limit := func(trust bool) func(*Config) {
		return func(c *Config) { c.CreateBurst, c.CreateEvery, c.TrustProxy = 2, time.Minute, trust }
	}

	h := newHarness(t, limit(false))
	for i, want := range []int{201, 201, 429} {
		// Without TrustProxy a spoofed X-Real-Ip changes nothing.
		if rec := h.do(newReq("192.0.2.1", "198.51.100."+string(rune('1'+i)))); rec.Code != want {
			t.Fatalf("request %d: %d, want %d", i, rec.Code, want)
		}
	}
	if rec := h.do(newReq("192.0.2.2", "")); rec.Code != 201 {
		t.Fatalf("another client: %d, want 201", rec.Code)
	}
	h.now = h.now.Add(time.Minute)
	if rec := h.do(newReq("192.0.2.1", "")); rec.Code != 201 {
		t.Fatalf("after refill: %d, want 201", rec.Code)
	}

	h = newHarness(t, limit(true))
	for i, want := range []int{201, 201, 429} {
		// Behind the proxy, X-Real-Ip is the client; IPv6 shares a /64.
		ip := "2001:db8:1:2::" + string(rune('a'+i))
		if rec := h.do(newReq("10.0.0.1", ip)); rec.Code != want {
			t.Fatalf("v6 request %d: %d, want %d", i, rec.Code, want)
		}
	}
	if rec := h.do(newReq("10.0.0.1", "2001:db8:1:3::a")); rec.Code != 201 {
		t.Fatalf("other /64: %d, want 201", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := newHarness(t, nil)
	rec := h.get("/")
	for k, want := range map[string]string{
		"X-Content-Type-Options":    "nosniff",
		"Referrer-Policy":           "no-referrer",
		"X-Frame-Options":           "DENY",
		"Strict-Transport-Security": "max-age=31536000",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP = %q", csp)
	}
	if rec := h.get("/static/style.css"); rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/css") {
		t.Errorf("stylesheet: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
}

type failingPastes struct{ memPastes }

func (*failingPastes) Ping(context.Context) error { return errors.New("down") }

func TestReadyz(t *testing.T) {
	if rec := newHarness(t, nil).get("/readyz"); rec.Code != 200 {
		t.Fatalf("readyz: %d", rec.Code)
	}
	h := newHarness(t, func(c *Config) { c.Pastes = &failingPastes{} })
	if rec := h.get("/readyz"); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz with rqlite down: %d, want 503", rec.Code)
	}
}
