// Package web serves the pastebin: an HTML form, paste pages, raw text and a
// small API for curl.
package web

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/x6c-co/p-x6c-us/internal/ids"
	"github.com/x6c-co/p-x6c-us/internal/keyring"
	"github.com/x6c-co/p-x6c-us/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// Pastes is the part of store.Store the server needs.
type Pastes interface {
	CreatePaste(ctx context.Context, p store.Paste) error
	Paste(ctx context.Context, id string, now time.Time) (*store.Paste, error)
	DeletePaste(ctx context.Context, id string) (bool, error)
	Ping(ctx context.Context) error
}

type Config struct {
	Pastes   Pastes
	Ring     *keyring.Ring
	IDs      ids.Generator
	BaseURL  string // e.g. https://p.x6c.us, used in links handed out
	MaxBytes int    // largest paste accepted, in bytes of UTF-8

	// TrustProxy takes the client IP for rate limiting from X-Real-Ip. Only
	// set it behind a proxy that overwrites that header, as Traefik does.
	TrustProxy bool
	// Each client IP (or IPv6 /64) may create CreateBurst pastes at once,
	// then one per CreateEvery.
	CreateBurst int
	CreateEvery time.Duration

	Log *slog.Logger
	Now func() time.Time // defaults to time.Now
}

type Server struct {
	Config
	site    string
	tmpl    *template.Template
	limiter *limiter
}

type expiryOption struct {
	Value, Label string
	TTL          time.Duration
}

var expiries = []expiryOption{
	{"10m", "10 minutes", 10 * time.Minute},
	{"1h", "1 hour", time.Hour},
	{"1d", "1 day", 24 * time.Hour},
	{"1w", "1 week", 7 * 24 * time.Hour},
	{"30d", "30 days", 30 * 24 * time.Hour},
}

const defaultExpiry = "1d"

func New(cfg Config) (*Server, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("base URL %q is not an absolute URL", cfg.BaseURL)
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"utc": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	}).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{
		Config:  cfg,
		site:    u.Host,
		tmpl:    tmpl,
		limiter: newLimiter(cfg.CreateEvery, cfg.CreateBurst),
	}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("POST /{$}", s.createForm)
	mux.HandleFunc("POST /api/paste", s.createAPI)
	mux.HandleFunc("GET /raw/{id}", s.raw)
	mux.HandleFunc("GET /{id}", s.view)
	mux.HandleFunc("POST /{id}", s.reveal)
	mux.Handle("GET /static/", http.FileServerFS(staticFS))
	mux.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "User-agent: *\nDisallow: /\n")
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /readyz", s.ready)
	return s.headers(mux)
}

// headers sets the security headers every response gets. Handlers that serve
// raw text replace the Content-Security-Policy with a stricter one.
func (s *Server) headers(next http.Handler) http.Handler {
	hsts := strings.HasPrefix(s.BaseURL, "https://")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer") // paste URLs are the only secret
		h.Set("X-Robots-Tag", "noindex, nofollow")
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// page is the data every template gets; each uses the fields it needs.
type page struct {
	Site, Title string

	Expiries []expiryOption
	Expiry   string
	Burn     bool
	Content  string
	MaxKiB   int
	Error    string
	CurlURL  string

	ID, URL, RawURL  string
	Created, Expires time.Time
	Burned           bool

	Message string
}

func (s *Server) page(title string) page {
	return page{Site: s.site, Title: title}
}

func (s *Server) index(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "index", s.form(page{}))
}

// form fills in what the paste form needs, keeping anything already in p
// (such as the content of a rejected submission).
func (s *Server) form(p page) page {
	p.Site, p.Title = s.site, "New paste"
	p.Expiries, p.MaxKiB, p.CurlURL = expiries, s.MaxBytes/1024, s.BaseURL+"/api/paste"
	if p.Expiry == "" {
		p.Expiry = defaultExpiry
	}
	return p
}

// userError is a create failure the client caused, with the status to send.
type userError struct {
	status int
	msg    string
}

func (e *userError) Error() string { return e.msg }

func (s *Server) createForm(w http.ResponseWriter, r *http.Request) {
	// URL encoding can triple the size of the content.
	r.Body = http.MaxBytesReader(w, r.Body, int64(3*s.MaxBytes+16<<10))
	if err := r.ParseForm(); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			s.message(w, http.StatusRequestEntityTooLarge, "Too large", s.tooLarge().msg)
			return
		}
		s.message(w, http.StatusBadRequest, "Bad request", "The form could not be read.")
		return
	}
	// Browsers submit textarea line breaks as CRLF.
	content := strings.ReplaceAll(r.PostForm.Get("content"), "\r\n", "\n")
	expiry, burn := r.PostForm.Get("expiry"), r.PostForm.Get("burn") != ""

	id, err := s.create(r, []byte(content), expiry, burn)
	if err != nil {
		status, msg := s.createFailure(r, err)
		s.render(w, status, "index", s.form(page{Error: msg, Content: content, Expiry: expiry, Burn: burn}))
		return
	}
	if !burn {
		http.Redirect(w, r, "/"+id, http.StatusSeeOther)
		return
	}
	// Redirecting to a burn-after-read paste would only show its
	// confirmation page, so show the link to share instead.
	noStore(w)
	p := s.page("Paste created")
	p.ID, p.URL = id, s.BaseURL+"/"+id
	s.render(w, http.StatusCreated, "created", p)
}

// createAPI takes the raw request body as the paste, for curl:
//
//	curl --data-binary @file 'https://p.x6c.us/api/paste?expiry=1h&burn=1'
func (s *Server) createAPI(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(s.MaxBytes)+1))
	if err != nil {
		s.text(w, http.StatusBadRequest, "The request body could not be read.")
		return
	}
	q := r.URL.Query()
	expiry := q.Get("expiry")
	if expiry == "" {
		expiry = defaultExpiry
	}
	burn, _ := strconv.ParseBool(q.Get("burn"))
	id, err := s.create(r, body, expiry, burn)
	if err != nil {
		status, msg := s.createFailure(r, err)
		s.text(w, status, msg)
		return
	}
	u := s.BaseURL + "/" + id
	w.Header().Set("Location", u)
	s.text(w, http.StatusCreated, u)
}

func (s *Server) tooLarge() *userError {
	return &userError{http.StatusRequestEntityTooLarge, fmt.Sprintf("Pastes are limited to %d KiB.", s.MaxBytes/1024)}
}

// create validates, rate-limits, seals and stores a paste, returning its ID.
func (s *Server) create(r *http.Request, content []byte, expiry string, burn bool) (string, error) {
	var ttl time.Duration
	for _, e := range expiries {
		if e.Value == expiry {
			ttl = e.TTL
		}
	}
	switch {
	case ttl == 0:
		return "", &userError{http.StatusBadRequest, "Unknown expiry; use 10m, 1h, 1d, 1w or 30d."}
	case len(bytes.TrimSpace(content)) == 0:
		return "", &userError{http.StatusBadRequest, "The paste is empty."}
	case len(content) > s.MaxBytes:
		return "", s.tooLarge()
	case !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0:
		return "", &userError{http.StatusBadRequest, "Only UTF-8 text can be pasted."}
	}
	now := s.Now()
	if !s.limiter.allow(limitKey(s.clientIP(r)), now) {
		return "", &userError{http.StatusTooManyRequests, "Too many pastes from your address; try again in a few minutes."}
	}
	// A clash is only plausible with short IDs, but a new ID needs a new
	// seal because the ID is bound into the ciphertext.
	for range 3 {
		id := s.IDs.New()
		keyID, nonce, ct := s.Ring.Seal(id, content)
		err := s.Pastes.CreatePaste(r.Context(), store.Paste{
			ID: id, KeyID: keyID, Nonce: nonce, Ciphertext: ct,
			CreatedAt: now, ExpiresAt: now.Add(ttl), BurnAfterRead: burn,
		})
		if !errors.Is(err, store.ErrDuplicateID) {
			return id, err
		}
	}
	return "", errors.New("three paste IDs in a row were already taken")
}

// createFailure turns a create error into a status and a message for the
// client, logging server-side failures.
func (s *Server) createFailure(r *http.Request, err error) (int, string) {
	var ue *userError
	if errors.As(err, &ue) {
		return ue.status, ue.msg
	}
	s.Log.ErrorContext(r.Context(), "creating paste", "err", err)
	return http.StatusInternalServerError, "The paste could not be saved. Try again shortly."
}

// view shows a paste, or for a burn-after-read paste, a page asking to
// confirm. Link previews and scanners send GETs, so a GET never burns one.
func (s *Server) view(w http.ResponseWriter, r *http.Request) {
	p, content, ok := s.load(w, r, false)
	if !ok {
		return
	}
	noStore(w)
	if p.BurnAfterRead {
		pg := s.page("Burn after reading")
		pg.ID = p.ID
		s.render(w, http.StatusOK, "confirm", pg)
		return
	}
	s.render(w, http.StatusOK, "view", s.viewPage(p, content, false))
}

// reveal shows a burn-after-read paste once, deleting it.
func (s *Server) reveal(w http.ResponseWriter, r *http.Request) {
	p, content, ok := s.load(w, r, false)
	if !ok {
		return
	}
	if !p.BurnAfterRead {
		http.Redirect(w, r, "/"+p.ID, http.StatusSeeOther)
		return
	}
	if !s.burn(w, r, p, false) {
		return
	}
	noStore(w)
	s.render(w, http.StatusOK, "view", s.viewPage(p, content, true))
}

// raw serves a paste as plain text. It does burn a burn-after-read paste,
// since that is how such a paste is read from a terminal.
func (s *Server) raw(w http.ResponseWriter, r *http.Request) {
	p, content, ok := s.load(w, r, true)
	if !ok {
		return
	}
	if p.BurnAfterRead && !s.burn(w, r, p, true) {
		return
	}
	noStore(w)
	w.Header().Set("Content-Security-Policy", "sandbox; default-src 'none'")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write(content)
}

func (s *Server) viewPage(p *store.Paste, content []byte, burned bool) page {
	pg := s.page("Paste")
	pg.ID, pg.Content, pg.Burned = p.ID, string(content), burned
	pg.RawURL, pg.Created, pg.Expires = "/raw/"+p.ID, p.CreatedAt, p.ExpiresAt
	return pg
}

// load fetches and decrypts the paste named in the path, writing the error
// response itself when it fails.
func (s *Server) load(w http.ResponseWriter, r *http.Request, plain bool) (*store.Paste, []byte, bool) {
	id := r.PathValue("id")
	if !ids.Valid(id) {
		s.notFound(w, plain)
		return nil, nil, false
	}
	p, err := s.Pastes.Paste(r.Context(), id, s.Now())
	if errors.Is(err, store.ErrNotFound) {
		s.notFound(w, plain)
		return nil, nil, false
	}
	if err != nil {
		s.serverError(w, r, plain, "reading paste", err)
		return nil, nil, false
	}
	content, err := s.Ring.Open(p.KeyID, p.ID, p.Nonce, p.Ciphertext)
	if err != nil {
		s.serverError(w, r, plain, "decrypting paste", err)
		return nil, nil, false
	}
	return p, content, true
}

// burn deletes a burn-after-read paste. Only the request whose delete removed
// the row may show it, so two readers racing cannot both see it.
func (s *Server) burn(w http.ResponseWriter, r *http.Request, p *store.Paste, plain bool) bool {
	deleted, err := s.Pastes.DeletePaste(r.Context(), p.ID)
	if err != nil {
		s.serverError(w, r, plain, "burning paste", err)
		return false
	}
	if !deleted {
		s.notFound(w, plain)
	}
	return deleted
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.Pastes.Ping(ctx); err != nil {
		s.Log.WarnContext(ctx, "readiness check failed", "err", err)
		http.Error(w, "rqlite unavailable", http.StatusServiceUnavailable)
		return
	}
	_, _ = io.WriteString(w, "ok\n")
}

const notFoundMsg = "This paste does not exist. It may have expired or already been read."

func (s *Server) notFound(w http.ResponseWriter, plain bool) {
	if plain {
		s.text(w, http.StatusNotFound, notFoundMsg)
		return
	}
	s.message(w, http.StatusNotFound, "Not found", notFoundMsg)
}

func (s *Server) serverError(w http.ResponseWriter, r *http.Request, plain bool, what string, err error) {
	s.Log.ErrorContext(r.Context(), what, "err", err)
	const msg = "Something went wrong. Try again shortly."
	if plain {
		s.text(w, http.StatusInternalServerError, msg)
		return
	}
	s.message(w, http.StatusInternalServerError, "Error", msg)
}

func (s *Server) message(w http.ResponseWriter, status int, title, msg string) {
	p := s.page(title)
	p.Message = msg
	s.render(w, status, "message", p)
}

func (s *Server) text(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg+"\n")
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data page) {
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		s.Log.Error("rendering template", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func (s *Server) clientIP(r *http.Request) string {
	if s.TrustProxy {
		if ip := r.Header.Get("X-Real-Ip"); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
