// Command p serves the p.x6c.us pastebin.
//
//	p             serve
//	p rotate-key  generate a new data key; replicas use it after a restart
//
// It is configured entirely from the environment; see README.md.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/x6c-co/p-x6c-us/internal/ids"
	"github.com/x6c-co/p-x6c-us/internal/keyring"
	"github.com/x6c-co/p-x6c-us/internal/rypt"
	"github.com/x6c-co/p-x6c-us/internal/store"
	"github.com/x6c-co/p-x6c-us/internal/web"
)

// version is set at build time with -ldflags "-X main.version=…".
var version = "dev"

type config struct {
	listen      string
	baseURL     string
	rqliteURL   string
	ryptURL     string
	ryptKeyID   string
	ryptToken   string
	idFormat    string
	idShortLen  int
	maxBytes    int
	trustProxy  bool
	createBurst int
	createEvery time.Duration
	altchaKey   string
	altchaMax   int
}

func loadConfig() (config, error) {
	var errs []error
	str := func(key, def string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		if def == "" {
			errs = append(errs, fmt.Errorf("%s is required", key))
		}
		return def
	}
	num := func(key string, def int) int {
		v := os.Getenv(key)
		if v == "" {
			return def
		}
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			errs = append(errs, fmt.Errorf("%s=%q is not a positive integer", key, v))
		}
		return n
	}
	dur := func(key string, def time.Duration) time.Duration {
		v := os.Getenv(key)
		if v == "" {
			return def
		}
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			errs = append(errs, fmt.Errorf("%s=%q is not a positive duration", key, v))
		}
		return d
	}
	trust, err := strconv.ParseBool(str("P_TRUST_PROXY", "false"))
	if err != nil {
		errs = append(errs, fmt.Errorf("P_TRUST_PROXY: %w", err))
	}
	c := config{
		listen:      str("P_LISTEN", ":8080"),
		baseURL:     str("P_BASE_URL", "https://p.x6c.us"),
		rqliteURL:   str("P_RQLITE_URL", "http://rqlite.rqlite.svc.cluster.local"),
		ryptURL:     str("P_RYPT_URL", "https://api.rypt.dev"),
		ryptKeyID:   str("P_RYPT_KEY_ID", ""),
		ryptToken:   str("P_RYPT_TOKEN", ""),
		idFormat:    str("P_ID_FORMAT", "uuid"),
		idShortLen:  num("P_ID_SHORT_LENGTH", 12),
		maxBytes:    num("P_MAX_PASTE_BYTES", 256<<10),
		trustProxy:  trust,
		createBurst: num("P_CREATE_BURST", 10),
		createEvery: dur("P_CREATE_EVERY", 2*time.Minute),
		altchaKey:   os.Getenv("P_ALTCHA_HMAC_KEY"), // optional: unset turns the check off
		altchaMax:   num("P_ALTCHA_MAX_NUMBER", 100_000),
	}
	return c, errors.Join(errs...)
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(log)
	case "rotate-key":
		err = rotateKey(log)
	default:
		err = fmt.Errorf("unknown command %q (want serve or rotate-key)", cmd)
	}
	if err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func serve(log *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	gen, err := ids.New(cfg.idFormat, cfg.idShortLen)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := store.Open(ctx, cfg.rqliteURL)
	if err != nil {
		return fmt.Errorf("opening rqlite: %w", err)
	}
	defer func() { _ = st.Close() }()
	ring, err := keyring.Load(ctx, st, rypt.New(cfg.ryptURL, cfg.ryptKeyID, cfg.ryptToken))
	if err != nil {
		return err
	}
	srv, err := web.New(web.Config{
		Pastes: st, Ring: ring, IDs: gen,
		BaseURL: cfg.baseURL, MaxBytes: cfg.maxBytes, TrustProxy: cfg.trustProxy,
		CreateBurst: cfg.createBurst, CreateEvery: cfg.createEvery,
		AltchaKey: cfg.altchaKey, AltchaMaxNumber: int64(cfg.altchaMax),
		Log: log,
	})
	if err != nil {
		return err
	}

	go sweep(ctx, st, log)

	hs := &http.Server{
		Addr:              cfg.listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := hs.Shutdown(shutdown); err != nil {
			log.Warn("shutting down", "err", err)
		}
	}()
	log.Info("listening", "addr", cfg.listen, "version", version, "id_format", cfg.idFormat, "data_key", ring.Active(),
		"altcha", cfg.altchaKey != "")
	if err := hs.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// sweep deletes expired pastes every minute. Reads already hide them; this
// keeps them from piling up.
func sweep(ctx context.Context, st *store.Store, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			n, err := st.Sweep(ctx, now)
			if err != nil {
				log.Warn("sweeping expired pastes", "err", err)
			} else if n > 0 {
				log.Info("swept expired pastes", "count", n)
			}
		}
	}
}

func rotateKey(log *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.rqliteURL)
	if err != nil {
		return fmt.Errorf("opening rqlite: %w", err)
	}
	defer func() { _ = st.Close() }()
	id, err := keyring.Rotate(ctx, st, rypt.New(cfg.ryptURL, cfg.ryptKeyID, cfg.ryptToken))
	if err != nil {
		return err
	}
	log.Info("added data key; restart the deployment to start using it", "data_key", id)
	return nil
}
