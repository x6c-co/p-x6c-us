// Package store keeps pastes and wrapped data keys in rqlite. Paste text is
// only ever stored as ciphertext; see package keyring.
package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	rqlite "github.com/rqlite/rqlite-go-http"
)

var (
	ErrNotFound    = errors.New("paste not found")
	ErrDuplicateID = errors.New("paste ID already exists")
)

// Paste is a stored paste. Nonce and Ciphertext are the AES-256-GCM output of
// keyring.Ring.Seal under the data key KeyID.
type Paste struct {
	ID            string
	KeyID         string
	Nonce         []byte
	Ciphertext    []byte
	CreatedAt     time.Time
	ExpiresAt     time.Time // the zero time means never
	BurnAfterRead bool
}

// DataKey is a data key in the form rypt wrapped it.
type DataKey struct {
	ID        string
	Wrapped   []byte
	CreatedAt time.Time
}

// rqlite holds a single SQLite database shared by every app on the cluster,
// so every table name here starts with "paste".
var schema = []string{
	`CREATE TABLE IF NOT EXISTS paste_data_keys (
		id         TEXT PRIMARY KEY,
		wrapped    TEXT NOT NULL,
		created_at INTEGER NOT NULL
	)`,
	`CREATE TABLE IF NOT EXISTS pastes (
		id              TEXT PRIMARY KEY,
		key_id          TEXT NOT NULL REFERENCES paste_data_keys (id),
		nonce           TEXT NOT NULL,
		ciphertext      TEXT NOT NULL,
		created_at      INTEGER NOT NULL,
		expires_at      INTEGER NOT NULL, -- 0: never expires
		burn_after_read INTEGER NOT NULL DEFAULT 0
	)`,
	`CREATE INDEX IF NOT EXISTS pastes_expires_at ON pastes (expires_at)`,
}

type Store struct {
	c *rqlite.Client
}

// Open connects to rqlite at url and creates the tables if they are missing.
func Open(ctx context.Context, url string) (*Store, error) {
	c, err := rqlite.NewClient(url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Execute(ctx, rqlite.NewSQLStatementsFromStrings(schema), &rqlite.ExecuteOptions{Transaction: true})
	if err == nil {
		err = execError(resp)
	}
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}
	return &Store{c: c}, nil
}

func (s *Store) Close() error { return s.c.Close() }

// Ping checks that rqlite answers queries.
func (s *Store) Ping(ctx context.Context) error {
	_, err := s.query(ctx, "SELECT 1")
	return err
}

func (s *Store) CreatePaste(ctx context.Context, p Paste) error {
	_, err := s.exec(ctx,
		`INSERT INTO pastes (id, key_id, nonce, ciphertext, created_at, expires_at, burn_after_read)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.KeyID, b64(p.Nonce), b64(p.Ciphertext), p.CreatedAt.Unix(), unixOrZero(p.ExpiresAt), p.BurnAfterRead)
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: pastes.id") {
		return ErrDuplicateID
	}
	return err
}

// Paste returns the paste id unless it is missing or has expired by now.
func (s *Store) Paste(ctx context.Context, id string, now time.Time) (*Paste, error) {
	rows, err := s.query(ctx,
		`SELECT key_id, nonce, ciphertext, created_at, expires_at, burn_after_read
		 FROM pastes WHERE id = ? AND (expires_at = 0 OR expires_at > ?)`, id, now.Unix())
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, ErrNotFound
	}
	r := row(rows[0])
	var expires time.Time
	if e := r.int(4); e != 0 {
		expires = time.Unix(e, 0)
	}
	p := &Paste{
		ID:            id,
		KeyID:         r.str(0),
		Nonce:         r.bytes(1),
		Ciphertext:    r.bytes(2),
		CreatedAt:     time.Unix(r.int(3), 0),
		ExpiresAt:     expires,
		BurnAfterRead: r.int(5) != 0,
	}
	return p, r.err
}

// DeletePaste deletes the paste id and reports whether this call was the one
// that deleted it. Burn-after-read relies on that to show a paste only once.
func (s *Store) DeletePaste(ctx context.Context, id string) (bool, error) {
	res, err := s.exec(ctx, `DELETE FROM pastes WHERE id = ?`, id)
	return err == nil && res.RowsAffected == 1, err
}

// Sweep deletes every paste that has expired by now and returns how many.
func (s *Store) Sweep(ctx context.Context, now time.Time) (int64, error) {
	res, err := s.exec(ctx, `DELETE FROM pastes WHERE expires_at > 0 AND expires_at <= ?`, now.Unix())
	return res.RowsAffected, err
}

// DataKeys returns every data key, oldest first.
func (s *Store) DataKeys(ctx context.Context) ([]DataKey, error) {
	rows, err := s.query(ctx, `SELECT id, wrapped, created_at FROM paste_data_keys ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	keys := make([]DataKey, 0, len(rows))
	for _, v := range rows {
		r := row(v)
		keys = append(keys, DataKey{ID: r.str(0), Wrapped: r.bytes(1), CreatedAt: time.Unix(r.int(2), 0)})
		if r.err != nil {
			return nil, r.err
		}
	}
	return keys, nil
}

func (s *Store) AddDataKey(ctx context.Context, k DataKey) error {
	_, err := s.exec(ctx, `INSERT INTO paste_data_keys (id, wrapped, created_at) VALUES (?, ?, ?)`,
		k.ID, b64(k.Wrapped), k.CreatedAt.Unix())
	return err
}

func (s *Store) exec(ctx context.Context, stmt string, args ...any) (rqlite.ExecuteResult, error) {
	resp, err := s.c.ExecuteSingle(ctx, stmt, args...)
	if err == nil {
		err = execError(resp)
	}
	if err != nil {
		return rqlite.ExecuteResult{}, err
	}
	return resp.Results[0], nil
}

func (s *Store) query(ctx context.Context, stmt string, args ...any) ([][]any, error) {
	resp, err := s.c.QuerySingle(ctx, stmt, args...)
	if err != nil {
		return nil, err
	}
	if bad, _, msg := resp.HasError(); bad {
		return nil, fmt.Errorf("rqlite: %s", msg)
	}
	results := resp.GetQueryResults()
	if len(results) != 1 {
		return nil, fmt.Errorf("rqlite: got %d results for one query", len(results))
	}
	return results[0].Values, nil
}

func execError(resp *rqlite.ExecuteResponse) error {
	if bad, _, msg := resp.HasError(); bad {
		return fmt.Errorf("rqlite: %s", msg)
	}
	return nil
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// unixOrZero stores the zero time ("never") as 0.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// row decodes one result row, keeping the first error so callers check once.
type rowDecoder struct {
	v   []any
	err error
}

func row(v []any) *rowDecoder { return &rowDecoder{v: v} }

func (r *rowDecoder) fail(i int, want string) {
	if r.err == nil {
		r.err = fmt.Errorf("rqlite: column %d is %T, want %s", i, r.v[i], want)
	}
}

func (r *rowDecoder) str(i int) string {
	s, ok := r.v[i].(string)
	if !ok {
		r.fail(i, "string")
	}
	return s
}

func (r *rowDecoder) bytes(i int) []byte {
	b, err := base64.StdEncoding.DecodeString(r.str(i))
	if err != nil && r.err == nil {
		r.err = fmt.Errorf("rqlite: column %d: %w", i, err)
	}
	return b
}

// int accepts json.Number, which is how the client decodes numbers.
func (r *rowDecoder) int(i int) int64 {
	switch n := r.v[i].(type) {
	case json.Number:
		v, err := n.Int64()
		if err != nil {
			r.fail(i, "integer")
		}
		return v
	case float64:
		return int64(n)
	}
	r.fail(i, "integer")
	return 0
}
