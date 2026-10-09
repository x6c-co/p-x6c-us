package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// open connects to the rqlite named by P_TEST_RQLITE_URL, or skips. Tests
// use random IDs and delete what they add, so they can share a database and
// run repeatedly. Their fake data keys must not outlive them: the app refuses
// to start if any stored key fails to unwrap.
func open(t *testing.T) *Store {
	t.Helper()
	url := os.Getenv("P_TEST_RQLITE_URL")
	if url == "" {
		t.Skip("P_TEST_RQLITE_URL not set")
	}
	s, err := Open(context.Background(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func addKey(t *testing.T, s *Store) DataKey {
	t.Helper()
	k := DataKey{ID: uuid.NewString(), Wrapped: []byte("wrapped-" + uuid.NewString()), CreatedAt: time.Now()}
	if err := s.AddDataKey(context.Background(), k); err != nil {
		t.Fatal(err)
	}
	cleanupKey(t, s, k.ID)
	return k
}

// cleanupKey deletes data key id, and any pastes under it, when t ends.
func cleanupKey(t *testing.T, s *Store, id string) {
	t.Cleanup(func() {
		ctx := context.Background()
		if _, err := s.exec(ctx, `DELETE FROM pastes WHERE key_id = ?`, id); err != nil {
			t.Error(err)
		}
		if _, err := s.exec(ctx, `DELETE FROM paste_data_keys WHERE id = ?`, id); err != nil {
			t.Error(err)
		}
	})
}

func TestPasteRoundTrip(t *testing.T) {
	s, ctx := open(t), context.Background()
	k := addKey(t, s)
	now := time.Unix(time.Now().Unix(), 0)
	p := Paste{
		ID: uuid.NewString(), KeyID: k.ID,
		Nonce: []byte{1, 2, 3}, Ciphertext: []byte{0, 255, 10, 13},
		CreatedAt: now, ExpiresAt: now.Add(time.Hour), BurnAfterRead: true,
	}
	if err := s.CreatePaste(ctx, p); err != nil {
		t.Fatal(err)
	}
	got, err := s.Paste(ctx, p.ID, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyID != p.KeyID || !bytes.Equal(got.Nonce, p.Nonce) || !bytes.Equal(got.Ciphertext, p.Ciphertext) ||
		!got.CreatedAt.Equal(p.CreatedAt) || !got.ExpiresAt.Equal(p.ExpiresAt) || !got.BurnAfterRead {
		t.Fatalf("got %+v, want %+v", got, p)
	}

	if err := s.CreatePaste(ctx, p); !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("second insert: %v, want ErrDuplicateID", err)
	}

	if _, err := s.Paste(ctx, p.ID, now.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read at expiry: %v, want ErrNotFound", err)
	}

	deleted, err := s.DeletePaste(ctx, p.ID)
	if err != nil || !deleted {
		t.Fatalf("first delete = %v, %v", deleted, err)
	}
	deleted, err = s.DeletePaste(ctx, p.ID)
	if err != nil || deleted {
		t.Fatalf("second delete = %v, %v; want false, nil", deleted, err)
	}
	if _, err := s.Paste(ctx, p.ID, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("read after delete: %v, want ErrNotFound", err)
	}
}

func TestUnknownKeyRejected(t *testing.T) {
	s := open(t)
	now := time.Now()
	err := s.CreatePaste(context.Background(), Paste{ID: uuid.NewString(), KeyID: "no-such-key", CreatedAt: now, ExpiresAt: now})
	if err == nil {
		t.Fatal("insert with unknown key_id succeeded; is rqlite running with -fk=true?")
	}
}

func TestSweep(t *testing.T) {
	s, ctx := open(t), context.Background()
	k := addKey(t, s)
	now := time.Now()
	old := Paste{ID: uuid.NewString(), KeyID: k.ID, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)}
	live := Paste{ID: uuid.NewString(), KeyID: k.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	for _, p := range []Paste{old, live} {
		if err := s.CreatePaste(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.Sweep(ctx, now)
	if err != nil || n < 1 {
		t.Fatalf("Sweep = %d, %v", n, err)
	}
	if deleted, _ := s.DeletePaste(ctx, old.ID); deleted {
		t.Error("expired paste survived the sweep")
	}
	if deleted, _ := s.DeletePaste(ctx, live.ID); !deleted {
		t.Error("live paste was swept")
	}
}

func TestDataKeysOrdered(t *testing.T) {
	s, ctx := open(t), context.Background()
	a := addKey(t, s)
	b := DataKey{ID: uuid.NewString(), Wrapped: []byte("b"), CreatedAt: a.CreatedAt.Add(time.Second)}
	if err := s.AddDataKey(ctx, b); err != nil {
		t.Fatal(err)
	}
	cleanupKey(t, s, b.ID)
	keys, err := s.DataKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ia, ib := -1, -1
	for i, k := range keys {
		switch k.ID {
		case a.ID:
			ia = i
			if !bytes.Equal(k.Wrapped, a.Wrapped) {
				t.Error("wrapped key changed in storage")
			}
		case b.ID:
			ib = i
		}
	}
	if ia < 0 || ib < 0 || ia > ib {
		t.Fatalf("keys at %d and %d, want both present and oldest first", ia, ib)
	}
}
