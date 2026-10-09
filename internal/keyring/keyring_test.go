package keyring

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/x6c-co/p-x6c-us/internal/store"
)

// fakeRypt "wraps" by storing the key in a map under a random handle and
// checks the AAD on unwrap, like rypt does.
type fakeRypt struct {
	wraps, unwraps int
	keys           map[string][2][]byte // handle -> {dek, aad}
}

func (f *fakeRypt) Wrap(_ context.Context, aad []byte) ([]byte, []byte, error) {
	f.wraps++
	if f.keys == nil {
		f.keys = map[string][2][]byte{}
	}
	dek, handle := make([]byte, 32), make([]byte, 16)
	rand.Read(dek)
	rand.Read(handle)
	f.keys[string(handle)] = [2][]byte{dek, aad}
	return dek, handle, nil
}

func (f *fakeRypt) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	f.unwraps++
	k, ok := f.keys[string(wrapped)]
	if !ok || !bytes.Equal(k[1], aad) {
		return nil, errors.New("invalid_ciphertext")
	}
	return k[0], nil
}

type memStore struct{ keys []store.DataKey }

func (m *memStore) DataKeys(context.Context) ([]store.DataKey, error) {
	return append([]store.DataKey(nil), m.keys...), nil
}

func (m *memStore) AddDataKey(_ context.Context, k store.DataKey) error {
	m.keys = append(m.keys, k)
	return nil
}

func TestFirstLoadCreatesKeyThenReusesIt(t *testing.T) {
	ctx, st, w := context.Background(), &memStore{}, &fakeRypt{}

	r1, err := Load(ctx, st, w)
	if err != nil {
		t.Fatal(err)
	}
	if w.wraps != 1 || w.unwraps != 0 || len(st.keys) != 1 {
		t.Fatalf("first load: %d wraps, %d unwraps, %d keys; want 1, 0, 1", w.wraps, w.unwraps, len(st.keys))
	}
	keyID, nonce, ct := r1.Seal("paste-1", []byte("hello"))

	// A restart unwraps the stored key and makes no new one.
	r2, err := Load(ctx, st, w)
	if err != nil {
		t.Fatal(err)
	}
	if w.wraps != 1 || w.unwraps != 1 {
		t.Fatalf("second load: %d wraps, %d unwraps; want 1, 1", w.wraps, w.unwraps)
	}
	got, err := r2.Open(keyID, "paste-1", nonce, ct)
	if err != nil || string(got) != "hello" {
		t.Fatalf("Open after restart = %q, %v", got, err)
	}
}

func TestSealBindsPasteID(t *testing.T) {
	r, err := Load(context.Background(), &memStore{}, &fakeRypt{})
	if err != nil {
		t.Fatal(err)
	}
	keyID, nonce, ct := r.Seal("a", []byte("secret"))
	if bytes.Contains(ct, []byte("secret")) {
		t.Fatal("ciphertext contains the plaintext")
	}
	if _, err := r.Open(keyID, "b", nonce, ct); err == nil {
		t.Fatal("ciphertext for paste a opened as paste b")
	}
	ct[0] ^= 1
	if _, err := r.Open(keyID, "a", nonce, ct); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
	if _, err := r.Open("other-key", "a", nonce, ct); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("unknown key: %v", err)
	}
	if _, err := r.Open(keyID, "a", nonce[:4], ct); err == nil {
		t.Fatal("short nonce accepted")
	}
}

func TestNoncesDiffer(t *testing.T) {
	r, _ := Load(context.Background(), &memStore{}, &fakeRypt{})
	_, n1, _ := r.Seal("a", []byte("x"))
	_, n2, _ := r.Seal("a", []byte("x"))
	if bytes.Equal(n1, n2) {
		t.Fatal("two seals used the same nonce")
	}
}

func TestRotate(t *testing.T) {
	ctx, st, w := context.Background(), &memStore{}, &fakeRypt{}
	r1, _ := Load(ctx, st, w)
	oldKey, nonce, ct := r1.Seal("p", []byte("before rotation"))

	newID, err := Rotate(ctx, st, w)
	if err != nil {
		t.Fatal(err)
	}
	// Rotation keys are stored with a later created_at; make the order certain.
	st.keys[1].CreatedAt = st.keys[0].CreatedAt.Add(time.Second)

	r2, err := Load(ctx, st, w)
	if err != nil {
		t.Fatal(err)
	}
	if r2.Active() != newID || r2.Active() == oldKey {
		t.Fatalf("active key %s, want the new key %s", r2.Active(), newID)
	}
	got, err := r2.Open(oldKey, "p", nonce, ct)
	if err != nil || string(got) != "before rotation" {
		t.Fatalf("old paste after rotation = %q, %v", got, err)
	}
}

func TestWrongAADFailsLoad(t *testing.T) {
	ctx, st, w := context.Background(), &memStore{}, &fakeRypt{}
	if _, err := Load(ctx, st, w); err != nil {
		t.Fatal(err)
	}
	st.keys[0].ID = "renamed" // the wrapped key no longer matches its AAD
	if _, err := Load(ctx, st, w); err == nil {
		t.Fatal("loaded a data key whose ID was changed")
	}
}
