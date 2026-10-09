package ids

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
)

func TestFormats(t *testing.T) {
	tests := []struct {
		format string
		check  func(string) error
	}{
		{"uuid", func(s string) error {
			u, err := uuid.Parse(s)
			if err == nil && u.Version() != 4 {
				t.Errorf("uuid %s is version %d, want 4", s, u.Version())
			}
			return err
		}},
		{"ulid", func(s string) error { _, err := ulid.ParseStrict(s); return err }},
		{"short", func(s string) error {
			if len(s) != 12 {
				t.Errorf("short ID %q has length %d, want 12", s, len(s))
			}
			return nil
		}},
	}
	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			g, err := New(tt.format, 12)
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for range 1000 {
				id := g.New()
				if !Valid(id) {
					t.Fatalf("%q is not Valid", id)
				}
				if err := tt.check(id); err != nil {
					t.Fatalf("%q: %v", id, err)
				}
				if seen[id] {
					t.Fatalf("duplicate ID %q", id)
				}
				seen[id] = true
			}
		})
	}
}

func TestDefaultIsUUID(t *testing.T) {
	g, err := New("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uuid.Parse(g.New()); err != nil {
		t.Fatal(err)
	}
}

func TestShortUsesWholeAlphabet(t *testing.T) {
	g, _ := New("short", 64)
	var all strings.Builder
	for range 200 {
		all.WriteString(g.New())
	}
	for _, c := range alphabet {
		if !strings.ContainsRune(all.String(), c) {
			t.Errorf("character %q never appeared in 12,800 characters", c)
		}
	}
}

func TestNewRejects(t *testing.T) {
	for _, tt := range []struct {
		format string
		n      int
	}{{"nanoid", 10}, {"short", 7}, {"short", 65}} {
		if _, err := New(tt.format, tt.n); err == nil {
			t.Errorf("New(%q, %d) succeeded, want error", tt.format, tt.n)
		}
	}
}

func TestValid(t *testing.T) {
	for _, s := range []string{"", "a/b", "../x", "a b", "a.b", strings.Repeat("a", 65), "é"} {
		if Valid(s) {
			t.Errorf("Valid(%q) = true", s)
		}
	}
}
