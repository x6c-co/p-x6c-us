// Package ids generates paste IDs. The format is picked at startup, and IDs of
// every format stay valid, so changing it never breaks existing links.
package ids

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oklog/ulid/v2"
)

// Generator returns new paste IDs. A paste ID is the only thing protecting a
// paste, so every format here is unguessable.
type Generator interface {
	New() string
}

// valid matches every format below, with room for formats added later.
var valid = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Valid reports whether s could be a paste ID. Handlers check it before any
// database lookup.
func Valid(s string) bool { return valid.MatchString(s) }

// New returns the generator for format: "uuid" (v4, the default), "ulid" or
// "short". shortLen is the length of "short" IDs and is ignored otherwise.
func New(format string, shortLen int) (Generator, error) {
	switch strings.ToLower(format) {
	case "", "uuid":
		return uuidGen{}, nil
	case "ulid":
		return ulidGen{}, nil
	case "short":
		if shortLen < 8 || shortLen > 64 {
			return nil, fmt.Errorf("short ID length %d is outside 8-64", shortLen)
		}
		return shortGen{n: shortLen}, nil
	}
	return nil, fmt.Errorf("unknown ID format %q (want uuid, ulid or short)", format)
}

// uuidGen makes UUIDv4s: 122 random bits.
type uuidGen struct{}

func (uuidGen) New() string { return uuid.NewString() }

// ulidGen makes ULIDs: a 48-bit millisecond timestamp, which anyone holding
// the link can read, then 80 random bits. ulid.Make is not used because its
// default entropy is monotonic within a millisecond, so consecutive IDs would
// be guessable from each other.
type ulidGen struct{}

func (ulidGen) New() string {
	return ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader).String()
}

// shortGen makes base62 strings of length n, about 5.95 random bits per
// character.
type shortGen struct{ n int }

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func (g shortGen) New() string {
	out := make([]byte, 0, g.n)
	buf := make([]byte, g.n*2)
	for len(out) < g.n {
		rand.Read(buf) // never returns an error since Go 1.24
		for _, c := range buf {
			// 248 = 4*62: rejecting the top 8 values keeps every character
			// equally likely.
			if c < 248 && len(out) < g.n {
				out = append(out, alphabet[c%62])
			}
		}
	}
	return string(out)
}
