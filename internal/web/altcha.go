package web

import (
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"

	"github.com/altcha-org/altcha-lib-go"
)

// verifier issues ALTCHA proof-of-work challenges for the paste form and
// checks the answers. The browser widget (static/altcha) finds the number
// whose SHA-256 with the challenge's salt matches; that costs it CPU time, and
// this costs us one HMAC per check.
//
// A challenge is valid until it expires and may be answered once. Answers
// seen are remembered in memory, so with several replicas one answer could be
// used once on each.
type verifier struct {
	key       string
	maxNumber int64
	ttl       time.Duration

	mu   sync.Mutex
	used map[string]time.Time // answered challenge signature -> its expiry
}

func newVerifier(key string, maxNumber int64, ttl time.Duration) *verifier {
	return &verifier{key: key, maxNumber: maxNumber, ttl: ttl, used: map[string]time.Time{}}
}

// challenge returns a new challenge. Its expiry is part of the signed salt.
func (v *verifier) challenge(now time.Time) (altcha.Challenge, error) {
	expires := now.Add(v.ttl)
	return altcha.CreateChallenge(altcha.ChallengeOptions{
		Algorithm: altcha.SHA256,
		MaxNumber: v.maxNumber,
		HMACKey:   v.key,
		Expires:   &expires,
	})
}

// verify reports whether payload, the base64 JSON the widget puts in the
// form, answers an unexpired challenge of ours that has not been used before.
func (v *verifier) verify(payload string, now time.Time) bool {
	if payload == "" {
		return false
	}
	ok, err := altcha.VerifySolutionSafe(payload, v.key, true)
	if err != nil || !ok {
		return false
	}
	// The library recomputes the challenge with whatever algorithm the
	// payload names; only accept the one we issue.
	var p altcha.Payload
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil || json.Unmarshal(raw, &p) != nil || p.Algorithm != string(altcha.SHA256) {
		return false
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	for sig, exp := range v.used {
		if now.After(exp) {
			delete(v.used, sig)
		}
	}
	if _, seen := v.used[p.Signature]; seen {
		return false
	}
	// Remember it for at least as long as the challenge can be valid.
	v.used[p.Signature] = now.Add(v.ttl)
	return true
}
