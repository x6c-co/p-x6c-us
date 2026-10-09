package web

import (
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// limiter is a token bucket per client, kept in memory. With more than one
// replica each enforces its own limit.
type limiter struct {
	mu        sync.Mutex
	every     time.Duration
	burst     int
	clients   map[string]*client
	lastPrune time.Time
}

type client struct {
	bucket *rate.Limiter
	seen   time.Time
}

func newLimiter(every time.Duration, burst int) *limiter {
	return &limiter{every: every, burst: burst, clients: map[string]*client{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastPrune) > time.Minute {
		l.prune(now)
	}
	c, ok := l.clients[key]
	if !ok {
		c = &client{bucket: rate.NewLimiter(rate.Every(l.every), l.burst)}
		l.clients[key] = c
	}
	c.seen = now
	return c.bucket.AllowN(now, 1)
}

// prune forgets clients idle long enough for their bucket to be full again,
// which is the state a forgotten client starts over in.
func (l *limiter) prune(now time.Time) {
	full := l.every * time.Duration(l.burst)
	for k, c := range l.clients {
		if now.Sub(c.seen) > full {
			delete(l.clients, k)
		}
	}
	l.lastPrune = now
}

// limitKey groups IPv6 clients by /64, since one host usually has a whole
// /64 to pick addresses from.
func limitKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}
