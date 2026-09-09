package secops

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"
)

// defaultReplayCapacity bounds the recent-seen set.
//
// Bounded because the key is a token id, which is chosen by whoever mints the
// tokens: an unbounded map here would let a stream of distinct tokens decide
// how much memory this process holds, which is the same mistake the JWKS
// cache and the metrics labels are already written to avoid. 4096 entries is
// a few hundred kilobytes and covers far more concurrent tokens than a
// gateway in front of one shared provider credential has callers.
const defaultReplayCapacity = 4096

// ReplayFilter records which peer first presented a token id, so a second
// peer presenting the same id can be reported.
//
// What it is not: a block list. It has no reject path, no eviction of a
// caller, and no notion of a bad actor. Whether a replayed token is refused
// is decided entirely by RFC 8705 certificate binding in internal/jwt, which
// already existed; a token the issuer did not bind is admitted here exactly
// as it was before this file existed. The filter's whole contribution is that
// the admission is no longer silent.
//
// Memory is bounded and nothing is persisted: on a restart the process has
// seen no tokens, which is honest about what an in-memory detector can know.
type ReplayFilter struct {
	mu       sync.Mutex
	capacity int
	seen     map[string]sighting
	// order is insertion order, for eviction. A ring rather than an LRU
	// because recency of use is not the interesting axis: a token id is
	// interesting until it expires, and then never again.
	order []string
}

type sighting struct {
	peer      string
	expiresAt time.Time
}

func NewReplayFilter(capacity int) *ReplayFilter {
	if capacity <= 0 {
		capacity = defaultReplayCapacity
	}
	return &ReplayFilter{
		capacity: capacity,
		seen:     make(map[string]sighting, capacity),
		order:    make([]string, 0, capacity),
	}
}

// TokenID is the identity a replay is tracked under: the jti when the issuer
// set one, and the hash of the raw token when it did not.
//
// Hashing rather than storing the token: this map is in the same process as
// the gateway's own credentials, and a structure holding live bearer tokens
// in plaintext is a secret store nobody would think to treat as one.
func TokenID(jti, raw string) string {
	if jti != "" {
		return "jti:" + jti
	}
	sum := sha256.Sum256([]byte(raw))
	return "tok:" + base64.RawURLEncoding.EncodeToString(sum[:16])
}

// replaySighting is the verdict of one presentation.
type replaySighting struct {
	replayed  bool
	firstPeer string
}

// note records a presentation and reports whether it was a replay from a
// different peer.
func (f *ReplayFilter) note(tokenID, peer string, expiresAt, now time.Time) replaySighting {
	f.mu.Lock()
	defer f.mu.Unlock()

	prior, ok := f.seen[tokenID]
	if ok && now.Before(prior.expiresAt) {
		if prior.peer != peer {
			// Deliberately not overwritten: the first peer is the one worth
			// keeping, because it is the answer to "who was this token
			// issued to" when a third peer shows up later.
			return replaySighting{replayed: true, firstPeer: prior.peer}
		}
		return replaySighting{}
	}
	f.insert(tokenID, sighting{peer: peer, expiresAt: expiresAt})
	return replaySighting{}
}

// insert adds a sighting, evicting the oldest entry when full. Caller holds
// the lock.
func (f *ReplayFilter) insert(tokenID string, s sighting) {
	if _, exists := f.seen[tokenID]; !exists {
		if len(f.order) >= f.capacity {
			oldest := f.order[0]
			f.order = f.order[1:]
			delete(f.seen, oldest)
		}
		f.order = append(f.order, tokenID)
	}
	f.seen[tokenID] = s
}

// Len reports how many token ids are currently tracked, for the harness and
// for tests asserting the bound holds.
func (f *ReplayFilter) Len() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seen)
}

// PeerIdentity is what the transport can say about who presented a
// credential: the client certificate when there is one, and the peer address
// otherwise.
//
// Two different things on purpose, and the caller labels which. A certificate
// thumbprint is proof of key possession; an address is a hint that a NAT can
// erase. A detector that treated them as the same kind of evidence would
// report a replay every time a legitimate client changed networks.
func PeerIdentity(certThumbprint, remoteHost string) string {
	if certThumbprint != "" {
		return "cert:" + certThumbprint
	}
	if remoteHost == "" {
		return "unknown"
	}
	return "ip:" + remoteHost
}

// NoteTokenUse records that a verified token was presented, and emits
// token_replay when the same token id has already been presented by someone
// else inside its own lifetime.
//
// Called only for tokens that VERIFIED. A token whose signature did not check
// out has an attacker-chosen jti, and recording that would let anyone poison
// the filter with an id they then blame on a real caller.
func (r *Recorder) NoteTokenUse(ctx context.Context, tokenID, peer string, expiresAt time.Time, boundToCert bool) {
	if r == nil || r.replay == nil {
		return
	}
	s := r.replay.note(tokenID, peer, expiresAt, r.now())
	if !s.replayed {
		return
	}
	// Outcome follows the existing control, and says so. A bound token that
	// reached here passed certificate binding, so the replay came from a peer
	// holding the right key; an unbound one was admitted because the issuer
	// never constrained it.
	//
	// No wall-clock detail in the evidence: the timeline is compared byte for
	// byte across two runs to prove the replay is deterministic, and a
	// timestamp inside an evidence value would make every run differ. The
	// pointer back to the original presentation is first_seen_peer, which is
	// what an operator greps the timeline for anyway.
	r.Emit(ctx, Event{
		Type:    EventTokenReplay,
		Control: ControlTokenReplayFilter,
		Outcome: OutcomeAllowed,
		Evidence: map[string]string{
			"token_id":          tokenID,
			"peer":              peer,
			"first_seen_peer":   s.firstPeer,
			"certificate_bound": boolText(boundToCert),
			"refused":           boolText(false),
		},
	})
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
