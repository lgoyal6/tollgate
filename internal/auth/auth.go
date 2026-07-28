// Package auth implements API key credentials: generation, hashed storage,
// verification with constant-time comparison, scopes, and rotation with a
// grace window.
//
// Key format: tg_<key id>_<secret>. The key id is public and indexes the
// store; the secret is 32 bytes of crypto/rand entropy. We store SHA-256 of
// the secret rather than a slow KDF like bcrypt: KDFs exist to stretch
// low-entropy human passwords, but a random 256-bit secret cannot be
// brute-forced, and a gateway hashing on every request cannot afford
// 100ms of bcrypt.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/lgoyal6/tollgate/internal/store"
)

const keyPrefix = "tg"

// Verification failures. Handlers map all of these to a single opaque 401 so
// responses do not leak whether a key id exists.
var (
	ErrMalformed      = errors.New("auth: malformed api key")
	ErrUnknownKey     = errors.New("auth: unknown key id")
	ErrBadSecret      = errors.New("auth: secret mismatch")
	ErrRevoked        = errors.New("auth: key revoked")
	ErrGraceExpired   = errors.New("auth: rotation grace window expired")
	ErrTenantDisabled = errors.New("auth: tenant disabled")
	ErrTenantUnknown  = errors.New("auth: tenant missing for key")
)

// GeneratedKey is returned once at issue time; the plaintext is never stored.
type GeneratedKey struct {
	ID         string
	Plaintext  string // full "tg_<id>_<secret>" credential
	SecretHash []byte
}

// Generate creates a new API key credential.
func Generate() (GeneratedKey, error) {
	idBytes := make([]byte, 6)
	if _, err := rand.Read(idBytes); err != nil {
		return GeneratedKey{}, fmt.Errorf("generating key id: %w", err)
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return GeneratedKey{}, fmt.Errorf("generating key secret: %w", err)
	}
	id := "k" + hex.EncodeToString(idBytes)
	secret := base64.RawURLEncoding.EncodeToString(secretBytes)
	return GeneratedKey{
		ID:         id,
		Plaintext:  keyPrefix + "_" + id + "_" + secret,
		SecretHash: HashSecret(secret),
	}, nil
}

// HashSecret is the storage transform for key secrets.
func HashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// Parse splits a presented credential into key id and secret. SplitN, not
// Split: the secret is base64url and may itself contain underscores.
func Parse(raw string) (id, secret string, err error) {
	parts := strings.SplitN(strings.TrimSpace(raw), "_", 3)
	if len(parts) != 3 || parts[0] != keyPrefix || parts[1] == "" || parts[2] == "" {
		return "", "", ErrMalformed
	}
	return parts[1], parts[2], nil
}

// Verdict is a successful verification.
type Verdict struct {
	Key    *store.APIKey
	Tenant *store.Tenant
	// Deprecated is true when the key is in its rotation grace window; the
	// gateway surfaces this via a response header so clients notice.
	Deprecated bool
}

// Verify authenticates a raw credential against the config snapshot.
func Verify(snap *store.Snapshot, raw string, now time.Time) (Verdict, error) {
	id, secret, err := Parse(raw)
	if err != nil {
		return Verdict{}, err
	}
	key, ok := snap.Key(id)
	if !ok {
		// Burn a hash anyway so unknown vs. known key ids are not
		// distinguishable by timing.
		subtle.ConstantTimeCompare(HashSecret(secret), HashSecret(secret))
		return Verdict{}, ErrUnknownKey
	}
	if subtle.ConstantTimeCompare(HashSecret(secret), key.SecretHash) != 1 {
		return Verdict{}, ErrBadSecret
	}
	switch key.Status {
	case store.KeyActive:
	case store.KeyGrace:
		if key.GraceUntil == nil || now.After(*key.GraceUntil) {
			return Verdict{}, ErrGraceExpired
		}
	default:
		return Verdict{}, ErrRevoked
	}
	tenant, ok := snap.Tenant(key.TenantID)
	if !ok {
		return Verdict{}, ErrTenantUnknown
	}
	if !tenant.Enabled {
		return Verdict{}, ErrTenantDisabled
	}
	return Verdict{Key: key, Tenant: tenant, Deprecated: key.Status == store.KeyGrace}, nil
}

// HasScope reports whether the key carries the required scope. An empty
// requirement means the route is open to any authenticated key.
func HasScope(key *store.APIKey, required string) bool {
	if required == "" {
		return true
	}
	return slices.Contains(key.Scopes, required)
}
