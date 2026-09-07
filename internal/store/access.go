package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AccessState is the current database-backed authorization state at the
// protected action boundary. It closes the notification window during which a
// second replica can still hold a snapshot from before a revocation.
type AccessState string

const (
	AccessAllowed        AccessState = "allowed"
	AccessUnknown        AccessState = "unknown"
	AccessRevoked        AccessState = "revoked"
	AccessGraceExpired   AccessState = "grace_expired"
	AccessTenantDisabled AccessState = "tenant_disabled"
)

// CurrentAccess checks only mutable lifecycle state. Secret verification and
// scopes stay on the immutable snapshot path; this query makes a committed key
// revocation or tenant disable bind on the next protected action even before a
// replica has processed LISTEN/NOTIFY.
//
// An empty keyID represents an OIDC credential, whose mutable authorization is
// the tenant's enabled state.
func (s *Store) CurrentAccess(ctx context.Context, tenantID, keyID string, now time.Time) (AccessState, error) {
	if keyID == "" {
		var enabled bool
		err := s.Pool.QueryRow(ctx, `SELECT enabled FROM tenants WHERE id = $1`, tenantID).Scan(&enabled)
		if errors.Is(err, pgx.ErrNoRows) {
			return AccessUnknown, nil
		}
		if err != nil {
			return "", fmt.Errorf("checking current tenant access: %w", err)
		}
		if !enabled {
			return AccessTenantDisabled, nil
		}
		return AccessAllowed, nil
	}

	var (
		status     KeyStatus
		graceUntil *time.Time
		enabled    bool
	)
	err := s.Pool.QueryRow(ctx, `
		SELECT k.status, k.grace_until, t.enabled
		  FROM api_keys k
		  JOIN tenants t ON t.id = k.tenant_id
		 WHERE k.id = $1 AND k.tenant_id = $2`, keyID, tenantID).Scan(&status, &graceUntil, &enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessUnknown, nil
	}
	if err != nil {
		return "", fmt.Errorf("checking current key access: %w", err)
	}
	if !enabled {
		return AccessTenantDisabled, nil
	}
	switch status {
	case KeyActive:
		return AccessAllowed, nil
	case KeyGrace:
		if graceUntil != nil && !now.After(*graceUntil) {
			return AccessAllowed, nil
		}
		return AccessGraceExpired, nil
	default:
		return AccessRevoked, nil
	}
}
