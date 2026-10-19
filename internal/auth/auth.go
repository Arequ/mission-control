// Package auth covers bearer tokens, enroll secrets, and role checks.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// Roles are ordered. A higher role satisfies every lower requirement.
const (
	RoleViewer   = "viewer"
	RoleOperator = "operator"
	RoleAdmin    = "admin"
)

// Principal is the authenticated API caller.
type Principal struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role"`
}

// Hash returns the hex-encoded SHA-256 of a bearer token or node key.
func Hash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// SecretMatch compares two secrets without leaking the length of either.
func SecretMatch(expected, provided string) bool {
	if expected == "" {
		return false
	}
	a := sha256.Sum256([]byte(expected))
	b := sha256.Sum256([]byte(provided))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// NewSecret returns a random token with the given prefix (for example "mc_").
func NewSecret(prefix string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read random: %w", err)
	}
	return prefix + hex.EncodeToString(buf), nil
}

// ValidRole reports whether role is one the server will store.
func ValidRole(role string) bool {
	switch role {
	case RoleViewer, RoleOperator, RoleAdmin:
		return true
	default:
		return false
	}
}

// Allows reports whether have satisfies need.
func Allows(have, need string) bool {
	return rank(have) >= rank(need) && rank(need) > 0
}

func rank(role string) int {
	switch role {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	default:
		return 0
	}
}
