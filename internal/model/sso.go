package model

import "time"

// SSOProvider is an OIDC issuer. ClientSecret is write-only.
type SSOProvider struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Issuer         string    `json:"issuer"`
	ClientID       string    `json:"client_id"`
	ClientSecret   string    `json:"client_secret,omitempty"`
	AllowedDomains []string  `json:"allowed_domains"`
	GroupClaim     string    `json:"group_claim"`
	Enabled        bool      `json:"enabled"`
	ManagedBy      string    `json:"managed_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// Public clears the write-only client secret.
func (p SSOProvider) Public() SSOProvider {
	p.ClientSecret = ""
	if p.AllowedDomains == nil {
		p.AllowedDomains = []string{}
	}
	return p
}

// SSOProviderPublic is the sign-in list. It has no client id or secret.
type SSOProviderPublic struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Issuer string `json:"issuer"`
}

// RoleBinding maps one IdP group to a Mission Control role.
type RoleBinding struct {
	ID         string    `json:"id"`
	ProviderID string    `json:"provider_id"`
	Group      string    `json:"group"`
	Role       string    `json:"role"`
	ManagedBy  string    `json:"managed_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// SessionUser is the signed-in browser identity. CSRFToken is not a credential
// by itself; state-changing requests must send it with the session cookie.
type SessionUser struct {
	Email     string `json:"email"`
	Name      string `json:"name"`
	Role      string `json:"role"`
	CSRFToken string `json:"csrf_token"`
}
