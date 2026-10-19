package provider

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// credentialFingerprint is a stable hash of write-only credential material.
// The raw values stay in configuration only. State stores this hash so a
// later plan can see that a credential changed. An imported resource has no
// hash, and a null hash must not by itself plan an update.
func credentialFingerprint(parts ...string) string {
	h := sha256.New()
	var buf [8]byte
	for _, p := range parts {
		binary.BigEndian.PutUint64(buf[:], uint64(len(p)))
		h.Write(buf[:])
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// nextFingerprint plans the credentials hash.
//
// creating is true only when there is no prior state. A create always records
// the hash, including the hash of empty credentials, so a later edit is visible.
// After import the stored hash is null. Write-only values are not in state, so
// a null hash is left null and the secret alone does not plan an update.
// Once a hash is recorded, a configured value that hashes differently plans
// an update. Credentials omitted from configuration (null, not empty string)
// keep the stored hash and the API keeps the stored secret.
func nextFingerprint(creating bool, prior types.String, secrets []types.String) types.String {
	vals := make([]string, len(secrets))
	for i, s := range secrets {
		if s.IsUnknown() {
			return types.StringUnknown()
		}
		if !s.IsNull() {
			vals[i] = s.ValueString()
		}
	}
	if !creating {
		if prior.IsNull() || prior.IsUnknown() || prior.ValueString() == "" {
			return types.StringNull()
		}
		allOmitted := true
		for _, s := range secrets {
			if !s.IsNull() {
				allOmitted = false
				break
			}
		}
		if allOmitted {
			return prior
		}
	}
	fp := credentialFingerprint(vals...)
	if !creating && prior.ValueString() == fp {
		return prior
	}
	return types.StringValue(fp)
}

func configuredSecret(s types.String) string {
	if s.IsNull() || s.IsUnknown() {
		return ""
	}
	return s.ValueString()
}
