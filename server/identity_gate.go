package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
)

var (
	ErrIdentityUnproven             = errors.New("identity_unproven")
	ErrIdentityConflict             = errors.New("identity_conflict")
	ErrIdentityGateClosed           = errors.New("identity_gate_closed")
	ErrIdentityUnavailable          = errors.New("identity_unavailable")
	ErrCallbackConfigurationChanged = errors.New("callback_configuration_changed")
)

const identityGateKey = "identity_v1_gate"

type identityGate struct {
	Version             int                 `json:"version"`
	Status              string              `json:"status"`
	Epoch               uint64              `json:"epoch"`
	Issuer              string              `json:"issuer"`
	ClientID            string              `json:"client_id"`
	IdentityFingerprint string              `json:"identity_fingerprint"`
	ApprovedMapSHA256   string              `json:"approved_map_sha256"`
	MaintenanceReceipt  *maintenanceReceipt `json:"maintenance_receipt"`
}

// Maintenance fields are operator attestations, not remotely verified facts.
type maintenanceReceipt struct {
	ScopeSHA256             string `json:"scope_sha256"`
	AllNodesQuiesced        bool   `json:"all_nodes_quiesced"`
	AffectedSessionsRevoked bool   `json:"affected_sessions_revoked"`
	EvidenceRef             string `json:"evidence_ref"`
}

func digestJSON(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func identityFingerprint(issuer, client string) string {
	return digestJSON([]string{"mm-oidc-identity-v1", issuer, client})
}
func configuredIssuer(c *Configuration) string {
	return strings.TrimSuffix(c.IssuerURL, "/.well-known/openid-configuration")
}
func (p *Plugin) readIdentityGate() (identityGate, []byte, error) {
	b, e := p.API.KVGet(identityGateKey)
	if e != nil {
		return identityGate{}, nil, ErrIdentityUnavailable
	}
	if len(b) == 0 {
		return identityGate{Version: 1, Status: "uninitialized"}, nil, nil
	}
	var g identityGate
	if json.Unmarshal(b, &g) != nil || g.Version != 1 || (g.Status != "uninitialized" && g.Status != "frozen" && g.Status != "active") || (g.Status != "uninitialized" && g.Epoch == 0) {
		return g, nil, ErrIdentityUnavailable
	}
	return g, b, nil
}
func (p *Plugin) casIdentity(key string, old []byte, next any) (bool, error) {
	b, e := json.Marshal(next)
	if e != nil {
		return false, ErrIdentityUnavailable
	}
	ok, ae := p.API.KVCompareAndSet(key, old, b)
	if ae != nil {
		return false, ErrIdentityUnavailable
	}
	return ok, nil
}
func (p *Plugin) freezeIdentityGate() (identityGate, error) {
	for i := 0; i < 32; i++ {
		g, b, e := p.readIdentityGate()
		if e != nil {
			return g, e
		}
		if g.Status == "frozen" {
			return g, nil
		}
		if g.Epoch == math.MaxUint64 {
			return g, ErrIdentityUnavailable
		}
		g.Status = "frozen"
		g.Epoch++
		g.ApprovedMapSHA256 = ""
		g.MaintenanceReceipt = nil
		ok, e := p.casIdentity(identityGateKey, b, g)
		if e != nil {
			return g, e
		}
		if ok {
			return g, nil
		}
	}
	return identityGate{}, ErrIdentityUnavailable
}

// Observe mismatch even when login is disabled. A local mismatch always denies,
// including when persistence of the freeze fails.
func (p *Plugin) observeIdentityGate(c *Configuration) (identityGate, error) {
	g, _, e := p.readIdentityGate()
	if e != nil {
		return g, e
	}
	if g.IdentityFingerprint != "" && g.IdentityFingerprint != identityFingerprint(configuredIssuer(c), c.ClientID) {
		_, _ = p.freezeIdentityGate()
		return g, ErrIdentityGateClosed
	}
	return g, nil
}
func (p *Plugin) requireIdentityGate(fp string, epoch uint64) error {
	c := p.getConfiguration()
	g, e := p.observeIdentityGate(c)
	if e != nil {
		return e
	}
	if g.Status != "active" || g.Epoch != epoch || g.IdentityFingerprint != fp || fp != identityFingerprint(configuredIssuer(c), c.ClientID) {
		return ErrIdentityGateClosed
	}
	return nil
}
