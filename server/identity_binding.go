package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/mattermost/mattermost/server/public/model"
)

const identityPairPrefix = "identity_v1_pair_"
const identityUserPrefix = "identity_v1_user_"

type IdentityBinding struct{ Issuer, Subject, MattermostUserID string }
type NativeAuthMode string

const (
	LegacyRaw   NativeAuthMode = "legacy_raw"
	QualifiedV2 NativeAuthMode = "qualified_v2"
)

type VerifiedLoginIdentity struct{ Issuer, Subject string }
type ResolvedIdentity struct {
	Binding                               IdentityBinding
	BindingRevision                       uint64
	GateEpoch                             uint64
	IdentityFingerprint                   string
	NativeAuthMode                        NativeAuthMode
	ExpectedAuthService, ExpectedAuthData string
}
type identityRecord struct {
	Version         int             `json:"version"`
	Binding         IdentityBinding `json:"binding"`
	Revision        uint64          `json:"revision"`
	TransactionID   string          `json:"transaction_id"`
	State           string          `json:"state"`
	Mode            NativeAuthMode  `json:"native_auth_mode"`
	AuthService     string          `json:"auth_service"`
	AuthData        string          `json:"auth_data"`
	Username        string          `json:"username,omitempty"`
	DefaultTeam     string          `json:"default_team,omitempty"`
	CreateAttempted bool            `json:"create_attempted,omitempty"`
}

func pairDigest(issuer, subject string) string {
	return digestJSON([]string{"mm-oidc-pair-v1", issuer, subject})
}
func pairKey(b IdentityBinding) string { return identityPairPrefix + pairDigest(b.Issuer, b.Subject) }
func (p *Plugin) readIdentityRecord(key string) (identityRecord, []byte, error) {
	b, e := p.API.KVGet(key)
	if e != nil {
		return identityRecord{}, nil, ErrIdentityUnavailable
	}
	var r identityRecord
	if len(b) == 0 {
		return r, nil, ErrIdentityUnproven
	}
	if json.Unmarshal(b, &r) != nil || r.Version != 1 || r.Revision == 0 || r.TransactionID == "" || r.Binding.Issuer == "" || r.Binding.Subject == "" || (r.State != "pending" && r.State != "committed") {
		return r, b, ErrIdentityConflict
	}
	return r, b, nil
}
func validNative(u *model.User, r identityRecord) bool {
	return u != nil && model.IsValidId(u.Id) && u.Id == r.Binding.MattermostUserID && u.DeleteAt == 0 && !u.IsBot && u.AuthService == r.AuthService && u.AuthData != nil && *u.AuthData == r.AuthData && r.AuthService == AuthService && ((r.Mode == LegacyRaw && r.AuthData == r.Binding.Subject) || (r.Mode == QualifiedV2 && r.AuthData == "v2:"+pairDigest(r.Binding.Issuer, r.Binding.Subject)))
}
func (p *Plugin) committedIdentity(b IdentityBinding) (identityRecord, *model.User, error) {
	r, _, e := p.readIdentityRecord(pairKey(b))
	if e != nil {
		return r, nil, e
	}
	if r.Binding != b || r.State != "committed" {
		return r, nil, ErrIdentityConflict
	}
	reverse, _, e := p.readIdentityRecord(identityUserPrefix + b.MattermostUserID)
	if e != nil {
		return r, nil, e
	}
	if reverse != r {
		return r, nil, ErrIdentityConflict
	}
	u, ae := p.API.GetUser(b.MattermostUserID)
	if ae != nil {
		return r, nil, ErrIdentityUnavailable
	}
	if !validNative(u, r) {
		return r, nil, ErrIdentityConflict
	}
	return r, u, nil
}
func resolved(r identityRecord, g identityGate) ResolvedIdentity {
	return ResolvedIdentity{r.Binding, r.Revision, g.Epoch, g.IdentityFingerprint, r.Mode, r.AuthService, r.AuthData}
}
func (p *Plugin) AssertCurrentBinding(ctx context.Context, b ResolvedIdentity) error {
	if e := ctx.Err(); e != nil {
		return ErrIdentityUnavailable
	}
	if e := p.requireIdentityGate(b.IdentityFingerprint, b.GateEpoch); e != nil {
		return e
	}
	if b.Binding.Issuer != configuredIssuer(p.getConfiguration()) {
		return ErrIdentityConflict
	}
	r, _, e := p.committedIdentity(b.Binding)
	if e != nil {
		return e
	}
	if r.Revision != b.BindingRevision || r.Mode != b.NativeAuthMode || r.AuthService != b.ExpectedAuthService || r.AuthData != b.ExpectedAuthData {
		return ErrIdentityConflict
	}
	return p.requireIdentityGate(b.IdentityFingerprint, b.GateEpoch)
}
func (p *Plugin) ResolveBrokerBinding(ctx context.Context, id string) (ResolvedIdentity, error) {
	if !model.IsValidId(id) {
		return ResolvedIdentity{}, ErrIdentityUnproven
	}
	g, e := p.observeIdentityGate(p.getConfiguration())
	if e != nil {
		return ResolvedIdentity{}, e
	}
	if e = p.requireIdentityGate(g.IdentityFingerprint, g.Epoch); e != nil {
		return ResolvedIdentity{}, e
	}
	r, _, e := p.readIdentityRecord(identityUserPrefix + id)
	if e != nil {
		return ResolvedIdentity{}, e
	}
	if r.Binding.MattermostUserID != id || r.Binding.Issuer != g.Issuer {
		return ResolvedIdentity{}, ErrIdentityConflict
	}
	r, _, e = p.committedIdentity(r.Binding)
	if e != nil {
		return ResolvedIdentity{}, e
	}
	b := resolved(r, g)
	return b, p.AssertCurrentBinding(ctx, b)
}

// finishIdentity commits reverse first. Neither partial state authorizes a login.
func (p *Plugin) finishIdentity(r identityRecord) error {
	if !model.IsValidId(r.Binding.MattermostUserID) {
		return ErrIdentityConflict
	}
	for i := 0; i < 32; i++ {
		current, old, e := p.readIdentityRecord(pairKey(r.Binding))
		if e != nil {
			return e
		}
		if current.TransactionID != r.TransactionID || current.Binding.Issuer != r.Binding.Issuer || current.Binding.Subject != r.Binding.Subject || (current.Binding.MattermostUserID != "" && current.Binding.MattermostUserID != r.Binding.MattermostUserID) {
			return ErrIdentityConflict
		}
		if current.State == "committed" {
			_, _, e = p.committedIdentity(r.Binding)
			return e
		}
		u, ae := p.API.GetUser(r.Binding.MattermostUserID)
		if ae != nil {
			return ErrIdentityUnavailable
		}
		if !validNative(u, r) {
			return ErrIdentityConflict
		}
		done := r
		done.State = "committed"
		reverse, rb, re := p.readIdentityRecord(identityUserPrefix + r.Binding.MattermostUserID)
		if re != nil && re != ErrIdentityUnproven {
			return re
		}
		if re == nil && reverse != done {
			return ErrIdentityConflict
		}
		if re == ErrIdentityUnproven {
			ok, e := p.casIdentity(identityUserPrefix+r.Binding.MattermostUserID, rb, done)
			if e != nil {
				return e
			}
			if !ok {
				continue
			}
		}
		ok, e := p.casIdentity(pairKey(r.Binding), old, done)
		if e != nil {
			return e
		}
		if ok {
			return nil
		}
	}
	return ErrIdentityUnavailable
}
func (p *Plugin) resolveVerifiedLogin(ctx context.Context, s *LoginSnapshot, id VerifiedLoginIdentity, profile *OIDCUserInfo) (ResolvedIdentity, *model.User, error) {
	var empty ResolvedIdentity
	if s == nil || profile == nil || id.Issuer == "" || id.Subject == "" || id.Issuer != configuredIssuer(&s.configuration) || profile.Subject != id.Subject {
		return empty, nil, ErrIdentityConflict
	}
	if e := p.assertLoginSnapshot(ctx, s); e != nil {
		return empty, nil, e
	}
	b := IdentityBinding{Issuer: id.Issuer, Subject: id.Subject}
	for attempt := 0; attempt < 32; attempt++ {
		r, raw, e := p.readIdentityRecord(pairKey(b))
		if e == ErrIdentityUnproven {
			// Legacy entries are collision evidence only, never ownership authority.
			legacy, ae := p.API.KVGet(KVOIDCUserPrefix + id.Subject)
			if ae != nil {
				return empty, nil, ErrIdentityUnavailable
			}
			if len(legacy) > 0 {
				return empty, nil, ErrIdentityUnproven
			}
			if !s.configuration.AutoCreateAccounts {
				return empty, nil, ErrIdentityUnproven
			}
			existing, ae := p.API.GetUserByEmail(profile.Email)
			if ae == nil || existing != nil {
				return empty, nil, ErrIdentityConflict
			}
			if ae.StatusCode != http.StatusNotFound {
				return empty, nil, ErrIdentityUnavailable
			}
			name := sanitizeUsername(profile.Username)
			if name == "" {
				return empty, nil, ErrIdentityConflict
			}
			existing, ae = p.API.GetUserByUsername(name)
			if ae == nil && existing != nil {
				suffix, se := generateRandomKey(3)
				if se != nil {
					return empty, nil, ErrIdentityUnavailable
				}
				if len(name) > 55 {
					name = name[:55]
				}
				name += "_" + suffix
			} else if ae != nil && ae.StatusCode != http.StatusNotFound {
				return empty, nil, ErrIdentityUnavailable
			}
			tx, se := generateRandomKey(16)
			if se != nil {
				return empty, nil, ErrIdentityUnavailable
			}
			r = identityRecord{Version: 1, Binding: b, Revision: 1, TransactionID: tx, State: "pending", Mode: QualifiedV2, AuthService: AuthService, AuthData: "v2:" + pairDigest(id.Issuer, id.Subject), Username: name, DefaultTeam: s.configuration.DefaultTeam}
			_, e := p.casIdentity(pairKey(b), nil, r)
			if e != nil {
				return empty, nil, e
			}
			continue
		}
		if e != nil {
			return empty, nil, e
		}
		if r.Binding.Issuer != id.Issuer || r.Binding.Subject != id.Subject {
			return empty, nil, ErrIdentityConflict
		}
		if r.State == "committed" {
			rr, u, e := p.committedIdentity(r.Binding)
			if e != nil {
				return empty, nil, e
			}
			out := ResolvedIdentity{rr.Binding, rr.Revision, s.GateEpoch, s.IdentityFingerprint, rr.Mode, rr.AuthService, rr.AuthData}
			if e = p.AssertCurrentBinding(ctx, out); e != nil {
				return empty, nil, e
			}
			return out, u, nil
		}
		if r.Mode != QualifiedV2 || r.Username == "" {
			return empty, nil, ErrIdentityUnproven
		}
		u, ae := p.API.GetUserByUsername(r.Username)
		if ae != nil && ae.StatusCode != http.StatusNotFound {
			return empty, nil, ErrIdentityUnavailable
		}
		if u == nil {
			if r.CreateAttempted {
				return empty, nil, ErrIdentityConflict
			}
			r.CreateAttempted = true
			ok, e := p.casIdentity(pairKey(b), raw, r)
			if e != nil {
				return empty, nil, e
			}
			if !ok {
				continue
			}
			if e = p.assertLoginSnapshot(ctx, s); e != nil {
				return empty, nil, e
			}
			u, ae = p.API.CreateUser(&model.User{Username: r.Username, Email: profile.Email, FirstName: profile.FirstName, LastName: profile.LastName, Position: profile.Position, AuthService: r.AuthService, AuthData: model.NewPointer(r.AuthData), EmailVerified: profile.EmailVerified == nil || *profile.EmailVerified})
			if ae != nil || u == nil {
				return empty, nil, ErrIdentityUnavailable
			}
		}
		r.Binding.MattermostUserID = u.Id
		if !validNative(u, r) {
			return empty, nil, ErrIdentityConflict
		}
		if e = p.assertLoginSnapshot(ctx, s); e != nil {
			return empty, nil, e
		}
		if r.DefaultTeam != "" {
			team, ae := p.API.GetTeamByName(r.DefaultTeam)
			if ae != nil || team == nil {
				return empty, nil, ErrIdentityUnavailable
			}
			member, ae := p.API.GetTeamMember(team.Id, u.Id)
			if ae != nil && ae.StatusCode != http.StatusNotFound {
				return empty, nil, ErrIdentityUnavailable
			}
			if member == nil || member.DeleteAt != 0 {
				if _, ae = p.API.CreateTeamMember(team.Id, u.Id); ae != nil {
					return empty, nil, ErrIdentityUnavailable
				}
			}
		}
		if e = p.finishIdentity(r); e != nil {
			return empty, nil, e
		}
	}
	return empty, nil, ErrIdentityUnavailable
}
