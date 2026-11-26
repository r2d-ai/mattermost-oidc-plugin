package main

import (
	"context"
	"strings"

	"github.com/mattermost/mattermost/server/public/model"
)

// An administrator explicitly attests which issuer owned this installation's
// legacy subject namespace. A successful fresh OIDC callback still has to prove
// the subject before any individual account is migrated.
type legacyUpgradeApproval struct {
	Issuer          string `json:"issuer"`
	ClientID        string `json:"client_id"`
	AdministratorID string `json:"administrator_id"`
}

func (p *Plugin) approveLegacyUpgrade(actorID, issuer string) error {
	actor, ae := p.API.GetUser(actorID)
	if ae != nil || actor == nil || actor.Id != actorID || actor.DeleteAt != 0 || actor.IsBot || !actor.IsSystemAdmin() {
		return ErrIdentityUnproven
	}
	cfg := p.getConfiguration()
	if issuer != configuredIssuer(cfg) || !secureEndpoint(issuer) || cfg.ClientID == "" {
		return ErrIdentityConflict
	}
	approval := legacyUpgradeApproval{issuer, cfg.ClientID, actorID}
	for range 32 {
		g, raw, err := p.readIdentityGate()
		if err != nil {
			return err
		}
		// Repeating approval is harmless, but this command cannot thaw a gate or
		// replace approval for a different issuer/client or an existing registry.
		if g.Status == "active" && g.LegacyUpgrade != nil &&
			g.LegacyUpgrade.Issuer == issuer && g.LegacyUpgrade.ClientID == cfg.ClientID &&
			g.IdentityFingerprint == identityFingerprint(issuer, cfg.ClientID) {
			return nil
		}
		if g.Status != "uninitialized" || g.Epoch != 0 || g.IdentityFingerprint != "" ||
			g.Issuer != "" || g.ClientID != "" || g.ApprovedMapSHA256 != "" ||
			g.MaintenanceReceipt != nil || g.LegacyUpgrade != nil {
			return ErrIdentityGateClosed
		}
		if err = p.requireEmptyIdentityRegistry(); err != nil {
			return err
		}
		current := p.getConfiguration()
		if *current != *cfg {
			return ErrCallbackConfigurationChanged
		}
		next := identityGate{
			Version: 1, Status: "active", Epoch: 1,
			Issuer: issuer, ClientID: cfg.ClientID,
			IdentityFingerprint: identityFingerprint(issuer, cfg.ClientID),
			LegacyUpgrade:       &approval,
		}
		ok, err := p.casIdentity(identityGateKey, raw, next)
		if err != nil {
			return err
		}
		if ok {
			_, err = p.observeIdentityGate(p.getConfiguration())
			return err
		}
	}
	return ErrIdentityUnavailable
}

func (p *Plugin) requireEmptyIdentityRegistry() error {
	for page := 0; page < 100000; page++ {
		keys, ae := p.API.KVList(page, 200)
		if ae != nil {
			return ErrIdentityUnavailable
		}
		for _, key := range keys {
			if strings.HasPrefix(key, identityPairPrefix) || strings.HasPrefix(key, identityUserPrefix) {
				return ErrIdentityConflict
			}
		}
		if len(keys) < 200 {
			return nil
		}
	}
	return ErrIdentityUnavailable
}

func (p *Plugin) approvedLegacyRecord(ctx context.Context, snapshot *LoginSnapshot, b IdentityBinding) (identityRecord, error) {
	if err := p.assertLoginSnapshot(ctx, snapshot); err != nil {
		return identityRecord{}, err
	}
	g, _, err := p.readIdentityGate()
	if err != nil {
		return identityRecord{}, err
	}
	approval := g.LegacyUpgrade
	if approval == nil || !model.IsValidId(approval.AdministratorID) ||
		approval.Issuer != b.Issuer || approval.ClientID != snapshot.configuration.ClientID ||
		g.Issuer != approval.Issuer || g.ClientID != approval.ClientID ||
		g.Status != "active" || g.Epoch != snapshot.GateEpoch ||
		g.IdentityFingerprint != snapshot.IdentityFingerprint {
		return identityRecord{}, ErrIdentityUnproven
	}
	legacy, ae := p.API.KVGet(KVOIDCUserPrefix + b.Subject)
	if ae != nil {
		return identityRecord{}, ErrIdentityUnavailable
	}
	id := string(legacy)
	if !model.IsValidId(id) {
		return identityRecord{}, ErrIdentityUnproven
	}
	if b.MattermostUserID != "" && b.MattermostUserID != id {
		return identityRecord{}, ErrIdentityConflict
	}
	b.MattermostUserID = id
	u, ae := p.API.GetUser(id)
	if ae != nil {
		return identityRecord{}, ErrIdentityUnavailable
	}
	r := identityRecord{
		Version: 1, Binding: b, Revision: 1,
		TransactionID: digestJSON([]string{"mm-oidc-legacy-upgrade-v1", b.Issuer, approval.ClientID, b.Subject, id}),
		State:         "pending", Mode: LegacyRaw, AuthService: AuthService, AuthData: b.Subject,
	}
	if !validNative(u, r) {
		return identityRecord{}, ErrIdentityConflict
	}
	if err = p.assertLoginSnapshot(ctx, snapshot); err != nil {
		return identityRecord{}, err
	}
	return r, nil
}

func (p *Plugin) finishLegacyUpgrade(ctx context.Context, snapshot *LoginSnapshot, r identityRecord) error {
	expected, err := p.approvedLegacyRecord(ctx, snapshot, r.Binding)
	if err != nil {
		return err
	}
	if r != expected {
		return ErrIdentityConflict
	}
	if err = p.finishIdentity(r); err != nil {
		return err
	}
	return p.assertLoginSnapshot(ctx, snapshot)
}
