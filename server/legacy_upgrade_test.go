package main

import (
	"bytes"
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"github.com/stretchr/testify/require"
)

func legacyUpgradeFixture(t *testing.T) (*Plugin, *identityAPI, *plugin.Context, *model.User) {
	t.Helper()
	p, a, _ := fixtureIdentity(t)
	delete(a.kv, identityGateKey)
	admin := &model.User{Id: model.NewId(), Roles: "system_admin"}
	a.users[admin.Id] = admin
	session := &model.Session{Id: model.NewId(), UserId: admin.Id, ExpiresAt: time.Now().Add(time.Hour).UnixMilli()}
	p.SetAPI(&lifecycleSessionAPI{a, session})
	u := &model.User{Id: model.NewId(), Username: "legacy", Email: "test@example.com", AuthService: "oidc", AuthData: model.NewPointer("s")}
	a.users[u.Id] = u
	a.kv[KVOIDCUserPrefix+"s"] = []byte(u.Id)
	return p, a, &plugin.Context{SessionId: session.Id}, admin
}

func approveLegacyTest(t *testing.T, p *Plugin, pc *plugin.Context, admin *model.User) *LoginSnapshot {
	t.Helper()
	r, ae := p.ExecuteCommand(pc, &model.CommandArgs{UserId: admin.Id, Command: "/oidc-identity approve-legacy https://a.example"})
	require.Nil(t, ae)
	require.Contains(t, r.Text, "outcome=ok")
	require.Contains(t, r.Text, "gate=active")
	s, err := p.currentLoginSnapshot(context.Background())
	require.NoError(t, err)
	return s
}

func TestLegacyUpgradeExplicitApprovalAndIdempotency(t *testing.T) {
	p, _, pc, admin := legacyUpgradeFixture(t)
	s := approveLegacyTest(t, p, pc, admin)
	require.Equal(t, uint64(1), s.GateEpoch)
	again := approveLegacyTest(t, p, pc, admin)
	require.Equal(t, s.GateEpoch, again.GateEpoch)
}

func TestLegacyUpgradeApprovalRequiresCurrentAdminSession(t *testing.T) {
	for _, mode := range []string{"no_context", "other_session_user", "expired", "integration", "local", "not_admin", "deleted", "bot"} {
		t.Run(mode, func(t *testing.T) {
			p, a, pc, admin := legacyUpgradeFixture(t)
			sessionAPI := p.API.(*lifecycleSessionAPI)
			switch mode {
			case "no_context":
				pc = nil
			case "other_session_user":
				sessionAPI.session.UserId = model.NewId()
			case "expired":
				sessionAPI.session.ExpiresAt = 1
			case "integration":
				sessionAPI.session.IsOAuth = true
			case "local":
				sessionAPI.session.Local = true
			case "not_admin":
				admin.Roles = "system_user"
			case "deleted":
				admin.DeleteAt = 1
			case "bot":
				admin.IsBot = true
			}
			r, ae := p.ExecuteCommand(pc, &model.CommandArgs{UserId: admin.Id, Command: "/oidc-identity approve-legacy https://a.example"})
			require.Nil(t, ae)
			require.Contains(t, r.Text, "authority_denied")
			require.Empty(t, a.kv[identityGateKey])
		})
	}
}

func TestLegacyUpgradeDoesNotApproveWrongIssuerOrExistingRegistry(t *testing.T) {
	for _, mode := range []string{"wrong_issuer", "frozen", "existing_pair", "existing_user", "partial_gate"} {
		t.Run(mode, func(t *testing.T) {
			p, a, pc, admin := legacyUpgradeFixture(t)
			issuer := "https://a.example"
			switch mode {
			case "wrong_issuer":
				issuer = "https://b.example"
			case "frozen":
				_, err := p.freezeIdentityGate()
				require.NoError(t, err)
			case "existing_pair":
				a.kv[identityPairPrefix+"partial"] = []byte(`{}`)
			case "existing_user":
				a.kv[identityUserPrefix+model.NewId()] = []byte(`{}`)
			case "partial_gate":
				a.kv[identityGateKey] = []byte(`{"version":1,"status":"uninitialized","epoch":0,"issuer":"https://a.example"}`)
			}
			before := string(a.kv[identityGateKey])
			r, ae := p.ExecuteCommand(pc, &model.CommandArgs{UserId: admin.Id, Command: "/oidc-identity approve-legacy " + issuer})
			require.Nil(t, ae)
			require.NotContains(t, r.Text, "outcome=ok")
			require.Equal(t, before, string(a.kv[identityGateKey]))
		})
	}
}

func TestLegacyUpgradeFreshLoginPreservesExistingUser(t *testing.T) {
	p, a, pc, admin := legacyUpgradeFixture(t)
	wantID := string(a.kv[KVOIDCUserPrefix+"s"])
	s := approveLegacyTest(t, p, pc, admin)
	resolved, u, err := resolveTest(p, s)
	require.NoError(t, err)
	require.Equal(t, wantID, u.Id)
	require.Equal(t, LegacyRaw, resolved.NativeAuthMode)
	require.Equal(t, "oidc", u.AuthService)
	require.Equal(t, "s", *u.AuthData)
	require.Zero(t, a.creates+a.updates+a.sessions+a.joins)
	require.NoError(t, p.AssertCurrentBinding(context.Background(), resolved))
	_, again, err := resolveTest(p, s)
	require.NoError(t, err)
	require.Equal(t, wantID, again.Id)
}

func TestLegacyUpgradeRejectsMismatchedNativeIdentity(t *testing.T) {
	for _, mode := range []string{"wrong_auth", "wrong_subject", "deleted", "bot", "invalid_uuid", "missing_user"} {
		t.Run(mode, func(t *testing.T) {
			p, a, pc, admin := legacyUpgradeFixture(t)
			s := approveLegacyTest(t, p, pc, admin)
			id := string(a.kv[KVOIDCUserPrefix+"s"])
			u := a.users[id]
			switch mode {
			case "wrong_auth":
				u.AuthService = ""
			case "wrong_subject":
				u.AuthData = model.NewPointer("other")
			case "deleted":
				u.DeleteAt = 1
			case "bot":
				u.IsBot = true
			case "invalid_uuid":
				a.kv[KVOIDCUserPrefix+"s"] = []byte("invalid")
			case "missing_user":
				delete(a.users, id)
			}
			_, _, err := resolveTest(p, s)
			require.Error(t, err)
			require.Zero(t, a.creates+a.updates+a.sessions+a.joins)
			require.Empty(t, a.kv[pairKey(IdentityBinding{"https://a.example", "s", id})])
		})
	}
}

func TestLegacyUpgradePartialCommitResumes(t *testing.T) {
	p, a, pc, admin := legacyUpgradeFixture(t)
	s := approveLegacyTest(t, p, pc, admin)
	id := string(a.kv[KVOIDCUserPrefix+"s"])
	a.failKey = identityUserPrefix
	_, _, err := resolveTest(p, s)
	require.Error(t, err)
	_, err = p.ResolveBrokerBinding(context.Background(), id)
	require.Error(t, err)
	a.failKey = ""
	_, u, err := resolveTest(p, s)
	require.NoError(t, err)
	require.Equal(t, id, u.Id)
	require.Zero(t, a.creates+a.updates+a.sessions+a.joins)
}

func TestLegacyUpgradeConcurrentFreshLogins(t *testing.T) {
	p, a, pc, admin := legacyUpgradeFixture(t)
	s := approveLegacyTest(t, p, pc, admin)
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); _, _, err := resolveTest(p, s); errors <- err }()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	require.Zero(t, a.creates+a.updates+a.sessions+a.joins)
}

func TestLegacyUpgradeFreezeClearsApprovalAndCannotReapprove(t *testing.T) {
	p, a, pc, admin := legacyUpgradeFixture(t)
	approveLegacyTest(t, p, pc, admin)
	_, err := p.freezeIdentityGate()
	require.NoError(t, err)
	var stored map[string]any
	require.NoError(t, json.Unmarshal(a.kv[identityGateKey], &stored))
	require.Nil(t, stored["legacy_upgrade"])
	r, ae := p.ExecuteCommand(pc, &model.CommandArgs{UserId: admin.Id, Command: "/oidc-identity approve-legacy https://a.example"})
	require.Nil(t, ae)
	require.Contains(t, r.Text, "identity_gate_closed")
}

func TestLegacyUpgradeLostCommitAcknowledgementResumes(t *testing.T) {
	p, a, pc, admin := legacyUpgradeFixture(t)
	s := approveLegacyTest(t, p, pc, admin)
	id := string(a.kv[KVOIDCUserPrefix+"s"])
	pair := pairKey(IdentityBinding{"https://a.example", "s", id})
	lost := false
	a.beforeCAS = func(key string, _, next []byte) *model.AppError {
		var record identityRecord
		if key != pair || json.Unmarshal(next, &record) != nil || record.State != "committed" || lost {
			return nil
		}
		lost = true
		a.mu.Lock()
		a.kv[key] = bytes.Clone(next)
		a.mu.Unlock()
		return failAPI()
	}
	_, _, err := resolveTest(p, s)
	require.Error(t, err, "lost response must not report login success")
	require.True(t, lost)
	var reverse identityRecord
	require.NoError(t, json.Unmarshal(a.kv[identityUserPrefix+id], &reverse))
	require.Equal(t, "committed", reverse.State)
	_, u, err := resolveTest(p, s)
	require.NoError(t, err)
	require.Equal(t, id, u.Id)
	require.Zero(t, a.creates+a.updates+a.sessions+a.joins)
}

func TestLegacyUpgradeCannotClaimForeignReverseRecord(t *testing.T) {
	p, a, pc, admin := legacyUpgradeFixture(t)
	s := approveLegacyTest(t, p, pc, admin)
	id := string(a.kv[KVOIDCUserPrefix+"s"])
	foreign := identityRecord{Version: 1, Binding: IdentityBinding{"https://a.example", "other-subject", id}, Revision: 1, TransactionID: "foreign", State: "committed", Mode: LegacyRaw, AuthService: AuthService, AuthData: "other-subject"}
	reverseKey := identityUserPrefix + id
	a.kv[reverseKey], _ = json.Marshal(foreign)
	before := bytes.Clone(a.kv[reverseKey])
	_, _, err := resolveTest(p, s)
	require.ErrorIs(t, err, ErrIdentityConflict)
	require.Equal(t, before, a.kv[reverseKey])
	require.Zero(t, a.creates+a.updates+a.sessions+a.joins)
}

func TestLegacyUpgradeAuthorityChangeDuringWritesDeniesLogin(t *testing.T) {
	for _, target := range []string{"candidate", "reverse"} {
		for _, change := range []string{"freeze", "client"} {
			t.Run(target+"/"+change, func(t *testing.T) {
				p, a, pc, admin := legacyUpgradeFixture(t)
				s := approveLegacyTest(t, p, pc, admin)
				id := string(a.kv[KVOIDCUserPrefix+"s"])
				key := pairKey(IdentityBinding{"https://a.example", "s", id})
				if target == "reverse" {
					key = identityUserPrefix + id
				}
				changed := false
				a.beforeCAS = func(k string, _, _ []byte) *model.AppError {
					if k != key || changed {
						return nil
					}
					changed = true
					if change == "freeze" {
						_, err := p.freezeIdentityGate()
						require.NoError(t, err)
					} else {
						cfg := p.getConfiguration()
						cfg.ClientID = "changed-client"
						p.setConfiguration(cfg)
					}
					return nil
				}
				_, _, err := resolveTest(p, s)
				require.Error(t, err)
				require.True(t, changed)
				_, err = p.ResolveBrokerBinding(context.Background(), id)
				require.Error(t, err)
				gate, _, err := p.readIdentityGate()
				require.NoError(t, err)
				require.Equal(t, "frozen", gate.Status)
				require.Zero(t, a.creates+a.updates+a.sessions+a.joins)
			})
		}
	}
}
