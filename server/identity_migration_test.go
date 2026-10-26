package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/stretchr/testify/require"
	"testing"
)

func mapBytes(t *testing.T, m approvalMap) ([]byte, string) {
	t.Helper()
	b, e := json.Marshal(m)
	require.NoError(t, e)
	h := sha256.Sum256(b)
	return b, hex.EncodeToString(h[:])
}
func legacyMap(t *testing.T) (*Plugin, *identityAPI, approvalMap) {
	p, a, _ := fixtureIdentity(t)
	g, e := p.freezeIdentityGate()
	require.NoError(t, e)
	u := &model.User{Id: model.NewId(), Username: "legacy", Email: "legacy@example.com", AuthService: "oidc", AuthData: model.NewPointer("legacy-sub")}
	a.users[u.Id] = u
	a.kv[KVOIDCUserPrefix+"legacy-sub"] = []byte(u.Id)
	m := approvalMap{SchemaVersion: 1, Approved: true, ExpectedGateEpoch: g.Epoch, Issuer: "https://a.example", ClientID: "client", Rows: []approvalRow{{Action: "import_legacy", Approved: true, Issuer: "https://a.example", Subject: "legacy-sub", MattermostUserID: u.Id, ExpectedAuthService: "oidc", ExpectedAuthData: "legacy-sub", ExpectedLegacyMapping: u.Id, ProvenanceRef: "fixture:evidence"}}, Maintenance: maintenanceReceipt{ScopeSHA256: digestJSON([]string{u.Id}), AllNodesQuiesced: true, AffectedSessionsRevoked: true, EvidenceRef: "fixture:maintenance"}}
	return p, a, m
}
func TestApprovedLegacyPreservesNativeIdentity(t *testing.T) {
	p, a, m := legacyMap(t)
	b, h := mapBytes(t, m)
	p.readApprovalFile = func() ([]byte, error) { return b, nil }
	require.NoError(t, p.applyApprovalMap(h))
	require.NoError(t, p.activateApprovalMap(h))
	r, e := p.ResolveBrokerBinding(context.Background(), m.Rows[0].MattermostUserID)
	require.NoError(t, e)
	require.Equal(t, LegacyRaw, r.NativeAuthMode)
	require.Equal(t, "legacy-sub", r.ExpectedAuthData)
	require.Zero(t, a.updates+a.joins+a.creates)
	require.Equal(t, "oidc", a.users[r.Binding.MattermostUserID].AuthService)
}
func TestApprovedMapPreconditions(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*approvalMap)
	}{{"unapproved", func(m *approvalMap) { m.Approved = false }}, {"provenance", func(m *approvalMap) { m.Rows[0].ProvenanceRef = "" }}, {"duplicate", func(m *approvalMap) { m.Rows = append(m.Rows, m.Rows[0]) }}, {"native", func(m *approvalMap) { m.Rows[0].ExpectedAuthService = "" }}, {"epoch", func(m *approvalMap) { m.ExpectedGateEpoch-- }}, {"issuer", func(m *approvalMap) { m.Rows[0].Issuer = "https://other" }}, {"legacy", func(m *approvalMap) { m.Rows[0].ExpectedLegacyMapping = model.NewId() }}} {
		t.Run(test.name, func(t *testing.T) {
			p, a, m := legacyMap(t)
			test.change(&m)
			b, h := mapBytes(t, m)
			p.readApprovalFile = func() ([]byte, error) { return b, nil }
			before := len(a.kv)
			require.Error(t, p.applyApprovalMap(h))
			require.Len(t, a.kv, before)
		})
	}
	p, _, m := legacyMap(t)
	b, h := mapBytes(t, m)
	p.readApprovalFile = func() ([]byte, error) { return append(b, ' '), nil }
	require.Error(t, p.applyApprovalMap(h))
	for _, bad := range []string{`{"schema_version":1,"schema_version":1}`, `{"unknown":1}`, `{} {}`} {
		_, e := parseApprovalMap([]byte(bad))
		require.Error(t, e)
	}
}
func TestIdentityApplyPartialResume(t *testing.T) {
	p, a, m := legacyMap(t)
	b, h := mapBytes(t, m)
	p.readApprovalFile = func() ([]byte, error) { return b, nil }
	a.failKey = identityUserPrefix
	require.Error(t, p.applyApprovalMap(h))
	g, _, e := p.readIdentityGate()
	require.NoError(t, e)
	require.Equal(t, "frozen", g.Status)
	require.Empty(t, g.ApprovedMapSHA256)
	require.Error(t, p.activateApprovalMap(h))
	a.failKey = ""
	require.NoError(t, p.applyApprovalMap(h))
	require.NoError(t, p.applyApprovalMap(h))
	require.NoError(t, p.activateApprovalMap(h))
	u := a.users[m.Rows[0].MattermostUserID]
	u.AuthData = model.NewPointer("changed")
	require.Error(t, p.activateApprovalMap(h))
}
func TestActivationRequiresMaintenanceReceipt(t *testing.T) {
	p, _, m := legacyMap(t)
	m.Maintenance.AllNodesQuiesced = false
	b, h := mapBytes(t, m)
	p.readApprovalFile = func() ([]byte, error) { return b, nil }
	require.NoError(t, p.applyApprovalMap(h))
	require.Error(t, p.activateApprovalMap(h))
	p, _, m = legacyMap(t)
	b, h = mapBytes(t, m)
	p.readApprovalFile = func() ([]byte, error) { return b, nil }
	require.Error(t, p.activateApprovalMap(h))
	require.NoError(t, p.applyApprovalMap(h))
	require.NoError(t, p.activateApprovalMap(h))
	g, _, _ := p.readIdentityGate()
	require.NoError(t, p.activateApprovalMap(h))
	again, _, _ := p.readIdentityGate()
	require.Equal(t, g.Epoch, again.Epoch)
}
func TestApprovedMapMissingRetainAndForeignConflict(t *testing.T) {
	p, a, m := legacyMap(t)
	b, h := mapBytes(t, m)
	p.readApprovalFile = func() ([]byte, error) { return b, nil }
	require.NoError(t, p.applyApprovalMap(h))
	original := a.kv[pairKey(IdentityBinding{Issuer: m.Issuer, Subject: m.Rows[0].Subject})]
	m.Rows = []approvalRow{}
	m.Maintenance.ScopeSHA256 = digestJSON([]string{})
	b, h = mapBytes(t, m)
	require.Error(t, p.applyApprovalMap(h))
	require.Equal(t, original, a.kv[pairKey(IdentityBinding{Issuer: m.Issuer, Subject: "legacy-sub"})])
}
func TestEmptyBootstrapRequiresExplicitCommands(t *testing.T) {
	p, a, _ := fixtureIdentity(t)
	delete(a.kv, identityGateKey)
	m := approvalMap{SchemaVersion: 1, Approved: true, ExpectedGateEpoch: 1, Issuer: "https://a.example", ClientID: "client", Rows: []approvalRow{}, Maintenance: maintenanceReceipt{ScopeSHA256: digestJSON([]string{}), AllNodesQuiesced: true, EvidenceRef: "fixture:empty"}}
	b, h := mapBytes(t, m)
	p.readApprovalFile = func() ([]byte, error) { return b, nil }
	require.Error(t, p.applyApprovalMap(h))
	_, e := p.freezeIdentityGate()
	require.NoError(t, e)
	require.Error(t, p.activateApprovalMap(h))
	require.NoError(t, p.applyApprovalMap(h))
	require.NoError(t, p.activateApprovalMap(h))
	g, _, e := p.readIdentityGate()
	require.NoError(t, e)
	require.Equal(t, uint64(2), g.Epoch)
}
func TestApplyCannotApproveBrokenCommittedReverse(t *testing.T) {
	p, a, m := legacyMap(t)
	b, h := mapBytes(t, m)
	p.readApprovalFile = func() ([]byte, error) { return b, nil }
	require.NoError(t, p.applyApprovalMap(h))
	delete(a.kv, identityUserPrefix+m.Rows[0].MattermostUserID)
	require.Error(t, p.applyApprovalMap(h))
}
