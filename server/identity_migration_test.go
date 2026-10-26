package main

import (
	"bytes"
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

func TestIdentityApplyPartialResumeAfterReverseCommit(t *testing.T) {
	p, a, m := legacyMap(t)
	b, h := mapBytes(t, m)
	p.readApprovalFile = func() ([]byte, error) { return b, nil }
	row := m.Rows[0]
	binding := IdentityBinding{Issuer: row.Issuer, Subject: row.Subject, MattermostUserID: row.MattermostUserID}
	forwardKey, reverseKey := pairKey(binding), identityUserPrefix+row.MattermostUserID
	failedForwardWrites := 0
	a.beforeCAS = func(k string, old, next []byte) *model.AppError {
		if k != forwardKey {
			return nil
		}
		var previous, proposed identityRecord
		if json.Unmarshal(old, &previous) == nil && json.Unmarshal(next, &proposed) == nil && previous.State == "pending" && proposed.State == "committed" {
			failedForwardWrites++
			return failAPI()
		}
		return nil
	}
	require.ErrorIs(t, p.applyApprovalMap(h), ErrIdentityUnavailable)
	require.Equal(t, 1, failedForwardWrites)
	forward, forwardBytes, e := p.readIdentityRecord(forwardKey)
	require.NoError(t, e)
	reverse, reverseBytes, e := p.readIdentityRecord(reverseKey)
	require.NoError(t, e)
	require.Equal(t, "pending", forward.State)
	require.Equal(t, "committed", reverse.State)
	require.Equal(t, binding, forward.Binding)
	require.Equal(t, binding, reverse.Binding)
	require.Equal(t, importTransaction(h, 0), forward.TransactionID)
	require.Equal(t, forward.TransactionID, reverse.TransactionID)
	require.Equal(t, forward.Revision, reverse.Revision)
	expected := forward
	expected.State = "committed"
	require.Equal(t, expected, reverse)
	g, gateBefore, e := p.readIdentityGate()
	require.NoError(t, e)
	require.Equal(t, "frozen", g.Status)
	require.Equal(t, m.ExpectedGateEpoch, g.Epoch)
	require.Empty(t, g.ApprovedMapSHA256)
	require.Nil(t, g.MaintenanceReceipt)
	// The registry itself denies the partial commit, independently of the gate.
	_, _, e = p.committedIdentity(binding)
	require.ErrorIs(t, e, ErrIdentityConflict)
	require.ErrorIs(t, p.AssertCurrentBinding(context.Background(), resolved(reverse, g)), ErrIdentityGateClosed)
	_, e = p.ResolveBrokerBinding(context.Background(), row.MattermostUserID)
	require.ErrorIs(t, e, ErrIdentityGateClosed)
	require.Error(t, p.activateApprovalMap(h))
	require.Equal(t, forwardBytes, a.kv[forwardKey])
	require.Equal(t, reverseBytes, a.kv[reverseKey])
	require.Equal(t, gateBefore, a.kv[identityGateKey])
	require.Zero(t, a.creates+a.updates+a.sessions)
	// Resume exactly the original document/transaction; the occupied committed
	// reverse entry must remain byte-for-byte unchanged while forward completes.
	a.beforeCAS = nil
	require.NoError(t, p.applyApprovalMap(h))
	committed, committedBytes, e := p.readIdentityRecord(forwardKey)
	require.NoError(t, e)
	require.Equal(t, expected, committed)
	require.Equal(t, reverseBytes, a.kv[reverseKey])
	appliedGate := bytes.Clone(a.kv[identityGateKey])
	require.NoError(t, p.applyApprovalMap(h))
	require.Equal(t, committedBytes, a.kv[forwardKey])
	require.Equal(t, reverseBytes, a.kv[reverseKey])
	require.Equal(t, appliedGate, a.kv[identityGateKey])
	require.NoError(t, p.activateApprovalMap(h))
	activeGate := bytes.Clone(a.kv[identityGateKey])
	require.NoError(t, p.activateApprovalMap(h))
	require.Equal(t, activeGate, a.kv[identityGateKey])
	resolvedBinding, e := p.ResolveBrokerBinding(context.Background(), row.MattermostUserID)
	require.NoError(t, e)
	require.Equal(t, binding, resolvedBinding.Binding)
	require.Equal(t, forward.Revision, resolvedBinding.BindingRevision)
	require.NoError(t, p.AssertCurrentBinding(context.Background(), resolvedBinding))
	require.Zero(t, a.creates+a.updates+a.sessions)
}
