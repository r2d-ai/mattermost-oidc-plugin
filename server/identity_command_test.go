package main

import (
	"errors"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityCommandAuthority(t *testing.T) {
	p, a, _ := fixtureIdentity(t)
	for _, u := range []*model.User{nil, {Id: model.NewId(), Roles: "system_user"}, {Id: model.NewId(), Roles: "system_admin", DeleteAt: 1}, {Id: model.NewId(), Roles: "system_admin", IsBot: true}, {Id: model.NewId(), Roles: "system_admin"}} {
		id := ""
		if u != nil {
			id = u.Id
			a.users[id] = u
		}
		r, e := p.ExecuteCommand(nil, &model.CommandArgs{UserId: id, Command: "/oidc-identity status"})
		require.Nil(t, e)
		require.Equal(t, model.CommandResponseTypeEphemeral, r.ResponseType)
		if u == nil || u.DeleteAt != 0 || u.IsBot || !u.IsSystemAdmin() {
			require.Contains(t, r.Text, "authority_denied")
		} else {
			require.Contains(t, r.Text, "active")
		}
	}
}
func TestIdentityCommandStrictGrammar(t *testing.T) {
	p, a, _ := fixtureIdentity(t)
	u := &model.User{Id: model.NewId(), Roles: "system_admin"}
	a.users[u.Id] = u
	for _, cmd := range []string{"/oidc-identity status extra", "/oidc-identity freeze extra", "/oidc-identity apply /tmp/map", "/oidc-identity status --actor admin", "/other status"} {
		r, e := p.ExecuteCommand(nil, &model.CommandArgs{UserId: u.Id, Command: cmd})
		require.Nil(t, e)
		require.Contains(t, r.Text, "invalid_command")
	}
}
func TestApprovedMapFileBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "map.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0444))
	b, e := readRegularApprovalFile(path)
	require.NoError(t, e)
	require.Equal(t, "{}", string(b))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(path, link))
	_, e = readRegularApprovalFile(link)
	require.Error(t, e)
	_, e = readRegularApprovalFile(dir)
	require.Error(t, e)
	large := filepath.Join(dir, "large")
	require.NoError(t, os.WriteFile(large, make([]byte, maxApprovalBytes+1), 0444))
	_, e = readRegularApprovalFile(large)
	require.Error(t, e)
	writable := filepath.Join(dir, "writable")
	require.NoError(t, os.WriteFile(writable, []byte("{}"), 0600))
	_, e = readRegularApprovalFile(writable)
	require.Error(t, e)
}
func TestIdentityCommandReportsApprovedRowCount(t *testing.T) {
	p, a, m := legacyMap(t)
	b, h := mapBytes(t, m)
	reads := 0
	p.readApprovalFile = func() ([]byte, error) { reads++; return b, nil }
	actor := &model.User{Id: model.NewId(), Roles: "system_admin"}
	a.users[actor.Id] = actor
	reply, e := p.ExecuteCommand(nil, &model.CommandArgs{UserId: actor.Id, Command: "/oidc-identity apply " + h})
	require.Nil(t, e)
	require.Contains(t, reply.Text, "rows=1")
	require.Equal(t, 1, reads)
}

func TestIdentityCommandOutcomeDoesNotExposeUnknownErrors(t *testing.T) {
	require.Equal(t, "identity_unavailable", identityCommandOutcome(errors.New("secret detail")))
	require.Equal(t, "identity_conflict", identityCommandOutcome(ErrIdentityConflict))
}
