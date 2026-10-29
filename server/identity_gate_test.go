package main

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIssuerChangeFreezesAcrossNodes(t *testing.T) {
	p, a, s := fixtureIdentity(t)
	r, _, err := resolveTest(p, s)
	require.NoError(t, err)
	q := &Plugin{}
	q.SetAPI(a)
	cfg := p.getConfiguration()
	cfg.IssuerURL = "https://b.example"
	q.setConfiguration(cfg)
	require.Error(t, q.AssertCurrentBinding(context.Background(), r))
	require.Error(t, p.AssertCurrentBinding(context.Background(), r))
	g, _, err := p.readIdentityGate()
	require.NoError(t, err)
	require.Equal(t, "frozen", g.Status)
	require.Equal(t, uint64(3), g.Epoch)
}
func TestIssuerReturnDoesNotReactivate(t *testing.T) {
	p, _, s := fixtureIdentity(t)
	r, _, err := resolveTest(p, s)
	require.NoError(t, err)
	cfg := p.getConfiguration()
	cfg.ClientID = "changed"
	p.setConfiguration(cfg)
	require.Error(t, p.AssertCurrentBinding(context.Background(), r))
	cfg.ClientID = "client"
	p.setConfiguration(cfg)
	require.Error(t, p.AssertCurrentBinding(context.Background(), r))
	g, err := p.freezeIdentityGate()
	require.NoError(t, err)
	require.Equal(t, uint64(3), g.Epoch)
}
func TestMissingGateDenies(t *testing.T) {
	p, a, s := fixtureIdentity(t)
	delete(a.kv, identityGateKey)
	_, _, err := resolveTest(p, s)
	require.ErrorIs(t, err, ErrIdentityGateClosed)
	g, err := p.freezeIdentityGate()
	require.NoError(t, err)
	require.Equal(t, uint64(1), g.Epoch)
	again, err := p.freezeIdentityGate()
	require.NoError(t, err)
	require.Equal(t, g, again)
	var stored identityGate
	require.NoError(t, json.Unmarshal(a.kv[identityGateKey], &stored))
	require.Equal(t, "frozen", stored.Status)
}
