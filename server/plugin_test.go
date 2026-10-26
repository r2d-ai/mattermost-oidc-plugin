package main

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIdentityHooksNeverApplyOrPurge(t *testing.T) {
	a := newIdentityAPI()
	p := &Plugin{}
	p.SetAPI(a)
	p.setConfiguration(&Configuration{})
	require.NoError(t, p.OnActivate())
	_, _, e := p.readIdentityGate()
	require.NoError(t, e)
	require.Nil(t, a.kv[identityGateKey])
	require.Zero(t, a.creates+a.sessions+a.updates)
}
