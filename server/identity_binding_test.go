package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin/plugintest"
	"github.com/stretchr/testify/require"
)

type identityAPI struct {
	member   bool
	loseJoin bool
	*plugintest.API
	mu                                sync.Mutex
	kv                                map[string][]byte
	users                             map[string]*model.User
	creates, updates, sessions, joins int
	readFail, loseCreate              bool
	failKey                           string
}

func newIdentityAPI() *identityAPI {
	return &identityAPI{API: &plugintest.API{}, kv: map[string][]byte{}, users: map[string]*model.User{}}
}
func failAPI() *model.AppError   { return model.NewAppError("test", "unavailable", nil, "", 503) }
func absentAPI() *model.AppError { return model.NewAppError("test", "missing", nil, "", 404) }
func (a *identityAPI) KVGet(k string) ([]byte, *model.AppError) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.readFail {
		return nil, failAPI()
	}
	return bytes.Clone(a.kv[k]), nil
}
func (a *identityAPI) KVCompareAndSet(k string, old, next []byte) (bool, *model.AppError) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failKey != "" && strings.HasPrefix(k, a.failKey) {
		return false, failAPI()
	}
	if !bytes.Equal(a.kv[k], old) {
		return false, nil
	}
	a.kv[k] = bytes.Clone(next)
	return true, nil
}
func (a *identityAPI) KVCompareAndDelete(k string, old []byte) (bool, *model.AppError) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !bytes.Equal(a.kv[k], old) {
		return false, nil
	}
	delete(a.kv, k)
	return true, nil
}
func (a *identityAPI) KVSetWithExpiry(k string, b []byte, _ int64) *model.AppError {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.kv[k] = bytes.Clone(b)
	return nil
}
func (a *identityAPI) KVList(page, size int) ([]string, *model.AppError) {
	a.mu.Lock()
	defer a.mu.Unlock()
	keys := []string{}
	for k := range a.kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	start := page * size
	if start >= len(keys) {
		return nil, nil
	}
	end := start + size
	if end > len(keys) {
		end = len(keys)
	}
	return keys[start:end], nil
}
func copyUser(u *model.User) *model.User {
	if u == nil {
		return nil
	}
	v := *u
	if u.AuthData != nil {
		v.AuthData = model.NewPointer(*u.AuthData)
	}
	return &v
}
func (a *identityAPI) GetUser(id string) (*model.User, *model.AppError) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if u := a.users[id]; u != nil {
		return copyUser(u), nil
	}
	return nil, absentAPI()
}
func (a *identityAPI) GetUserByUsername(name string) (*model.User, *model.AppError) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, u := range a.users {
		if u.Username == name {
			return copyUser(u), nil
		}
	}
	return nil, absentAPI()
}
func (a *identityAPI) GetUserByEmail(email string) (*model.User, *model.AppError) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, u := range a.users {
		if u.Email == email {
			return copyUser(u), nil
		}
	}
	return nil, absentAPI()
}
func (a *identityAPI) CreateUser(u *model.User) (*model.User, *model.AppError) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, v := range a.users {
		if v.Username == u.Username || v.Email == u.Email {
			return nil, failAPI()
		}
	}
	a.creates++
	v := copyUser(u)
	v.Id = model.NewId()
	a.users[v.Id] = v
	if a.loseCreate {
		a.loseCreate = false
		return nil, failAPI()
	}
	return copyUser(v), nil
}
func (a *identityAPI) UpdateUser(u *model.User) (*model.User, *model.AppError) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.updates++
	a.users[u.Id] = copyUser(u)
	return copyUser(u), nil
}
func (a *identityAPI) CreateSession(s *model.Session) (*model.Session, *model.AppError) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions++
	s.Token = model.NewId()
	return s, nil
}
func (a *identityAPI) GetConfig() *model.Config {
	return &model.Config{ServiceSettings: model.ServiceSettings{SiteURL: model.NewPointer("https://mm.example.com")}}
}
func (a *identityAPI) LogInfo(string, ...any)               {}
func (a *identityAPI) LogWarn(string, ...any)               {}
func (a *identityAPI) LogError(string, ...any)              {}
func (a *identityAPI) LogDebug(string, ...any)              {}
func (a *identityAPI) RegisterCommand(*model.Command) error { return nil }
func fixtureIdentity(t *testing.T) (*Plugin, *identityAPI, *LoginSnapshot) {
	t.Helper()
	a := newIdentityAPI()
	p := &Plugin{encryptionKey: "test-shared-key"}
	p.SetAPI(a)
	cfg := &Configuration{Enable: true, IssuerURL: "https://a.example", ClientID: "client", ClientSecret: "secret", AutoCreateAccounts: true}
	p.setConfiguration(cfg)
	fp := identityFingerprint(cfg.IssuerURL, cfg.ClientID)
	s := &LoginSnapshot{IdentityFingerprint: fp, GateEpoch: 2, configuration: *cfg}
	g := identityGate{Version: 1, Status: "active", Epoch: 2, Issuer: cfg.IssuerURL, ClientID: cfg.ClientID, IdentityFingerprint: fp}
	a.kv[identityGateKey], _ = json.Marshal(g)
	p.loginSnapshot = s
	return p, a, s
}
func resolveTest(p *Plugin, s *LoginSnapshot) (ResolvedIdentity, *model.User, error) {
	return p.resolveVerifiedLogin(context.Background(), s, VerifiedLoginIdentity{"https://a.example", "s"}, &OIDCUserInfo{Subject: "s", Email: "test@example.com", Username: "tester"})
}
func TestUnknownLegacyHasNoFallback(t *testing.T) {
	for _, link := range []bool{false, true} {
		p, a, s := fixtureIdentity(t)
		s.configuration.AutoLinkByEmail = link
		u := &model.User{Id: model.NewId(), Username: "legacy", Email: "test@example.com", AuthService: "oidc", AuthData: model.NewPointer("s")}
		a.users[u.Id] = u
		a.kv[KVOIDCUserPrefix+"s"] = []byte(u.Id)
		_, _, err := resolveTest(p, s)
		require.Error(t, err)
		require.Zero(t, a.creates+a.updates+a.sessions)
	}
}
func TestQualifiedNewAuthData(t *testing.T) {
	p, a, s := fixtureIdentity(t)
	r, u, err := resolveTest(p, s)
	require.NoError(t, err)
	require.Equal(t, "v2:"+pairDigest("https://a.example", "s"), *u.AuthData)
	require.Len(t, *u.AuthData, 67)
	require.NoError(t, p.AssertCurrentBinding(context.Background(), r))
	require.Equal(t, 1, a.creates)
	require.Len(t, "v2:"+pairDigest(strings.Repeat("x", 1000), strings.Repeat("s", 1000)), 67)
}
func TestNativeAccountUnchanged(t *testing.T) {
	p, a, s := fixtureIdentity(t)
	u := &model.User{Id: model.NewId(), Email: "test@example.com", Username: "native", Password: "retained"}
	a.users[u.Id] = u
	s.configuration.AutoLinkByEmail = true
	_, _, err := resolveTest(p, s)
	require.Error(t, err)
	require.Equal(t, "retained", a.users[u.Id].Password)
	require.Empty(t, u.AuthService)
	require.Zero(t, a.updates+a.creates)
}
func TestPartialRegistryNeverAuthorizes(t *testing.T) {
	p, a, s := fixtureIdentity(t)
	r, _, err := resolveTest(p, s)
	require.NoError(t, err)
	key := identityUserPrefix + r.Binding.MattermostUserID
	original := a.kv[key]
	for _, value := range [][]byte{nil, []byte(`{}`)} {
		a.kv[key] = value
		require.Error(t, p.AssertCurrentBinding(context.Background(), r))
	}
	a.kv[key] = original
	a.readFail = true
	require.ErrorIs(t, p.AssertCurrentBinding(context.Background(), r), ErrIdentityUnavailable)
}
func TestConcurrentPairResolution(t *testing.T) {
	p, a, s := fixtureIdentity(t)
	q := &Plugin{encryptionKey: "test-shared-key"}
	q.SetAPI(a)
	q.setConfiguration(p.getConfiguration())
	var wg sync.WaitGroup
	for _, node := range []*Plugin{p, q} {
		wg.Add(1)
		go func(node *Plugin) { defer wg.Done(); _, _, _ = resolveTest(node, s) }(node)
	}
	wg.Wait()
	r, u, err := resolveTest(p, s)
	require.NoError(t, err)
	require.Equal(t, 1, a.creates)
	other, err := q.ResolveBrokerBinding(context.Background(), u.Id)
	require.NoError(t, err)
	require.Equal(t, r, other)
}
func TestCreateResponseLostResumesSameUser(t *testing.T) {
	p, a, s := fixtureIdentity(t)
	a.loseCreate = true
	_, _, _ = resolveTest(p, s)
	_, u, err := resolveTest(p, s)
	require.NoError(t, err)
	require.Equal(t, 1, a.creates)
	require.NotNil(t, u)
}
func TestCreateResponseLostRenamedRefuses(t *testing.T) {
	p, a, s := fixtureIdentity(t)
	a.loseCreate = true
	_, _, _ = resolveTest(p, s)
	for _, u := range a.users {
		u.Username = "renamed"
	}
	_, _, err := resolveTest(p, s)
	require.Error(t, err)
	require.Equal(t, 1, a.creates)
}

var _ = http.StatusOK

func TestCallbackPolicyChangeBeforeCreateDenies(t *testing.T) {
	p, a, s := fixtureIdentity(t)
	cfg := p.getConfiguration()
	cfg.ClientSecret = "rotated"
	p.setConfiguration(cfg)
	_, _, e := resolveTest(p, s)
	require.Error(t, e)
	require.Zero(t, a.creates)
}

func (a *identityAPI) GetTeamByName(string) (*model.Team, *model.AppError) {
	return &model.Team{Id: "fixture-team"}, nil
}
func (a *identityAPI) GetTeamMember(team, user string) (*model.TeamMember, *model.AppError) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.member {
		return &model.TeamMember{TeamId: team, UserId: user}, nil
	}
	return nil, absentAPI()
}
func (a *identityAPI) CreateTeamMember(team, user string) (*model.TeamMember, *model.AppError) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.member {
		return nil, failAPI()
	}
	a.member = true
	a.joins++
	if a.loseJoin {
		a.loseJoin = false
		return nil, failAPI()
	}
	return &model.TeamMember{TeamId: team, UserId: user}, nil
}
func TestNewAccountTeamInitializationResumes(t *testing.T) {
	p, a, s := fixtureIdentity(t)
	cfg := p.getConfiguration()
	cfg.DefaultTeam = "team"
	p.setConfiguration(cfg)
	s.configuration = *cfg
	a.loseJoin = true
	_, _, _ = resolveTest(p, s)
	_, _, e := resolveTest(p, s)
	require.NoError(t, e)
	require.Equal(t, 1, a.creates)
	require.Equal(t, 1, a.joins)
}
func TestAssertionRejectsForeignIssuerEvenWithCurrentMetadata(t *testing.T) {
	p, a, s := fixtureIdentity(t)
	r, _, e := resolveTest(p, s)
	require.NoError(t, e)
	cfg := p.getConfiguration()
	cfg.IssuerURL = "https://b.example"
	p.setConfiguration(cfg)
	g := identityGate{Version: 1, Status: "active", Epoch: 4, Issuer: cfg.IssuerURL, ClientID: cfg.ClientID, IdentityFingerprint: identityFingerprint(cfg.IssuerURL, cfg.ClientID)}
	a.kv[identityGateKey], _ = json.Marshal(g)
	r.IdentityFingerprint = g.IdentityFingerprint
	r.GateEpoch = g.Epoch
	require.Error(t, p.AssertCurrentBinding(context.Background(), r))
}
func TestDifferentPairCannotClaimOccupiedUUID(t *testing.T) {
	p, a, m := legacyMap(t)
	b, h := mapBytes(t, m)
	p.readApprovalFile = func() ([]byte, error) { return b, nil }
	require.NoError(t, p.applyApprovalMap(h))
	uid := m.Rows[0].MattermostUserID
	original := bytes.Clone(a.kv[identityUserPrefix+uid])
	var r identityRecord
	require.NoError(t, json.Unmarshal(original, &r))
	r.Binding.Issuer = "https://b.example"
	r.TransactionID = "foreign"
	r.State = "pending"
	a.kv[pairKey(r.Binding)], _ = json.Marshal(r)
	require.ErrorIs(t, p.finishIdentity(r), ErrIdentityConflict)
	require.Equal(t, original, a.kv[identityUserPrefix+uid])
}
func TestPartialRegistryPendingAndMismatchDeny(t *testing.T) {
	for _, mutate := range []func(*identityRecord){func(r *identityRecord) { r.State = "pending" }, func(r *identityRecord) { r.TransactionID = "different" }, func(r *identityRecord) { r.Revision++ }, func(r *identityRecord) { r.Binding.Subject = "different" }} {
		p, a, s := fixtureIdentity(t)
		b, _, e := resolveTest(p, s)
		require.NoError(t, e)
		key := identityUserPrefix + b.Binding.MattermostUserID
		var r identityRecord
		require.NoError(t, json.Unmarshal(a.kv[key], &r))
		mutate(&r)
		a.kv[key], _ = json.Marshal(r)
		require.Error(t, p.AssertCurrentBinding(context.Background(), b))
		require.Zero(t, a.sessions+a.updates)
	}
}
func TestCreateResponseLostChangedNativeAuthRefuses(t *testing.T) {
	p, a, s := fixtureIdentity(t)
	a.loseCreate = true
	_, _, _ = resolveTest(p, s)
	for _, u := range a.users {
		u.AuthData = model.NewPointer("changed")
	}
	_, _, e := resolveTest(p, s)
	require.Error(t, e)
	require.Equal(t, 1, a.creates)
}
