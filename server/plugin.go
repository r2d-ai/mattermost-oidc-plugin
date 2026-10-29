package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"golang.org/x/oauth2"
)

const (
	// PluginID is the unique identifier for this plugin.
	PluginID = "mattermost-oidc"

	// AuthService is the service name stored in the user's AuthService field.
	AuthService = "oidc"

	// KVOAuthStatePrefix is the KV store key prefix for OAuth state tokens.
	KVOAuthStatePrefix = "oidc_state_"
)

// kvEncryptionKey is the KV store key under which the HMAC signing key is persisted.
const kvEncryptionKey = "_plugin_encryption_key"

// discoveryRetryInterval limits how often unauthenticated login requests can make the plugin contact the issuer.
const discoveryRetryInterval = 10 * time.Second

// Plugin implements the Mattermost plugin interface.
type Plugin struct {
	plugin.MattermostPlugin

	// configurationLock synchronizes access to the configuration.
	configurationLock sync.RWMutex

	// configuration is the active plugin configuration.
	configuration         *Configuration
	configurationRevision uint64
	// discoveryAttempt orders every discovery entry point, including overlapping
	// lifecycle and login-retry calls with the same configuration revision.
	discoveryAttempt uint64
	loginSnapshot    *LoginSnapshot
	readApprovalFile func() ([]byte, error)

	// encryptionKey is the HMAC key used to sign OAuth state tokens.
	// Loaded from the KV store on activation; never exposed via config or UI.
	encryptionKey string

	// oidcProvider is the cached OIDC provider from discovery.
	oidcProvider *oidc.Provider

	// oauth2Config is the cached OAuth2 configuration.
	oauth2Config *oauth2.Config

	// oidcVerifier is the ID token verifier.
	oidcVerifier *oidc.IDTokenVerifier

	// retryLock allows one login-time discovery retry at a time.
	retryLock sync.Mutex

	// lastDiscoveryRetry is when a login request last retried discovery, guarded by retryLock.
	lastDiscoveryRetry time.Time

	// discoveryClient overrides the HTTP client used for OIDC discovery when set (currently only used by tests).
	discoveryClient *http.Client

	// router handles HTTP requests for this plugin.
	router *mux.Router
	broker brokerLimits
}

// OnActivate is called when the plugin is activated.
func (p *Plugin) OnActivate() error {
	if err := p.initializeStateKey(); err != nil {
		return err
	}

	p.initRouter()
	if err := p.registerIdentityCommand(); err != nil {
		return err
	}

	cfg := p.getConfiguration()
	_, _ = p.observeIdentityGate(cfg)
	if cfg.Enable {
		if err := cfg.IsValid(); err != nil {
			p.API.LogWarn("OIDC plugin configuration is incomplete", "error", err.Error())
			return nil // Don't fail activation, just log the issue
		}
		if p.getOAuthConfig() == nil {
			if err := p.initOIDCProvider(); err != nil {
				p.API.LogWarn("Failed to initialize OIDC provider", "error", err.Error())
			}
		}
	}

	p.API.LogInfo("Mattermost / Mostlymatter OIDC plugin activated")
	return nil
}

// OnDeactivate is called when the plugin is deactivated.
func (p *Plugin) OnDeactivate() error {
	p.clearOIDCProvider()
	p.API.LogInfo("Mattermost / Mostlymatter OIDC plugin deactivated")
	return nil
}

// OnConfigurationChange is called when the configuration changes.
func (p *Plugin) OnConfigurationChange() error {
	var configuration Configuration
	if err := p.API.LoadPluginConfiguration(&configuration); err != nil {
		return fmt.Errorf("failed to load plugin configuration: %w", err)
	}

	p.configurationLock.RLock()
	var (
		unchanged        = p.configuration != nil && *p.configuration == configuration
		onlyCaptureFlags = p.configuration != nil && sameLoginConfiguration(p.configuration, &configuration)
		hasProvider      = p.oauth2Config != nil
	)
	p.configurationLock.RUnlock()
	if unchanged && hasProvider {
		return nil // if settings did not change and the provider is already running, skip re-discovery.
	}
	if onlyCaptureFlags && hasProvider {
		p.setConfiguration(&configuration)
		return nil
	}

	p.setConfiguration(&configuration)
	_, _ = p.observeIdentityGate(&configuration)
	p.clearOIDCProvider() // clear old config to prevent stale, outdated config in case the newly saved one is invalid

	if configuration.Enable {
		if err := configuration.IsValid(); err != nil {
			p.API.LogWarn("OIDC configuration invalid", "error", err.Error())
			return nil
		}
		if err := p.initOIDCProvider(); err != nil {
			p.API.LogError("Failed to re-initialize OIDC provider", "error", err.Error())
		}
	}

	return nil
}

// getConfiguration retrieves the active configuration.
func (p *Plugin) getConfiguration() *Configuration {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()

	if p.configuration == nil {
		return &Configuration{}
	}
	return p.configuration.Clone()
}

// setConfiguration replaces the active configuration.
func (p *Plugin) setConfiguration(configuration *Configuration) {
	p.configurationLock.Lock()
	defer p.configurationLock.Unlock()

	// Capture switches are live policy, not part of the verified login snapshot.
	// Preserve B0's full equality check for every other configuration field.
	if p.configuration != nil && p.loginSnapshot != nil && sameLoginConfiguration(p.configuration, configuration) {
		snapshot := *p.loginSnapshot
		snapshot.configuration = *configuration.Clone()
		p.loginSnapshot = &snapshot
	}
	p.configuration = configuration.Clone()
	p.configurationRevision++
}

func sameLoginConfiguration(a, b *Configuration) bool {
	left, right := *a, *b
	left.EnableTokenPersistence, right.EnableTokenPersistence = false, false
	left.EnablePlaneBroker, right.EnablePlaneBroker = false, false
	return left == right
}

// clearOIDCProvider resets the cached provider, OAuth2 configuration, and verifier.
func (p *Plugin) clearOIDCProvider() {
	p.configurationLock.Lock()
	defer p.configurationLock.Unlock()

	p.loginSnapshot = nil
	p.oidcProvider = nil
	p.oauth2Config = nil
	p.oidcVerifier = nil
}

// initOIDCProvider discovers and initializes the OIDC provider, OAuth2 config, and verifier.
func (p *Plugin) initOIDCProvider() error {
	p.configurationLock.Lock()
	config := p.configuration.Clone()
	revision := p.configurationRevision
	key := p.encryptionKey
	p.discoveryAttempt++
	attempt := p.discoveryAttempt
	p.configurationLock.Unlock()
	if key == "" {
		return nil
	} // OnConfigurationChange may precede activation.
	if err := config.IsValid(); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if p.discoveryClient != nil {
		ctx = oidc.ClientContext(ctx, p.discoveryClient)
	}

	// oidc.NewProvider expects the issuer URL and appends /.well-known/openid-configuration itself -> strip the suffix if the user accidentally included it.
	// Note that this will potentially result in a URL mismatch if the provider sends its URL with a trailing slash, see https://github.com/coreos/go-oidc/issues/442.
	issuer := strings.TrimSuffix(config.IssuerURL, "/.well-known/openid-configuration")

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return fmt.Errorf("failed to discover OIDC provider at %s: %w", issuer, err)
	}

	mmConfig := p.API.GetConfig()
	if mmConfig == nil {
		return fmt.Errorf("failed to get Mattermost config")
	}
	siteURL := mmConfig.ServiceSettings.SiteURL
	if siteURL == nil || *siteURL == "" {
		return fmt.Errorf("SiteURL is not configured in Mattermost")
	}

	redirectURL := fmt.Sprintf("%s/plugins/%s/oauth2/callback", *siteURL, PluginID)

	oauthConfig := &oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       config.GetScopes(),
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: config.ClientID,
	})

	p.configurationLock.Lock()
	// A newer discovery attempt fences this result even at the same configuration
	// revision. Slow lifecycle discovery must not overwrite a newer login retry.
	stale := p.discoveryAttempt != attempt || p.configuration == nil || p.configurationRevision != revision || p.encryptionKey != key || *p.configuration != *config
	if !stale {
		p.oidcProvider = provider
		p.oauth2Config = oauthConfig
		p.oidcVerifier = verifier
		p.loginSnapshot = makeLoginSnapshot(config, provider, verifier, oauthConfig, key)
	}
	p.configurationLock.Unlock()
	if stale {
		return ErrCallbackConfigurationChanged
	}

	p.API.LogInfo("OIDC provider initialized successfully",
		"issuer_url", config.IssuerURL,
		"redirect_url", redirectURL,
		"pkce", "S256",
	)
	return nil
}

// retryOIDCProvider re-runs failed discovery for a login request, at most once per discoveryRetryInterval.
func (p *Plugin) retryOIDCProvider() {
	if !p.retryLock.TryLock() {
		return
	}
	defer p.retryLock.Unlock()
	if p.getOAuthConfig() != nil || time.Since(p.lastDiscoveryRetry) < discoveryRetryInterval {
		return
	}
	if err := p.initOIDCProvider(); err != nil {
		p.API.LogWarn("Failed to initialize OIDC provider on login", "error", err.Error())
	}
	p.lastDiscoveryRetry = time.Now()
}

// ServeHTTP routes incoming HTTP requests to the plugin's router.
func (p *Plugin) ServeHTTP(c *plugin.Context, w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == brokerLocalPath {
		p.handlePlaneBroker(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/internal/") {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/api/v1/plane/disconnect" || r.URL.Path == "/api/v1/plane/revoke" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p.handleCredentialManagement(c, w, r, r.URL.Path == "/api/v1/plane/revoke")
		return
	}
	p.router.ServeHTTP(w, r)
}

// initRouter sets up HTTP routes for the plugin.
func (p *Plugin) initRouter() {
	p.router = mux.NewRouter()

	// OAuth2 endpoints
	p.router.HandleFunc("/oauth2/connect", p.handleOAuth2Connect).Methods(http.MethodGet)
	p.router.HandleFunc("/oauth2/callback", p.handleOAuth2Callback).Methods(http.MethodGet)

	// API endpoints
	p.router.HandleFunc("/api/v1/config", p.handleGetPublicConfig).Methods(http.MethodGet)
}

// getEncryptionKey returns the HMAC signing key cached from the KV store.
func (p *Plugin) getEncryptionKey() string {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()
	return p.encryptionKey
}

// generateRandomKey generates a random hex-encoded key of the given byte length.
func generateRandomKey(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// getSiteURL returns the configured SiteURL or an empty string.
func (p *Plugin) getSiteURL() string {
	siteURL := p.API.GetConfig().ServiceSettings.SiteURL
	if siteURL == nil {
		return ""
	}
	return *siteURL
}

// getOAuthConfig safely retrieves the current OAuth2 config.
func (p *Plugin) getOAuthConfig() *oauth2.Config {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()
	return p.oauth2Config
}

// getOIDCVerifier safely retrieves the current OIDC ID token verifier.
func (p *Plugin) getOIDCVerifier() *oidc.IDTokenVerifier {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()
	return p.oidcVerifier
}

// getOIDCProvider safely retrieves the current OIDC provider.
func (p *Plugin) getOIDCProvider() *oidc.Provider {
	p.configurationLock.RLock()
	defer p.configurationLock.RUnlock()
	return p.oidcProvider
}

// Only management routes require this ordinary session + explicit CSRF guard.
// The Context/header pair is trusted only behind Mattermost's plugin dispatcher.
func (p *Plugin) managementActor(c *plugin.Context, r *http.Request) (*model.User, error) {
	id := r.Header.Get("Mattermost-User-Id")
	if c == nil || !model.IsValidId(c.SessionId) || !model.IsValidId(id) {
		return nil, ErrIdentityMismatch
	}
	session, ae := p.API.GetSession(c.SessionId)
	if ae != nil || session == nil || session.Id != c.SessionId || session.UserId != id || session.IsExpired() || session.IsIntegration() {
		return nil, ErrIdentityMismatch
	}
	csrf := r.Header.Get(model.HeaderCsrfToken)
	if csrf == "" || session.GetCSRF() == "" || subtle.ConstantTimeCompare([]byte(csrf), []byte(session.GetCSRF())) != 1 {
		return nil, ErrIdentityMismatch
	}
	user, ae := p.API.GetUser(id)
	if ae != nil || user == nil || user.Id != id || user.DeleteAt != 0 || user.IsBot {
		return nil, ErrIdentityMismatch
	}
	return user, nil
}
func (p *Plugin) handleCredentialManagement(c *plugin.Context, w http.ResponseWriter, r *http.Request, admin bool) {
	actor, e := p.managementActor(c, r)
	if e != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id := actor.Id
	if admin {
		// Roles come from a fresh server GetUser, never from session/request claims.
		if !actor.IsSystemAdmin() {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		var target struct {
			UserID string `json:"user_id"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&target) != nil || decoder.Decode(new(any)) != io.EOF || !model.IsValidId(target.UserID) {
			http.Error(w, "invalid target", http.StatusBadRequest)
			return
		}
		id = target.UserID
	}
	b, e := p.cleanupBinding(id)
	if e != nil {
		http.Error(w, "identity unavailable", http.StatusConflict)
		return
	}
	if e = newTokenLifecycle(p).Disconnect(r.Context(), b); e != nil {
		http.Error(w, "credential invalidation unavailable", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Core invokes this asynchronously and does not guarantee durable delivery.
// Broker use must independently reread the user even after successful cleanup.
func (p *Plugin) UserHasBeenDeactivated(_ *plugin.Context, user *model.User) {
	if user == nil {
		return
	}
	b, e := p.cleanupBinding(user.Id)
	if e != nil {
		p.API.LogWarn("Delegated credential deactivation binding unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), refreshBudget)
	defer cancel()
	if e = newCredentialStore(p).Invalidate(ctx, b); e != nil {
		p.API.LogWarn("Delegated credential deactivation invalidation unavailable")
	}
}
