package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/mail"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/mattermost/mattermost/server/public/model"
	"golang.org/x/oauth2"
)

const (
	// stateExpiry is how long an OAuth state token is valid.
	stateExpiry = 10 * time.Minute

	// oidcStateCookie holds the OAuth state token in the browser that started the
	// flow. It is set at /oauth2/connect and required to match the state at
	// /oauth2/callback (web), binding the flow to that browser. Without it,
	// an attacker could pre-generate a valid code+state for their own IdP account and
	// feed the callback to a victim, silently logging the victim into the attacker's
	// account (login CSRF). The mobile and desktop flows are exempt (see the callback).
	oidcStateCookie = "MMOIDCSTATE"
)

// OAuthState represents the state parameter stored in KV during the OAuth flow.
type OAuthState struct {
	GateEpoch           uint64 `json:"gate_epoch"`
	IdentityFingerprint string `json:"identity_fingerprint"`
	CallbackFingerprint string `json:"callback_fingerprint"`
	Token               string `json:"token"`
	CreateAt            int64  `json:"create_at"`
	ReturnTo            string `json:"return_to"`
	// MobileRedirect, when set, is the native app's custom URL scheme callback
	// (e.g. mmauth://callback). Its presence switches the callback into mobile
	// mode: instead of setting a session cookie, the token is handed back to the
	// app via the deep link, mirroring core's /oauth/<service>/mobile_login flow.
	MobileRedirect string `json:"mobile_redirect,omitempty"`
	// DesktopChallenge is the PKCE-style challenge of the Desktop app that started a system-browser login.
	DesktopChallenge string `json:"desktop_challenge,omitempty"`
	// CodeVerifier is the PKCE S256 verifier (RFC 7636). Stored in KV, never in the URL state parameter.
	CodeVerifier string `json:"code_verifier,omitempty"`
	// Nonce is sent on the authorization request and must match the ID token
	// nonce claim after verification (OIDC Core 3.1.3.7).
	Nonce string `json:"nonce,omitempty"`
}

// allowedMobileSchemes are the exact custom-scheme callback URLs the native
// Mattermost apps register for SSO deep links (mmauth:// = production app,
// mmauthbeta:// = beta build). The native app always sends the bare callback;
// we append the token query ourselves.
var allowedMobileSchemes = []string{"mmauth://callback", "mmauthbeta://callback"}

// isAllowedMobileScheme reports whether the redirect target is one of the known
// app callback URLs. It matches the full base (optionally followed by a query)
// rather than a loose prefix, so a crafted host/path such as
// "mmauth://callback.evil.com" is rejected.
func isAllowedMobileScheme(redirect string) bool {
	for _, s := range allowedMobileSchemes {
		if redirect == s || strings.HasPrefix(redirect, s+"?") {
			return true
		}
	}
	return false
}

// OIDCUserInfo holds the user information extracted from OIDC claims.
type OIDCUserInfo struct {
	Issuer        string `json:"iss"`
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	Username      string `json:"username"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	Position      string `json:"position,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
}

// handleOAuth2Connect initiates the OIDC login flow by redirecting the user to the identity provider's authorization endpoint.
func (p *Plugin) handleOAuth2Connect(w http.ResponseWriter, r *http.Request) {
	config := p.getConfiguration()
	if !config.Enable {
		http.Error(w, "OIDC authentication is not enabled", http.StatusBadRequest)
		return
	}

	p.retryOIDCProvider()
	snapshot, err := p.currentLoginSnapshot(r.Context())
	if err != nil {
		http.Error(w, "OIDC identity unavailable", http.StatusServiceUnavailable)
		return
	}
	oauthConfig := &snapshot.oauth

	// Generate a secure state token
	stateToken, err := generateRandomKey(16)
	if err != nil {
		p.API.LogError("Failed to generate state token", "error", err.Error())
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Sign the state token with HMAC to prevent tampering
	signedState := p.signState(stateToken)

	// Store state in KV with expiry information
	returnTo := safeReturnTo(r.URL.Query().Get("return_to"))

	// Mobile login: the native app reaches this endpoint (via the front proxy
	// rewriting /oauth/openid/mobile_login) and passes its custom-scheme callback
	// as mobile_redirect. Reject anything that is not a known app scheme.
	mobileRedirect := r.URL.Query().Get("mobile_redirect")
	if mobileRedirect != "" && !isAllowedMobileScheme(mobileRedirect) {
		p.API.LogWarn("Rejected mobile_redirect with disallowed scheme", "redirect", mobileRedirect)
		mobileRedirect = ""
	}

	desktopChallenge := r.URL.Query().Get("desktop_challenge")
	if desktopChallenge != "" && (!desktopChallengeRe.MatchString(desktopChallenge) || mobileRedirect != "") {
		http.Error(w, "Invalid desktop_challenge", http.StatusBadRequest)
		return
	}

	nonce, err := generateRandomKey(16)
	if err != nil {
		p.API.LogError("Failed to generate OIDC nonce", "error", err.Error())
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	state := OAuthState{
		GateEpoch: snapshot.GateEpoch, IdentityFingerprint: snapshot.IdentityFingerprint, CallbackFingerprint: snapshot.CallbackFingerprint,
		Token:            stateToken,
		CreateAt:         time.Now().UnixMilli(),
		ReturnTo:         returnTo,
		MobileRedirect:   mobileRedirect,
		DesktopChallenge: desktopChallenge,
		Nonce:            nonce,
	}

	authOpts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOnline,
		oauth2.SetAuthURLParam("nonce", nonce),
	}
	codeVerifier := oauth2.GenerateVerifier()
	state.CodeVerifier = codeVerifier
	authOpts = append(authOpts, oauth2.S256ChallengeOption(codeVerifier))

	stateBytes, err := json.Marshal(state)
	if err != nil {
		p.API.LogError("Failed to marshal state", "error", err.Error())
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	kvKey := KVOAuthStatePrefix + stateToken
	if appErr := p.API.KVSetWithExpiry(kvKey, stateBytes, int64(stateExpiry.Seconds())); appErr != nil {
		p.API.LogError("Failed to store OAuth state", "error", appErr.Error())
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	authURL := oauthConfig.AuthCodeURL(signedState, authOpts...)

	// Desktop: the app fetches the URL and opens it in the system browser, so there is no browser cookie to bind.
	if desktopChallenge != "" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]string{"authorize_url": authURL})
		return
	}

	// Bind this flow to the initiating browser: the callback (web) requires a
	// cookie matching this state token, so a code+state pre-generated by an attacker
	// cannot be replayed into a victim's browser (login CSRF).
	p.setStateCookie(w, stateToken)
	http.Redirect(w, r, authURL, http.StatusFound)
}

var errKVGone = errors.New("not found or already consumed")

// consumeKV returns the value stored under key and deletes it atomically, so only the first of concurrent callers succeeds.
func (p *Plugin) consumeKV(key string) ([]byte, error) {
	value, appErr := p.API.KVGet(key)
	if appErr != nil || value == nil {
		return nil, errKVGone
	}
	deleted, appErr := p.API.KVCompareAndDelete(key, value)
	if appErr != nil {
		return nil, appErr
	}
	if !deleted {
		return nil, errKVGone
	}
	return value, nil
}

// handleOAuth2Callback processes the callback from the OIDC provider after
// the user has authenticated. It validates the state, exchanges the code
// for tokens, verifies the ID token, and either creates or updates the
// Mattermost user account.
func (p *Plugin) handleOAuth2Callback(w http.ResponseWriter, r *http.Request) {
	config := p.getConfiguration()
	if !config.Enable {
		http.Error(w, "OIDC authentication is not enabled", http.StatusBadRequest)
		return
	}

	// Check for errors from the OIDC provider
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		p.API.LogError("OIDC provider rejected authentication")
		p.renderError(w, "Authentication failed. Check the server logs for details.")
		return
	}

	// Validate the state parameter
	signedState := r.URL.Query().Get("state")
	stateToken, err := p.verifyAndExtractState(signedState)
	if err != nil {
		p.API.LogError("Invalid OAuth state", "error", err.Error())
		p.renderError(w, "Invalid authentication state. Please try again.")
		return
	}

	stateBytes, err := p.consumeKV(KVOAuthStatePrefix + stateToken)
	if err != nil {
		p.API.LogWarn("OAuth state rejected")
		if errors.Is(err, errKVGone) {
			p.renderError(w, "Authentication session expired. Please try again.")
		} else {
			p.renderError(w, "Internal error")
		}
		return
	}

	var state OAuthState
	if err := json.Unmarshal(stateBytes, &state); err != nil {
		p.API.LogError("Failed to unmarshal OAuth state", "error", err.Error())
		p.renderError(w, "Internal error")
		return
	}

	// Check state expiry
	if time.Since(time.UnixMilli(state.CreateAt)) > stateExpiry {
		p.renderError(w, "Authentication session expired. Please try again.")
		return
	}

	isMobile := state.MobileRedirect != ""
	isDesktop := state.DesktopChallenge != ""

	// Login-CSRF protection (web): the browser finishing the flow must be the
	// one that started it, proven by the state cookie set at connect. The mobile
	// deep-link flow is exempt — the token is handed straight to the app rather than
	// via a shared browser session, and its in-app auth session may not round-trip the
	// cookie. Reject before the token exchange to avoid needless work.
	if !isMobile && !isDesktop {
		if !stateCookieMatches(r, stateToken) {
			p.API.LogWarn("OAuth state cookie missing or mismatched — possible login CSRF")
			p.clearStateCookie(w)
			p.renderError(w, "Invalid authentication state. Please try again.")
			return
		}
		// One-shot: consume the binding cookie now that it has served its purpose.
		p.clearStateCookie(w)
	}

	// Exchange the authorization code for tokens
	code := r.URL.Query().Get("code")
	if code == "" {
		p.renderError(w, "No authorization code received")
		return
	}

	snapshot, snapshotErr := p.currentLoginSnapshot(r.Context())
	if snapshotErr != nil || snapshot.GateEpoch != state.GateEpoch || snapshot.IdentityFingerprint != state.IdentityFingerprint || snapshot.CallbackFingerprint != state.CallbackFingerprint {
		p.renderError(w, "Authentication configuration changed. Please try again.")
		return
	}
	config = &snapshot.configuration
	oauthConfig, verifier := &snapshot.oauth, snapshot.verifier

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var exchangeOpts []oauth2.AuthCodeOption
	if state.CodeVerifier != "" {
		exchangeOpts = append(exchangeOpts, oauth2.VerifierOption(state.CodeVerifier))
	}

	token, err := oauthConfig.Exchange(ctx, code, exchangeOpts...)
	tokenReceivedAt := time.Now()
	if err != nil {
		p.API.LogError("OIDC code exchange failed")
		p.renderError(w, "Failed to complete authentication. Please try again.")
		return
	}

	// Extract and verify the ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		p.API.LogError("No ID token in token response")
		p.renderError(w, "Authentication failed: no ID token received")
		return
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		p.API.LogError("OIDC token verification failed")
		p.renderError(w, "Authentication failed: invalid ID token")
		return
	}

	if !nonceMatches(state.Nonce, idToken.Nonce) {
		p.API.LogError("OIDC nonce mismatch or missing in ID token")
		p.renderError(w, "Authentication failed: invalid ID token")
		return
	}

	// Extract user claims
	userInfo, err := p.extractUserInfo(ctx, idToken, token, snapshot)
	if err != nil {
		p.API.LogError("OIDC claim extraction failed")
		p.renderError(w, "Failed to read user information from identity provider")
		return
	}

	if config.RequireEmailVerified && (userInfo.EmailVerified == nil || !*userInfo.EmailVerified) {
		p.API.LogWarn("OIDC email verification required")
		p.renderError(w, "Your email address is not verified by your identity provider.")
		return
	}

	if err := p.assertLoginSnapshot(ctx, snapshot); err != nil {
		p.renderError(w, "Authentication configuration changed. Please try again.")
		return
	}
	binding, mmUser, err := p.resolveVerifiedLogin(ctx, snapshot, VerifiedLoginIdentity{Issuer: idToken.Issuer, Subject: idToken.Subject}, userInfo)
	if err != nil {
		p.renderError(w, "Identity unavailable. Contact your administrator.")
		return
	}
	if p.assertLoginSnapshot(ctx, snapshot) != nil || p.AssertCurrentBinding(ctx, binding) != nil {
		p.renderError(w, "Identity unavailable. Contact your administrator.")
		return
	}
	mmUser, err = p.updateUserIfChanged(mmUser, userInfo)
	if err != nil {
		p.renderError(w, "Unable to update account.")
		return
	}

	credentials := &StoredCredentials{
		Binding: binding.Binding, AccessToken: token.AccessToken, RefreshToken: token.RefreshToken,
		AccessExpiresAt: token.Expiry, RefreshExpiresAt: refreshExpiry(token, tokenReceivedAt),
		GateEpoch: binding.GateEpoch, BindingRevision: binding.BindingRevision,
	}
	// Desktop creates no session in the system browser. Its app must redeem
	// the verified, expiring handoff before capture or session-cookie release.
	if isDesktop {
		p.issueDesktopCode(ctx, w, &state, snapshot, binding, credentials)
		return
	}

	session, csrfToken, err := p.createLoginSession(r.WithContext(ctx), mmUser, snapshot, binding, credentials, nil, isMobile)
	if err != nil {
		p.renderError(w, "Identity unavailable. Please try again.")
		return
	}

	// Mobile login: hand the session token back to the native app through its custom
	// URL scheme, mirroring core's /oauth/<service>/mobile_login (token + CSRF appended
	// to the deep link, delivered via an HTML auto-redirect page rather than a 302 —
	// a custom-scheme navigation must originate from within the page).
	if isMobile {
		p.renderMobileAuthComplete(w, state.MobileRedirect, session.Token, csrfToken)
		return
	}

	siteURL := p.getSiteURL()
	p.setSessionCookie(w, r, session, siteURL)

	returnTo := safeReturnTo(state.ReturnTo)

	http.Redirect(w, r, siteURL+returnTo, http.StatusFound)
}

// createLoginSession creates a Mattermost session for a user who completed OIDC login.
func (p *Plugin) createLoginSession(r *http.Request, mmUser *model.User, snapshot *LoginSnapshot, binding ResolvedIdentity, credentials *StoredCredentials, expectedGeneration *uint64, isMobile bool) (*model.Session, string, error) {
	ctx := r.Context()
	mmConfig := p.API.GetConfig()
	sessionLengthHours := 720 // fallback: 30 days
	if mmConfig != nil {
		if isMobile && mmConfig.ServiceSettings.SessionLengthMobileInHours != nil {
			sessionLengthHours = *mmConfig.ServiceSettings.SessionLengthMobileInHours
		} else if mmConfig.ServiceSettings.SessionLengthWebInHours != nil {
			sessionLengthHours = *mmConfig.ServiceSettings.SessionLengthWebInHours
		}
	}

	userAgent := r.UserAgent()
	if len(userAgent) > 256 {
		userAgent = userAgent[:256]
	}

	// The native app refuses to complete login unless MMCSRF is non-empty. Bearer-token
	// (mobile) API calls are not CSRF-checked server-side, but we persist the token in
	// session Props so Session.GetCSRF() stays consistent with what we hand the app.
	csrfToken := model.NewId()

	// IsOAuth must be false: it is reserved for sessions backed by a Mattermost
	// OAuth-app access token. Our session has no OAuthAccessData row, so setting
	// IsOAuth=true makes logout's RevokeSession → RevokeAccessToken fail with
	// "could not get token" (HTTP 500). Core SSO logins also use IsOAuth=false and
	// flag OAuth via the isOAuthUser session prop instead.
	if p.assertLoginSnapshot(ctx, snapshot) != nil || p.AssertCurrentBinding(ctx, binding) != nil || mmUser.Id != binding.Binding.MattermostUserID {
		return nil, "", ErrIdentityConflict
	}
	session, appErr := p.API.CreateSession(&model.Session{
		UserId:        mmUser.Id,
		Roles:         mmUser.GetRawRoles(),
		IsOAuth:       false,
		ExpiresAt:     model.GetMillis() + int64(sessionLengthHours)*60*60*1000,
		ExpiredNotify: false,
		Props: model.StringMap{
			"platform":                    "oidc_plugin",
			"os":                          userAgent,
			"csrf":                        csrfToken,
			model.UserAuthServiceIsOAuth:  "true",
			model.UserAuthServiceIsMobile: strconv.FormatBool(isMobile),
		},
	})
	if appErr != nil {
		return nil, "", appErr
	}
	if session == nil {
		return nil, "", ErrIdentityConflict
	}
	var err error
	if session.UserId != binding.Binding.MattermostUserID {
		err = ErrIdentityConflict
	} else {
		err = p.captureLoginCredentials(ctx, snapshot, binding, credentials, expectedGeneration)
	}
	if err != nil {
		if revokeErr := p.API.RevokeSession(session.Id); revokeErr != nil {
			p.API.LogError("Failed to revoke unreleased OIDC session")
		}
		return nil, "", err
	}
	return session, csrfToken, nil
}

func (p *Plugin) captureLoginCredentials(ctx context.Context, snapshot *LoginSnapshot, binding ResolvedIdentity, credentials *StoredCredentials, expectedGeneration *uint64) error {
	if err := p.assertLoginSnapshot(ctx, snapshot); err != nil {
		return err
	}
	if err := p.AssertCurrentBinding(ctx, binding); err != nil {
		return err
	}
	store := newCredentialStore(p)
	var publication *credentialPublication
	if p.getConfiguration().EnableTokenPersistence && credentials != nil {
		var err error
		publication, err = store.save(ctx, *credentials, expectedGeneration)
		if err != nil {
			if !errors.Is(err, ErrCredentialsUnavailable) {
				return err
			}
			p.API.LogWarn("OIDC login completed without delegated credentials")
		}
	}
	err := p.assertLoginSnapshot(ctx, snapshot)
	if err == nil {
		err = p.AssertCurrentBinding(ctx, binding)
	}
	if err != nil && publication != nil {
		if cleanupErr := store.abandonPublication(ctx, binding.Binding, publication.envelope, publication.ready); cleanupErr != nil {
			return cleanupErr
		}
	}
	return err
}

// refresh_expires_in is provider-specific, not an OIDC guarantee. Missing, zero,
// invalid or unbounded values remain unknown, never an invented infinite expiry.
func refreshExpiry(token *oauth2.Token, now time.Time) time.Time {
	var seconds int64
	switch v := token.Extra("refresh_expires_in").(type) {
	case float64:
		if v <= 0 || v > 315360000 || v != float64(int64(v)) {
			return time.Time{}
		}
		seconds = int64(v)
	case json.Number:
		seconds, _ = v.Int64()
	case string:
		seconds, _ = strconv.ParseInt(v, 10, 64)
	case int64:
		seconds = v
	case int:
		seconds = int64(v)
	}
	if seconds <= 0 || seconds > 315360000 {
		return time.Time{}
	}
	return now.Add(time.Duration(seconds) * time.Second)
}

// renderMobileAuthComplete renders an HTML page that redirects the in-app browser to the
// native app's custom URL scheme with the session token (MMAUTHTOKEN) and CSRF token
// (MMCSRF) attached. This mirrors Mattermost core's utils.RenderMobileAuthComplete:
// a custom-scheme navigation has to come from within the page (meta refresh / link),
// not an HTTP 302, for the app's ASWebAuthenticationSession to intercept it.
func (p *Plugin) renderMobileAuthComplete(w http.ResponseWriter, redirectTo, token, csrf string) {
	u, err := url.Parse(redirectTo)
	if err != nil {
		p.API.LogError("Invalid mobile redirect target", "redirect", redirectTo, "error", err.Error())
		p.renderError(w, "Invalid mobile redirect target")
		return
	}

	q := u.Query()
	q.Set(model.SessionCookieToken, token) // MMAUTHTOKEN
	q.Set(model.SessionCookieCsrf, csrf)   // MMCSRF
	u.RawQuery = q.Encode()
	p.renderAppRedirect(w, u.String())
}

// renderAppRedirect renders a page that sends the browser to the app's custom URL scheme; a custom-scheme navigation has to come from the page (meta refresh / link), not an HTTP 302.
func (p *Plugin) renderAppRedirect(w http.ResponseWriter, link string) {
	// The link may carry secrets: prevent caching and referrer leakage.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="refresh" content="0; url=%s">
	<title>Authentication complete</title>
</head>
<body style="font-family: sans-serif; max-width: 600px; margin: 50px auto; text-align: center;">
	<h2>Authentication complete</h2>
	<p>Redirecting you back to the app&hellip;</p>
	<p><a href="%s">Tap here if you are not redirected automatically</a></p>
</body>
</html>`, html.EscapeString(link), html.EscapeString(link))
}

// extractUserInfo parses the OIDC claims into an OIDCUserInfo struct.
func (p *Plugin) extractUserInfo(ctx context.Context, idToken *oidc.IDToken, oauthToken *oauth2.Token, snapshot *LoginSnapshot) (*OIDCUserInfo, error) {
	config := &snapshot.configuration
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse ID token claims: %w", err)
	}

	// Also try to get claims from userinfo endpoint for additional data
	provider := snapshot.provider
	if provider != nil && oauthToken != nil && oauthToken.AccessToken != "" {
		tokenSource := oauth2.StaticTokenSource(oauthToken)
		userInfoResp, err := provider.UserInfo(ctx, tokenSource)
		if err == nil {
			if userInfoResp.Subject != idToken.Subject {
				return nil, ErrIdentityConflict
			}
			var uiClaims map[string]interface{}
			if err := userInfoResp.Claims(&uiClaims); err == nil {
				// Merge userinfo claims into ID token claims (ID token takes priority)
				for k, v := range uiClaims {
					if _, exists := claims[k]; !exists {
						claims[k] = v
					}
				}
			}
		}
	}

	claimKeys := make([]string, 0, len(claims))
	for k := range claims {
		claimKeys = append(claimKeys, k)
	}
	p.API.LogDebug("OIDC claims received", "claim_keys", strings.Join(claimKeys, ", "))

	info := &OIDCUserInfo{
		Subject:       idToken.Subject,
		Issuer:        idToken.Issuer,
		Email:         getStringClaim(claims, config.EmailClaim),
		Username:      getStringClaim(claims, config.UsernameClaim),
		FirstName:     getStringClaim(claims, config.FirstNameClaim),
		LastName:      getStringClaim(claims, config.LastNameClaim),
		Position:      getStringClaim(claims, config.PositionClaim),
		EmailVerified: getBoolClaim(claims, config.EmailVerifiedClaim),
	}

	// Fallback: use email prefix as username if no username claim found
	if info.Username == "" && info.Email != "" {
		parts := strings.SplitN(info.Email, "@", 2)
		info.Username = parts[0]
	}

	// Sanitize username for Mattermost compatibility
	info.Username = sanitizeUsername(info.Username)

	if info.Subject == "" {
		return nil, fmt.Errorf("OIDC subject (sub) claim is empty")
	}

	if info.Email == "" {
		return nil, fmt.Errorf("email claim '%s' is empty or not present in the ID token", config.EmailClaim)
	}
	if _, err := mail.ParseAddress(info.Email); err != nil {
		return nil, fmt.Errorf("OIDC provider returned invalid email address: %w", err)
	}

	return info, nil
}

// KVOIDCUserPrefix is the KV store key prefix for mapping OIDC subjects to Mattermost user IDs.
const KVOIDCUserPrefix = "oidc_user_"

// updateUserIfChanged updates the Mattermost user profile if OIDC claims have changed.
func (p *Plugin) updateUserIfChanged(user *model.User, info *OIDCUserInfo) (*model.User, error) {
	changed := false

	if info.Email != "" && user.Email != info.Email {
		user.Email = info.Email
		changed = true
	}
	if info.FirstName != "" && user.FirstName != info.FirstName {
		user.FirstName = info.FirstName
		changed = true
	}
	if info.LastName != "" && user.LastName != info.LastName {
		user.LastName = info.LastName
		changed = true
	}
	if info.Position != "" && user.Position != info.Position {
		user.Position = info.Position
		changed = true
	}
	if info.EmailVerified != nil && user.EmailVerified != *info.EmailVerified {
		user.EmailVerified = *info.EmailVerified
		changed = true
	}

	if !changed {
		return user, nil
	}

	updatedUser, appErr := p.API.UpdateUser(user)
	if appErr != nil {
		return nil, fmt.Errorf("failed to update user: %s", appErr.Error())
	}
	return updatedUser, nil
}

// handleGetPublicConfig returns the publicly visible configuration (button text/color, enable status).
func (p *Plugin) handleGetPublicConfig(w http.ResponseWriter, r *http.Request) {
	config := p.getConfiguration()

	publicConfig := map[string]interface{}{
		"enable":       config.Enable && config.IsValid() == nil,
		"button_text":  config.ButtonText,
		"button_color": config.ButtonColor,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(publicConfig); err != nil {
		p.API.LogError("Failed to encode public config", "error", err.Error())
	}
}

// signState creates an HMAC-signed state string.
func (p *Plugin) signState(token string) string {
	mac := hmac.New(sha256.New, []byte(p.getEncryptionKey()))
	mac.Write([]byte(token))
	signature := hex.EncodeToString(mac.Sum(nil))
	return token + ":" + signature
}

// verifyAndExtractState verifies the HMAC signature and extracts the state token.
func (p *Plugin) verifyAndExtractState(signedState string) (string, error) {
	parts := strings.SplitN(signedState, ":", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("malformed state parameter")
	}

	token := parts[0]
	expectedSigned := p.signState(token)

	if !hmac.Equal([]byte(signedState), []byte(expectedSigned)) {
		return "", fmt.Errorf("state signature verification failed")
	}

	return token, nil
}

// setStateCookie stores the OAuth state token in a short-lived, browser-bound cookie
// at connect time. HttpOnly (no need for JS access) and SameSite=Lax so it still
// accompanies the top-level GET redirect back from the identity provider.
func (p *Plugin) setStateCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(stateExpiry.Seconds()),
		HttpOnly: true,
		Secure:   strings.HasPrefix(p.getSiteURL(), "https"),
		SameSite: http.SameSiteLaxMode,
	})
}

// clearStateCookie expires the state cookie once it has been consumed at the callback.
func (p *Plugin) clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   strings.HasPrefix(p.getSiteURL(), "https"),
		SameSite: http.SameSiteLaxMode,
	})
}

// stateCookieMatches reports whether the request carries the state cookie set at
// connect and its value matches the state token from the callback. The comparison is
// constant-time. A missing or empty cookie returns false.
func stateCookieMatches(r *http.Request, token string) bool {
	c, err := r.Cookie(oidcStateCookie)
	if err != nil || c.Value == "" {
		return false
	}
	return hmac.Equal([]byte(c.Value), []byte(token))
}

// setSessionCookie writes the Mattermost session cookies (MMAUTHTOKEN, MMUSERID,  MMCSRF) with the same Domain and lifetime core uses in AttachSessionCookies.
// See https://github.com/server-camp/mattermost-oidc-plugin/pull/32 for details.
func (p *Plugin) setSessionCookie(w http.ResponseWriter, r *http.Request, session *model.Session, siteURL string) {
	secure := strings.HasPrefix(siteURL, "https")
	domain := p.getCookieDomain()
	cookiePath := getCookiePath(siteURL)

	maxAge := max(int((session.ExpiresAt-model.GetMillis())/1000), 1)
	expires := time.UnixMilli(session.ExpiresAt)

	cookies := []*http.Cookie{
		{Name: model.SessionCookieToken, Value: session.Token, HttpOnly: true, Path: cookiePath, Domain: domain, MaxAge: maxAge, Expires: expires, Secure: secure, SameSite: http.SameSiteLaxMode},
		{Name: model.SessionCookieUser, Value: session.UserId, Path: cookiePath, Domain: domain, MaxAge: maxAge, Expires: expires, Secure: secure, SameSite: http.SameSiteLaxMode},
		{Name: model.SessionCookieCsrf, Value: session.GetCSRF(), Path: cookiePath, Domain: domain, MaxAge: maxAge, Expires: expires, Secure: secure, SameSite: http.SameSiteLaxMode},
	}
	for _, c := range cookies {
		// Drop any host-only copy left by an earlier login through this plugin, so the browser keeps a single cookie per name.
		if domain != "" {
			http.SetCookie(w, &http.Cookie{Name: c.Name, Value: "", Path: cookiePath, MaxAge: -1, Secure: c.Secure, HttpOnly: c.HttpOnly, SameSite: c.SameSite})
		}
		http.SetCookie(w, c)
	}
}

// getCookieDomain mirrors core's App.GetCookieDomain: the SiteURL host when AllowCookiesForSubdomains is on, otherwise "" (host-only cookies).
func (p *Plugin) getCookieDomain() string {
	cfg := p.API.GetConfig()
	if cfg == nil || cfg.ServiceSettings.AllowCookiesForSubdomains == nil || !*cfg.ServiceSettings.AllowCookiesForSubdomains {
		return ""
	}
	u, err := url.Parse(p.getSiteURL())
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// getCookiePath mirrors core's utils.GetSubpathFromConfig: returns the cleaned URL path from SiteURL (e.g. "/mattermost"), or "/" if no subpath is configured.
func getCookiePath(siteURL string) string {
	if siteURL == "" {
		return "/"
	}
	u, err := url.Parse(siteURL)
	if err != nil || u.Path == "" {
		return "/"
	}
	subpath := path.Clean(u.Path)
	if subpath == "" || subpath == "." || subpath == "/" {
		return "/"
	}
	if !strings.HasPrefix(subpath, "/") {
		subpath = "/" + subpath
	}
	return subpath
}

// renderError renders a simple error page to the user.
func (p *Plugin) renderError(w http.ResponseWriter, message string) {
	siteURL := p.getSiteURL()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Authentication Error</title></head>
<body style="font-family: sans-serif; max-width: 600px; margin: 50px auto; text-align: center;">
	<h2>Authentication Error</h2>
	<p>%s</p>
	<p><a href="%s/login">Back to Login</a></p>
</body>
</html>`, html.EscapeString(message), html.EscapeString(siteURL))
}

// getStringClaim safely extracts a string claim from a claims map.
func getStringClaim(claims map[string]interface{}, key string) string {
	if val, ok := claims[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func getBoolClaim(claims map[string]interface{}, key string) *bool {
	if key == "" {
		return nil
	}
	val, ok := claims[key]
	if !ok {
		return nil
	}
	switch v := val.(type) {
	case bool:
		return model.NewPointer(v)
	case string:
		if b, err := strconv.ParseBool(v); err == nil {
			return model.NewPointer(b)
		}
	}
	return nil
}

// sanitizeUsername makes a username compatible with Mattermost's requirements.
func sanitizeUsername(username string) string {
	username = strings.ToLower(username)
	username = strings.TrimSpace(username)

	// Replace disallowed characters with underscores
	var sanitized strings.Builder
	for _, r := range username {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			sanitized.WriteRune(r)
		} else {
			sanitized.WriteRune('_')
		}
	}

	result := sanitized.String()

	// Must start with a letter
	if len(result) > 0 && (result[0] < 'a' || result[0] > 'z') {
		result = "u" + result
	}

	// Minimum length 3
	for len(result) < 3 {
		result += "_"
	}

	// Maximum length 64
	if len(result) > 64 {
		result = result[:64]
	}

	return result
}

// nonceMatches reports whether the ID token nonce equals the value stored at connect. An empty expected nonce is a failure: we always send one.
func nonceMatches(expected, got string) bool {
	if expected == "" {
		return false
	}
	return hmac.Equal([]byte(expected), []byte(got))
}

// safeReturnTo returns path if it is a same-origin relative path, otherwise "/".
func safeReturnTo(path string) string {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsRune(path, '\\') {
		return "/"
	}
	return path
}
