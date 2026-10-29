package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/mattermost/mattermost/server/public/model"
)

const maxApprovalBytes = 1 << 20
const maxApprovalRows = 5000

type approvalMap struct {
	SchemaVersion     int                `json:"schema_version"`
	Approved          bool               `json:"approved"`
	ExpectedGateEpoch uint64             `json:"expected_gate_epoch"`
	Issuer            string             `json:"issuer"`
	ClientID          string             `json:"client_id"`
	Rows              []approvalRow      `json:"rows"`
	Maintenance       maintenanceReceipt `json:"maintenance"`
}
type approvalRow struct {
	Action                  string `json:"action"`
	Approved                bool   `json:"approved"`
	Issuer                  string `json:"issuer"`
	Subject                 string `json:"subject"`
	MattermostUserID        string `json:"mattermost_user_id"`
	ExpectedAuthService     string `json:"expected_auth_service"`
	ExpectedAuthData        string `json:"expected_auth_data"`
	ExpectedLegacyMapping   string `json:"expected_legacy_mapping"`
	ExpectedBindingRevision uint64 `json:"expected_binding_revision"`
	ProvenanceRef           string `json:"provenance_ref"`
}

// Reject duplicate keys at every depth before decoding typed values.
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrIdentityConflict
	}
	t, e := d.Token()
	if e != nil {
		return ErrIdentityConflict
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, e := d.Token()
			if e != nil {
				return ErrIdentityConflict
			}
			s, ok := key.(string)
			if !ok || seen[s] {
				return ErrIdentityConflict
			}
			seen[s] = true
			if e = uniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
	case '[':
		for d.More() {
			if e = uniqueJSON(d, depth+1); e != nil {
				return e
			}
		}
	default:
		return ErrIdentityConflict
	}
	_, e = d.Token()
	if e != nil {
		return ErrIdentityConflict
	}
	return nil
}
func requiredFields(raw json.RawMessage, names ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if b, ok := fields[name]; !ok || bytes.Equal(b, []byte("null")) {
			return false
		}
	}
	return true
}
func parseApprovalMap(b []byte) (approvalMap, error) {
	var m approvalMap
	if len(b) > maxApprovalBytes || len(b) == 0 {
		return m, ErrIdentityConflict
	}
	d := json.NewDecoder(bytes.NewReader(b))
	if uniqueJSON(d, 0) != nil {
		return m, ErrIdentityConflict
	}
	if _, e := d.Token(); e != io.EOF {
		return m, ErrIdentityConflict
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil {
		return m, ErrIdentityConflict
	}
	if !requiredFields(b, "schema_version", "approved", "expected_gate_epoch", "issuer", "client_id", "rows", "maintenance") {
		return m, ErrIdentityConflict
	}
	var raw struct {
		Rows        []json.RawMessage `json:"rows"`
		Maintenance json.RawMessage   `json:"maintenance"`
	}
	_ = json.Unmarshal(b, &raw)
	if !requiredFields(raw.Maintenance, "scope_sha256", "all_nodes_quiesced", "affected_sessions_revoked", "evidence_ref") {
		return m, ErrIdentityConflict
	}
	for _, r := range raw.Rows {
		if !requiredFields(r, "action", "approved", "issuer", "subject", "mattermost_user_id", "expected_auth_service", "expected_auth_data", "expected_legacy_mapping", "expected_binding_revision", "provenance_ref") {
			return m, ErrIdentityConflict
		}
	}
	if m.SchemaVersion != 1 || !m.Approved || m.ExpectedGateEpoch == 0 || m.Issuer == "" || m.ClientID == "" || m.Rows == nil || len(m.Rows) > maxApprovalRows || strings.TrimSpace(m.Maintenance.EvidenceRef) == "" {
		return m, ErrIdentityConflict
	}
	pairs, users := map[string]bool{}, map[string]bool{}
	scope := []string{}
	for _, r := range m.Rows {
		key := pairDigest(r.Issuer, r.Subject)
		if !r.Approved || r.Issuer != m.Issuer || r.Subject == "" || !model.IsValidId(r.MattermostUserID) || r.ExpectedAuthService != AuthService || strings.TrimSpace(r.ProvenanceRef) == "" || pairs[key] || users[r.MattermostUserID] {
			return m, ErrIdentityConflict
		}
		if r.Action != "import_legacy" && r.Action != "retain" {
			return m, ErrIdentityConflict
		}
		if r.Action == "import_legacy" && (r.ExpectedBindingRevision != 0 || r.ExpectedLegacyMapping != r.MattermostUserID || r.ExpectedAuthData != r.Subject) {
			return m, ErrIdentityConflict
		}
		if r.Action == "retain" && (r.ExpectedLegacyMapping != "" || r.ExpectedBindingRevision == 0 || r.ExpectedAuthData == "") {
			return m, ErrIdentityConflict
		}
		pairs[key] = true
		users[r.MattermostUserID] = true
		scope = append(scope, r.MattermostUserID)
	}
	sort.Strings(scope)
	if m.Maintenance.ScopeSHA256 != digestJSON(scope) {
		return m, ErrIdentityConflict
	}
	return m, nil
}
func validApprovalHash(h string) bool {
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
func (p *Plugin) loadApprovalMap(h string) (approvalMap, error) {
	var empty approvalMap
	if !validApprovalHash(h) {
		return empty, ErrIdentityConflict
	}
	reader := p.readApprovalFile
	if reader == nil {
		reader = readFixedApprovalFile
	}
	b, e := reader()
	if e != nil {
		return empty, ErrIdentityUnavailable
	}
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != h {
		return empty, ErrIdentityConflict
	}
	return parseApprovalMap(b)
}
func importTransaction(h string, i int) string {
	return digestJSON([]string{"mm-oidc-import-v1", h, strconv.Itoa(i)})
}
func (p *Plugin) validateApprovalRow(row approvalRow, h string, i int) (identityRecord, error) {
	b := IdentityBinding{row.Issuer, row.Subject, row.MattermostUserID}
	u, ae := p.API.GetUser(b.MattermostUserID)
	if ae != nil {
		return identityRecord{}, ErrIdentityUnavailable
	}
	if u == nil || u.DeleteAt != 0 || u.IsBot || u.AuthService != row.ExpectedAuthService || u.AuthData == nil || *u.AuthData != row.ExpectedAuthData {
		return identityRecord{}, ErrIdentityConflict
	}
	if row.Action == "retain" {
		r, _, e := p.committedIdentity(b)
		if e != nil {
			return r, e
		}
		if r.Revision != row.ExpectedBindingRevision {
			return r, ErrIdentityConflict
		}
		return r, nil
	}
	legacy, ae := p.API.KVGet(KVOIDCUserPrefix + row.Subject)
	if ae != nil {
		return identityRecord{}, ErrIdentityUnavailable
	}
	if string(legacy) != row.ExpectedLegacyMapping {
		return identityRecord{}, ErrIdentityConflict
	}
	expected := identityRecord{Version: 1, Binding: b, Revision: 1, TransactionID: importTransaction(h, i), State: "pending", Mode: LegacyRaw, AuthService: AuthService, AuthData: row.Subject}
	if !validNative(u, expected) {
		return expected, ErrIdentityConflict
	}
	r, _, e := p.readIdentityRecord(pairKey(b))
	if e != nil && e != ErrIdentityUnproven {
		return expected, e
	}
	if e == nil {
		compare := r
		compare.State = "pending"
		if compare != expected {
			return expected, ErrIdentityConflict
		}
		expected = r
		if r.State == "committed" {
			if _, _, e := p.committedIdentity(b); e != nil {
				return expected, e
			}
		}
	}
	reverse, _, e := p.readIdentityRecord(identityUserPrefix + b.MattermostUserID)
	if e != nil && e != ErrIdentityUnproven {
		return expected, e
	}
	if e == nil {
		compare := reverse
		compare.State = "pending"
		base := expected
		base.State = "pending"
		if compare != base || reverse.State != "committed" {
			return expected, ErrIdentityConflict
		}
	}
	return expected, nil
}
func (p *Plugin) validateApprovalMap(m approvalMap, h string, activeReplay bool) error {
	g, _, e := p.readIdentityGate()
	if e != nil {
		return e
	}
	if g.Status != "frozen" || g.Epoch != m.ExpectedGateEpoch {
		if !activeReplay || g.Status != "active" || g.Epoch != m.ExpectedGateEpoch+1 || g.ApprovedMapSHA256 != h {
			return ErrIdentityGateClosed
		}
	}
	cfg := p.getConfiguration()
	if configuredIssuer(cfg) != m.Issuer || cfg.ClientID != m.ClientID {
		return ErrIdentityConflict
	}
	represented := map[string]bool{}
	for i, row := range m.Rows {
		if _, e = p.validateApprovalRow(row, h, i); e != nil {
			return e
		}
		represented[pairKey(IdentityBinding{Issuer: row.Issuer, Subject: row.Subject})] = true
	}
	// Enumerate all registry pairs so an approved activation cannot omit existing
	// bindings for this issuer. Gate maintenance quiescence supplies the drain.
	for page := 0; ; page++ {
		keys, ae := p.API.KVList(page, 200)
		if ae != nil {
			return ErrIdentityUnavailable
		}
		for _, key := range keys {
			if !strings.HasPrefix(key, identityPairPrefix) {
				continue
			}
			r, _, e := p.readIdentityRecord(key)
			if e != nil {
				return e
			}
			if r.Binding.Issuer == m.Issuer && r.State == "committed" && !represented[key] {
				return ErrIdentityConflict
			}
		}
		if len(keys) < 200 {
			break
		}
		if page >= 100000 {
			return ErrIdentityUnavailable
		}
	}
	return nil
}
func (p *Plugin) applyApprovalMap(h string) error {
	m, e := p.loadApprovalMap(h)
	if e != nil {
		return e
	}
	return p.applyParsedApprovalMap(m, h)
}
func (p *Plugin) applyParsedApprovalMap(m approvalMap, h string) error {
	var e error
	if e = p.validateApprovalMap(m, h, false); e != nil {
		return e
	}
	for i, row := range m.Rows {
		g, _, e := p.readIdentityGate()
		if e != nil {
			return e
		}
		if g.Status != "frozen" || g.Epoch != m.ExpectedGateEpoch {
			return ErrIdentityGateClosed
		}
		r, e := p.validateApprovalRow(row, h, i)
		if e != nil {
			return e
		}
		if r.State == "committed" {
			continue
		}
		_, old, e := p.readIdentityRecord(pairKey(r.Binding))
		if e == ErrIdentityUnproven {
			ok, e := p.casIdentity(pairKey(r.Binding), old, r)
			if e != nil {
				return e
			}
			if !ok {
				r, e = p.validateApprovalRow(row, h, i)
				if e != nil {
					return e
				}
			}
		} else if e != nil {
			return e
		}
		if e = p.finishIdentity(r); e != nil {
			return e
		}
	}
	if e = p.validateApprovalMap(m, h, false); e != nil {
		return e
	}
	for i := 0; i < 32; i++ {
		g, old, e := p.readIdentityGate()
		if e != nil {
			return e
		}
		if g.Status != "frozen" || g.Epoch != m.ExpectedGateEpoch {
			return ErrIdentityGateClosed
		}
		if g.ApprovedMapSHA256 == h {
			return nil
		}
		g.Issuer = m.Issuer
		g.ClientID = m.ClientID
		g.IdentityFingerprint = identityFingerprint(m.Issuer, m.ClientID)
		g.ApprovedMapSHA256 = h
		g.MaintenanceReceipt = nil
		ok, e := p.casIdentity(identityGateKey, old, g)
		if e != nil {
			return e
		}
		if ok {
			return nil
		}
	}
	return ErrIdentityUnavailable
}
func (p *Plugin) activateApprovalMap(h string) error {
	m, e := p.loadApprovalMap(h)
	if e != nil {
		return e
	}
	return p.activateParsedApprovalMap(m, h)
}
func (p *Plugin) activateParsedApprovalMap(m approvalMap, h string) error {
	var e error
	if !m.Maintenance.AllNodesQuiesced || (len(m.Rows) > 0 && !m.Maintenance.AffectedSessionsRevoked) {
		return ErrIdentityGateClosed
	}
	if e = p.validateApprovalMap(m, h, true); e != nil {
		return e
	}
	for _, row := range m.Rows {
		if _, _, e = p.committedIdentity(IdentityBinding{row.Issuer, row.Subject, row.MattermostUserID}); e != nil {
			return e
		}
	}
	for i := 0; i < 32; i++ {
		g, old, e := p.readIdentityGate()
		if e != nil {
			return e
		}
		if g.ApprovedMapSHA256 != h || g.IdentityFingerprint != identityFingerprint(m.Issuer, m.ClientID) {
			return ErrIdentityGateClosed
		}
		if g.Status == "active" && g.Epoch == m.ExpectedGateEpoch+1 && g.MaintenanceReceipt != nil && *g.MaintenanceReceipt == m.Maintenance {
			return nil
		}
		if g.Status != "frozen" || g.Epoch != m.ExpectedGateEpoch || g.Epoch == math.MaxUint64 {
			return ErrIdentityGateClosed
		}
		g.Status = "active"
		g.Epoch++
		receipt := m.Maintenance
		g.MaintenanceReceipt = &receipt
		ok, e := p.casIdentity(identityGateKey, old, g)
		if e != nil {
			return e
		}
		if ok {
			return nil
		}
	}
	return ErrIdentityUnavailable
}
