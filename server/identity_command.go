package main

import (
	"errors"
	"fmt"
	"github.com/mattermost/mattermost/server/public/model"
	"github.com/mattermost/mattermost/server/public/plugin"
	"io"
	"os"
	"strings"
	"syscall"
)

const identityApprovalPath = "/run/secrets/mm-oidc-identity-map.json"

func readFixedApprovalFile() ([]byte, error) { return readRegularApprovalFile(identityApprovalPath) }

// Production always passes the compile-time path; this helper permits filesystem tests.
func readRegularApprovalFile(path string) ([]byte, error) {
	before, e := os.Lstat(path)
	if e != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0222 != 0 || before.Size() > maxApprovalBytes {
		return nil, ErrIdentityUnavailable
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, ErrIdentityUnavailable
	}
	f := os.NewFile(uintptr(fd), "identity-approval")
	defer func() { _ = f.Close() }()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || !os.SameFile(before, info) {
		return nil, ErrIdentityUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(f, maxApprovalBytes+1))
	if e != nil || len(b) > maxApprovalBytes {
		return nil, ErrIdentityUnavailable
	}
	after, e := os.Lstat(path)
	if e != nil || !os.SameFile(info, after) || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		return nil, ErrIdentityUnavailable
	}
	return b, nil
}
func (p *Plugin) registerIdentityCommand() error {
	return p.API.RegisterCommand(&model.Command{Trigger: "oidc-identity", DisplayName: "OIDC identity maintenance", AutoComplete: true, AutoCompleteDesc: "System administrators: status, freeze, validate <sha256>, apply <sha256>, activate <sha256>", AutoCompleteHint: "status | freeze | validate <sha256> | apply <sha256> | activate <sha256>"})
}
func (p *Plugin) ExecuteCommand(_ *plugin.Context, args *model.CommandArgs) (*model.CommandResponse, *model.AppError) {
	reply := func(text string) (*model.CommandResponse, *model.AppError) {
		return &model.CommandResponse{ResponseType: model.CommandResponseTypeEphemeral, Text: text}, nil
	}
	if args == nil || !model.IsValidId(args.UserId) {
		return reply("authority_denied")
	}
	actor, ae := p.API.GetUser(args.UserId)
	if ae != nil || actor == nil || actor.DeleteAt != 0 || actor.IsBot || !actor.IsSystemAdmin() {
		return reply("authority_denied")
	}
	parts := strings.Fields(args.Command)
	if len(parts) < 2 || parts[0] != "/oidc-identity" {
		return reply("invalid_command")
	}
	sub := parts[1]
	if (sub == "status" || sub == "freeze") && len(parts) != 2 {
		return reply("invalid_command")
	}
	if sub == "validate" || sub == "apply" || sub == "activate" {
		if len(parts) != 3 || !validApprovalHash(parts[2]) {
			return reply("invalid_command")
		}
	} else if sub != "status" && sub != "freeze" {
		return reply("invalid_command")
	}
	var e error
	count := 0
	digest := ""
	if sub == "freeze" {
		_, e = p.freezeIdentityGate()
	}
	if len(parts) == 3 {
		digest = parts[2]
		var m approvalMap
		m, e = p.loadApprovalMap(digest)
		if e == nil {
			count = len(m.Rows)
			switch sub {
			case "validate":
				e = p.validateApprovalMap(m, digest, false)
			case "apply":
				e = p.applyParsedApprovalMap(m, digest)
			case "activate":
				e = p.activateParsedApprovalMap(m, digest)
			}
		}
	}
	g, _, gateErr := p.readIdentityGate()
	if e == nil {
		e = gateErr
	}
	code := "ok"
	if e != nil {
		code = identityCommandOutcome(e)
	}
	if sub == "freeze" || sub == "apply" || sub == "activate" {
		p.API.LogInfo("OIDC identity maintenance", "actor_id", actor.Id, "approval_digest", digest, "count", count, "epoch", g.Epoch, "outcome", code)
	}
	if e != nil {
		return reply("outcome=" + code + " conflicts=1")
	}
	return reply(fmt.Sprintf("outcome=ok gate=%s epoch=%d approval_digest=%s rows=%d conflicts=0", g.Status, g.Epoch, g.ApprovedMapSHA256, count))
}

// Never expose raw storage/parser errors in the administrator response or log.
func identityCommandOutcome(err error) string {
	for _, known := range []error{ErrIdentityUnproven, ErrIdentityConflict, ErrIdentityGateClosed, ErrIdentityUnavailable} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return ErrIdentityUnavailable.Error()
}
