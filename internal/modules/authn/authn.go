// Package authn assesses authentication: it logs in with the operator's own lab
// account, analyzes the returned session token, checks for username enumeration,
// and demonstrates (with a tiny, bounded attempt set) the absence of lockout /
// rate limiting. It is not a credential-cracking tool.
package authn

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"autopen/internal/core"
	"autopen/internal/modules"
)

type Module struct{}

func (Module) Name() string  { return "authn" }
func (Module) Phase() string { return "authn" }

type loginResp struct {
	Token string `json:"token"`
	Role  string `json:"role"`
	Error string `json:"error"`
}

func (Module) Run(env modules.Env) error {
	c := env.Creds

	// 1. Authenticate with the operator's own lab account.
	if c.TestUsername != "" {
		lr, status, err := login(env, c.TestUsername, c.TestPassword)
		if err != nil {
			return err
		}
		if status == 200 && lr.Token != "" {
			env.State.SetToken("user", lr.Token)
			env.State.SetFact("user_role", lr.Role)
			env.State.SetFact("user_id_label", c.TestUsername)
			env.Logf("authenticated as %s (role=%s)", c.TestUsername, lr.Role)
			analyzeToken(env, lr.Token)
		} else {
			env.Logf("could not authenticate test user (status %d) — later phases may be limited", status)
		}
	}

	// 2. Username enumeration: compare a definitely-absent user vs the real one.
	if c.TestUsername != "" {
		_, missStatus, err := login(env, "definitely-not-a-user-"+c.TestUsername, "x")
		if err != nil {
			return err
		}
		_, wrongPwStatus, err := login(env, c.TestUsername, "definitely-wrong-password")
		if err != nil {
			return err
		}
		if missStatus != wrongPwStatus {
			env.State.AddFinding(core.Finding{
				ID: "username-enumeration", Title: "Username enumeration via distinct responses",
				Severity: core.SevMedium, Phase: "authn", OWASP: "API2:2019", Target: env.Base,
				Evidence:  fmt.Sprintf("unknown user -> HTTP %d, valid user + wrong password -> HTTP %d", missStatus, wrongPwStatus),
				Impact:    "An attacker can confirm which usernames exist, narrowing credential attacks.",
				Remediate: "Return an identical generic error (and status) for all failed logins.",
			})
			env.Logf("username enumeration detected (%d vs %d)", missStatus, wrongPwStatus)
		}
	}

	// 3. No-lockout / weak-credential demonstration — strictly bounded.
	if c.SprayUsername != "" && len(c.SprayPasswords) > 0 {
		attempts, lockedOut, cracked := 0, false, ""
		for _, pw := range c.SprayPasswords {
			lr, status, err := login(env, c.SprayUsername, pw)
			if err != nil {
				return err
			}
			attempts++
			if status == 429 || (lr.Error != "" && strings.Contains(strings.ToLower(lr.Error), "lock")) {
				lockedOut = true
				break
			}
			if status == 200 {
				cracked = pw
				break
			}
		}
		if !lockedOut && attempts >= 3 {
			sev := core.SevMedium
			ev := fmt.Sprintf("%d consecutive failed logins for %q with no lockout or rate limiting (no HTTP 429)", attempts, c.SprayUsername)
			if cracked != "" {
				sev = core.SevHigh
				ev = fmt.Sprintf("account %q accepted a weak password within %d bounded attempts, with no lockout", c.SprayUsername, attempts)
				env.State.SetFact("weak_cred_user", c.SprayUsername)
			}
			env.State.AddFinding(core.Finding{
				ID: "no-lockout", Title: "No brute-force protection / weak password policy",
				Severity: sev, Phase: "authn", OWASP: "API2:2019", Target: env.Base,
				Evidence:  ev,
				Impact:    "Accounts are exposed to online password guessing.",
				Remediate: "Enforce a strong password policy, add rate limiting and temporary lockout, and alert on repeated failures.",
			})
			env.Logf("no lockout observed after %d bounded attempts", attempts)
		}
	}
	return nil
}

func login(env modules.Env, user, pass string) (loginResp, int, error) {
	body, _ := json.Marshal(map[string]string{"username": user, "password": pass})
	resp, err := env.HTTP.Do(env.Ctx, "POST", env.Base+"/api/login", nil, body)
	if err != nil {
		return loginResp{}, 0, err
	}
	var lr loginResp
	_ = json.Unmarshal(resp.Body, &lr)
	return lr, resp.Status, nil
}

// analyzeToken inspects a session token for obvious weaknesses without any
// network traffic. If it base64-decodes to readable, unsigned content, it is
// forgeable — a critical flaw.
func analyzeToken(env modules.Env, token string) {
	dec, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return // opaque/!base64 — nothing to flag here
	}
	s := string(dec)
	printable := true
	for _, r := range s {
		if r < 32 || r > 126 {
			printable = false
			break
		}
	}
	// A JWT has two dots and a signature segment; absence of that + printable
	// payload strongly implies an unsigned, forgeable token.
	looksJWT := strings.Count(token, ".") == 2
	if printable && !looksJWT {
		env.State.SetFact("token_scheme", "unsigned-base64")
		env.State.SetFact("token_plaintext", s)
		env.State.AddFinding(core.Finding{
			ID: "forgeable-token", Title: "Unsigned, forgeable session token",
			Severity: core.SevCritical, Phase: "authn", OWASP: "API2:2019", Target: env.Base,
			Evidence:  fmt.Sprintf("token base64-decodes to readable, unsigned data: %q", s),
			Impact:    "Anyone can mint a valid token for any user or role (e.g. forge an admin session).",
			Remediate: "Use signed, expiring tokens (e.g. JWT with a server-side secret) and verify the signature on every request.",
		})
		env.Logf("token is unsigned/forgeable: %q", s)
	}
}
