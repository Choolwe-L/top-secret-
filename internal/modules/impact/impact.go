// Package impact demonstrates the BUSINESS IMPACT of confirmed access-control
// flaws in the safest way that still proves severity: it MEASURES how much data
// an attacker could reach (counts), rather than harvesting or persisting it.
//
// This is the responsible stand-in for a "data exfiltration" phase: it proves
// blast radius without copying personal data out of the lab. It only runs after
// an authorization flaw has been confirmed, and stays within a small id budget.
package impact

import (
	"encoding/json"
	"fmt"

	"autopen/internal/core"
	"autopen/internal/modules"
)

type Module struct{}

func (Module) Name() string  { return "impact" }
func (Module) Phase() string { return "impact" }

const idBudget = 10 // bounded; this is a demonstration, not a scrape

func (Module) Run(env modules.Env) error {
	if !env.State.HasFindingPhase("authz") {
		env.Logf("no access-control findings; nothing to demonstrate")
		return nil
	}

	// Prefer the regular-user token (shows impact needs no special access).
	tok := env.State.Token("user")
	if tok == "" {
		tok = env.State.Token("admin_forged")
	}
	if tok == "" {
		return nil
	}
	auth := map[string]string{"Authorization": "Bearer " + tok}

	// 1. Count accounts exposed via the admin endpoint (BFLA/forged).
	accountCount := -1
	if resp, err := env.HTTP.Do(env.Ctx, "GET", env.Base+"/api/admin/users", auth, nil); err == nil && resp.Status == 200 {
		var parsed struct {
			Users []json.RawMessage `json:"users"`
		}
		if json.Unmarshal(resp.Body, &parsed) == nil {
			accountCount = len(parsed.Users)
		}
	} else if err != nil {
		return err
	}

	// 2. Count how many other users' records are reachable via BOLA — counts
	//    only, we do not store the returned personal data.
	reachable := 0
	for id := 1; id <= idBudget; id++ {
		resp, err := env.HTTP.Do(env.Ctx, "GET",
			fmt.Sprintf("%s/api/users/%d/workouts", env.Base, id), auth, nil)
		if err != nil {
			return err
		}
		if resp.Status == 200 {
			var parsed struct {
				Workouts []json.RawMessage `json:"workouts"`
			}
			if json.Unmarshal(resp.Body, &parsed) == nil && len(parsed.Workouts) > 0 {
				reachable++
			}
		}
	}

	evidence := fmt.Sprintf("within a bounded %d-id probe, %d users' private records were reachable from a single low-privilege session", idBudget, reachable)
	if accountCount >= 0 {
		evidence += fmt.Sprintf("; the admin listing exposed %d full account records (usernames, roles, emails)", accountCount)
	}

	env.State.AddFinding(core.Finding{
		ID: "impact-data-exposure", Title: "Demonstrated impact: mass private-data exposure",
		Severity: core.SevHigh, Phase: "impact", OWASP: "API1:2019", Target: env.Base,
		Evidence:  evidence,
		Impact:    "A single ordinary account can enumerate and read other users' personal data at scale — a reportable data-breach condition.",
		Remediate: "Fix the underlying BOLA/BFLA authorization checks; add per-object access control and monitoring for enumeration patterns.",
	})
	env.Logf("impact demonstrated (counts only, no data retained): %s", evidence)
	return nil
}
