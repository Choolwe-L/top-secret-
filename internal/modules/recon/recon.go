// Package recon performs light, bounded discovery: it checks liveness and
// probes a small, fixed list of common API paths to map the attack surface.
// No brute forcing, no large wordlists — this is surface mapping, not scanning.
package recon

import (
	"fmt"
	"net/http"
	"strings"

	"autopen/internal/core"
	"autopen/internal/modules"
)

type Module struct{}

func (Module) Name() string  { return "recon" }
func (Module) Phase() string { return "recon" }

// A deliberately small, curated path list — surface mapping, not fuzzing.
var commonPaths = []string{
	"/health", "/api", "/api/me", "/api/login", "/api/register",
	"/api/admin/users", "/api/users/1/workouts", "/robots.txt", "/.git/config",
}

func (Module) Run(env modules.Env) error {
	env.Logf("probing liveness and mapping surface (%d paths)", len(commonPaths))

	// 1. fingerprint via a liveness request
	if resp, err := env.HTTP.Do(env.Ctx, "GET", env.Base+"/health", nil, nil); err == nil {
		if server := resp.Header.Get("Server"); server != "" {
			env.State.SetFact("server_header", server)
			env.Logf("server: %s", server)
		}
		env.State.NoteEndpoint("/health", resp.Status)
	}

	// 2. map surface
	found := 0
	for _, p := range commonPaths {
		resp, err := env.HTTP.Do(env.Ctx, "GET", env.Base+p, nil, nil)
		if err != nil {
			return err // likely budget/scope/ctx — stop cleanly
		}
		env.State.NoteEndpoint(p, resp.Status)
		if resp.Status < 400 || resp.Status == http.StatusUnauthorized || resp.Status == http.StatusForbidden {
			found++
		}
		// Exposed VCS metadata is a classic info-leak worth flagging.
		if p == "/.git/config" && resp.Status == 200 && strings.Contains(string(resp.Body), "[core]") {
			env.State.AddFinding(core.Finding{
				ID: "exposed-git", Title: "Exposed .git/config", Severity: core.SevMedium,
				Phase: "recon", Target: env.Base,
				Evidence:  "GET /.git/config returned 200 with repository metadata",
				Impact:    "Source code and history may be reconstructable by an attacker.",
				Remediate: "Block dotfiles at the web server; never deploy the .git directory.",
			})
		}
	}
	env.State.SetFact("surface_endpoints", fmt.Sprintf("%d", found))
	env.Logf("mapped %d reachable endpoints", found)
	return nil
}
