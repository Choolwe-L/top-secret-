// Package ai is the orchestrator's "brain". A Planner looks at the current
// assessment State and decides which phase to run next and why. Two
// implementations ship: a deterministic rule-based planner (default, offline,
// fully auditable) and an optional LLM planner (OpenAI-compatible) that the
// operator can enable by supplying an API key.
package ai

import (
	"autopen/internal/core"
)

// Decision is the planner's output for one orchestration step.
type Decision struct {
	NextPhase string `json:"next_phase"` // "recon"|"authn"|"authz"|"impact"|"" (done)
	Rationale string `json:"rationale"`
	Done      bool   `json:"done"`
}

type Planner interface {
	// Plan returns the next step given the plan (ordered phases the operator
	// allowed) and the live state. It must only ever choose from allowedPhases.
	Plan(allowedPhases []string, state *core.State) Decision
	Name() string
}

// RuleBased is a transparent planner: it walks the operator-approved phases in
// order, but uses findings to decide whether later, higher-impact phases are
// worth running. This mirrors how a human lead would triage.
type RuleBased struct{}

func (RuleBased) Name() string { return "rule-based" }

func (RuleBased) Plan(allowed []string, st *core.State) Decision {
	done := map[string]bool{}
	for _, p := range st.PhasesDone {
		done[p] = true
	}
	for _, phase := range allowed {
		if done[phase] {
			continue
		}
		switch phase {
		case "impact":
			// Only pursue impact demonstration if an access-control flaw was
			// actually found; otherwise there is nothing to safely demonstrate.
			if !st.HasFindingPhase("authz") {
				return Decision{NextPhase: "", Done: false, Rationale: "skipping impact: no access-control findings to demonstrate"}
			}
			return Decision{NextPhase: phase, Rationale: "access-control flaw found; demonstrating bounded, read-only impact"}
		case "authz":
			if st.Token("user") == "" {
				return Decision{NextPhase: phase, Rationale: "testing object/function-level authorization"}
			}
			return Decision{NextPhase: phase, Rationale: "authenticated session available; probing BOLA/BFLA and privilege escalation"}
		default:
			return Decision{NextPhase: phase, Rationale: "running " + phase + " (standard methodology order)"}
		}
	}
	return Decision{Done: true, Rationale: "all approved phases complete"}
}

// advanceSkipping lets the engine move past a phase the planner declined
// without rerunning it forever. Exposed as a helper for the engine.
func NextUndone(allowed []string, st *core.State) string {
	done := map[string]bool{}
	for _, p := range st.PhasesDone {
		done[p] = true
	}
	for _, p := range allowed {
		if !done[p] {
			return p
		}
	}
	return ""
}
