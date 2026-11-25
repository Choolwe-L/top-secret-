// Package engine is the orchestrator. It asks the AI planner which phase to run
// next, runs that phase's module through the scoped client, feeds results back
// into state, and repeats until the planner is done or phases are exhausted.
package engine

import (
	"context"
	"fmt"

	"autopen/internal/ai"
	"autopen/internal/audit"
	"autopen/internal/core"
	"autopen/internal/httpc"
	"autopen/internal/modules"
	"autopen/internal/modules/authn"
	"autopen/internal/modules/authz"
	"autopen/internal/modules/impact"
	"autopen/internal/modules/recon"
)

type Engine struct {
	planner ai.Planner
	client  *httpc.Client
	state   *core.State
	log     *audit.Logger
	creds   modules.Creds
	base    string
	phases  []string
	logf    func(string, ...any)
}

func New(planner ai.Planner, client *httpc.Client, state *core.State, log *audit.Logger,
	creds modules.Creds, base string, phases []string, logf func(string, ...any)) *Engine {
	return &Engine{planner, client, state, log, creds, base, phases, logf}
}

func registry() map[string]modules.Module {
	return map[string]modules.Module{
		"recon":  recon.Module{},
		"authn":  authn.Module{},
		"authz":  authz.Module{},
		"impact": impact.Module{},
	}
}

func (e *Engine) Run(ctx context.Context) error {
	reg := registry()
	e.logf("planner: %s | phases: %v", e.planner.Name(), e.phases)

	// Bound the loop by the number of phases (each runs at most once).
	for step := 0; step < len(e.phases)+2; step++ {
		d := e.planner.Plan(e.phases, e.state)
		e.log.Log(audit.Entry{Kind: "decision", Target: e.base,
			Message: fmt.Sprintf("next=%q done=%v: %s", d.NextPhase, d.Done, d.Rationale)})

		if d.Done {
			e.logf("planner: done — %s", d.Rationale)
			return nil
		}

		phase := d.NextPhase
		if phase == "" {
			// Planner declined the next phase (e.g. impact with no authz
			// findings). Mark the next undone phase as skipped so we progress.
			skip := ai.NextUndone(e.phases, e.state)
			if skip == "" {
				return nil
			}
			e.logf("skipping phase %q — %s", skip, d.Rationale)
			e.state.MarkPhaseDone(skip)
			continue
		}

		mod, ok := reg[phase]
		if !ok {
			e.logf("unknown phase %q, skipping", phase)
			e.state.MarkPhaseDone(phase)
			continue
		}

		e.logf("── phase: %s ──  (%s)", phase, d.Rationale)
		env := modules.Env{
			Ctx: ctx, Base: e.base, HTTP: e.client, State: e.state,
			Creds: e.creds, Logf: func(f string, a ...any) { e.logf("  "+f, a...) },
		}
		if err := mod.Run(env); err != nil {
			// Scope/budget/context errors are terminal and safe to stop on.
			e.logf("phase %s stopped: %v", phase, err)
			e.state.MarkPhaseDone(phase)
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// out-of-scope or budget: stop the whole run
			if _, ok := err.(*httpc.ErrBudget); ok {
				return err
			}
			if _, ok := err.(*httpc.ErrOutOfScope); ok {
				return err
			}
			continue
		}
		e.state.MarkPhaseDone(phase)
	}
	return nil
}
