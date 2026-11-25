// Command autopen is an AI-orchestrated, scope-limited, non-destructive
// penetration-testing framework for AUTHORIZED lab use.
//
// It refuses to run unless (1) authorization is acknowledged in the config and
// (2) the target is inside an explicit scope allowlist. Every request is
// throttled, budgeted and audited.
//
//	autopen -config config.json
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"autopen/internal/ai"
	"autopen/internal/audit"
	"autopen/internal/config"
	"autopen/internal/core"
	"autopen/internal/engine"
	"autopen/internal/httpc"
	"autopen/internal/modules"
	"autopen/internal/report"
)

func main() {
	cfgPath := flag.String("config", "config.json", "path to JSON run configuration")
	quiet := flag.Bool("quiet", false, "suppress progress output (audit log still written)")
	flag.Parse()

	if err := run(*cfgPath, *quiet); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(cfgPath string, quiet bool) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	// Safety gate: authorization + scope. Refuses here if not satisfied.
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("refusing to run: %w", err)
	}

	logf := func(format string, args ...any) {
		if !quiet {
			fmt.Printf(format+"\n", args...)
		}
	}

	auditLog, err := audit.New(cfg.AuditLog, nil)
	if err != nil {
		return err
	}
	defer auditLog.Close()
	auditLog.Log(audit.Entry{Kind: "note", Target: cfg.Target.BaseURL,
		Message: "run started; authorization: " + cfg.Authorization.Statement})

	logf("autopen — authorized assessment")
	logf("target: %s", cfg.Target.BaseURL)
	logf("authorization: %s", cfg.Authorization.Statement)
	logf("scope: hosts=%v cidrs=%v ports=%v budget=%d rps=%.1f",
		cfg.Scope.AllowHosts, cfg.Scope.AllowCIDRs, cfg.Scope.AllowPorts,
		cfg.Scope.MaxRequests, cfg.Scope.RequestsPerSecond)

	state := core.NewState(cfg.Target.BaseURL)
	client := httpc.New(cfg.Scope, auditLog, state)

	// Choose planner.
	var planner ai.Planner = ai.RuleBased{}
	if cfg.AI.Provider == "openai" {
		llm, err := ai.NewLLM(cfg.AI.Endpoint, cfg.AI.Model, cfg.AI.APIKeyEnv)
		if err != nil {
			logf("note: %v", err)
			logf("falling back to rule-based planner")
		} else {
			planner = llm
		}
	}

	creds := modules.Creds{
		TestUsername:   cfg.Credentials.TestUser.Username,
		TestPassword:   cfg.Credentials.TestUser.Password,
		SprayUsername:  cfg.Credentials.SprayUsername,
		SprayPasswords: cfg.Credentials.SprayPasswords,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	eng := engine.New(planner, client, state, auditLog, creds, cfg.Target.BaseURL, cfg.Phases, logf)
	runErr := eng.Run(ctx)

	// Always emit a report, even on partial runs.
	rep := report.Render(state, planner.Name())
	outPath := cfg.ReportPath
	if outPath == "" {
		outPath = "assessment_report.md"
	}
	if werr := report.Write(outPath, rep); werr != nil {
		logf("warning: could not write report: %v", werr)
	} else {
		logf("\nreport written: %s", outPath)
	}
	logf("findings: %d (critical/high: %d) · requests: %d",
		len(state.Findings), state.CountAtLeast(core.SevHigh), state.RequestsSpent)

	return runErr
}
