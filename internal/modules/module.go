// Package modules defines the plugin contract every phase module implements,
// plus the Env handed to it. Modules may ONLY reach the network through Env.HTTP,
// which enforces scope, throttling and the request budget.
package modules

import (
	"context"

	"autopen/internal/core"
	"autopen/internal/httpc"
)

// Creds mirrors the config credentials a module may use against the lab.
type Creds struct {
	TestUsername   string
	TestPassword   string
	SprayUsername  string
	SprayPasswords []string
}

type Env struct {
	Ctx     context.Context
	Base    string // target base URL
	HTTP    *httpc.Client
	State   *core.State
	Creds   Creds
	Logf    func(format string, args ...any)
}

type Module interface {
	Name() string
	Phase() string // recon|authn|authz|impact
	Run(env Env) error
}
