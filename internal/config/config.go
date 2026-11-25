// Package config loads the JSON run configuration (stdlib only, no external
// deps, so the framework builds and runs offline).
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"autopen/internal/scope"
)

type Target struct {
	BaseURL string `json:"base_url"`
}

type AI struct {
	Provider  string `json:"provider"`    // "rulebased" (default, offline) | "openai"
	APIKeyEnv string `json:"api_key_env"` // env var holding the key, e.g. "OPENAI_API_KEY"
	Endpoint  string `json:"endpoint"`    // OpenAI-compatible chat completions URL
	Model     string `json:"model"`
}

type Creds struct {
	// A known-good test account (the operator's own lab account) used to prove
	// authenticated flaws like BOLA/BFLA.
	TestUser struct {
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"test_user"`
	// A tiny, bounded list used only to demonstrate "no lockout / weak creds"
	// against the lab. Not a mass-cracking wordlist.
	SprayPasswords []string `json:"spray_passwords"`
	SprayUsername  string   `json:"spray_username"`
}

type Config struct {
	Authorization scope.Authorization `json:"authorization"`
	Scope         scope.Scope         `json:"scope"`
	Target        Target              `json:"target"`
	Phases        []string            `json:"phases"`
	AI            AI                   `json:"ai"`
	Credentials   Creds               `json:"credentials"`
	AuditLog      string              `json:"audit_log"`
	ReportPath    string              `json:"report_path"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &c, nil
}

// Validate runs every safety check before a run may begin.
func (c *Config) Validate() error {
	if err := c.Authorization.Validate(); err != nil {
		return err
	}
	if err := c.Scope.Validate(); err != nil {
		return err
	}
	if c.Target.BaseURL == "" {
		return fmt.Errorf("target.base_url is required")
	}
	if ok, reason := c.Scope.Allows(c.Target.BaseURL); !ok {
		return fmt.Errorf("target.base_url %q is not within scope: %s", c.Target.BaseURL, reason)
	}
	if len(c.Phases) == 0 {
		c.Phases = []string{"recon", "authn", "authz", "impact"}
	}
	return nil
}
