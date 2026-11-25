package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"autopen/internal/core"
)

// LLM is an optional planner backed by an OpenAI-compatible chat completions
// API. It is constrained hard: the model may ONLY pick from the allowed phases,
// its output is parsed as strict JSON, and anything unexpected falls back to the
// rule-based planner. The model never executes anything — it only orders phases.
type LLM struct {
	endpoint string
	model    string
	key      string
	fallback RuleBased
	hc       *http.Client
}

func NewLLM(endpoint, model, apiKeyEnv string) (*LLM, error) {
	key := os.Getenv(apiKeyEnv)
	if key == "" {
		return nil, fmt.Errorf("LLM planner requested but env %s is empty; add your key or set ai.provider=rulebased", apiKeyEnv)
	}
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1/chat/completions"
	}
	if model == "" {
		model = "gpt-4o-mini"
	}
	return &LLM{endpoint: endpoint, model: model, key: key, hc: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (l *LLM) Name() string { return "llm:" + l.model }

type chatReq struct {
	Model       string    `json:"model"`
	Messages    []message `json:"messages"`
	Temperature float64   `json:"temperature"`
}
type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type chatResp struct {
	Choices []struct {
		Message message `json:"message"`
	} `json:"choices"`
}

func (l *LLM) Plan(allowed []string, st *core.State) Decision {
	prompt := buildPrompt(allowed, st)
	body, _ := json.Marshal(chatReq{
		Model:       l.model,
		Temperature: 0,
		Messages: []message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: prompt},
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", l.endpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+l.key)

	resp, err := l.hc.Do(req)
	if err != nil {
		return l.fallbackWith(allowed, st, "LLM request failed: "+err.Error())
	}
	defer resp.Body.Close()
	var cr chatResp
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil || len(cr.Choices) == 0 {
		return l.fallbackWith(allowed, st, "LLM response unparseable")
	}
	raw := strings.TrimSpace(cr.Choices[0].Message.Content)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")

	var d Decision
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &d); err != nil {
		return l.fallbackWith(allowed, st, "LLM did not return valid JSON")
	}
	// Constrain to allowed phases — never trust the model to stay in bounds.
	if d.NextPhase != "" && !contains(allowed, d.NextPhase) {
		return l.fallbackWith(allowed, st, "LLM chose out-of-plan phase "+d.NextPhase)
	}
	if d.Rationale == "" {
		d.Rationale = "LLM decision"
	}
	d.Rationale = "[llm] " + d.Rationale
	return d
}

func (l *LLM) fallbackWith(allowed []string, st *core.State, why string) Decision {
	d := l.fallback.Plan(allowed, st)
	d.Rationale = "[llm fell back: " + why + "] " + d.Rationale
	return d
}

const systemPrompt = `You are the planning component of an AUTHORIZED, scope-limited penetration-testing lab tool.
You only decide which assessment PHASE runs next. You never produce exploit code and never touch anything yourself.
You must choose next_phase strictly from the provided allowed phases, or set done=true.
Favor standard methodology order (recon -> authn -> authz -> impact). Only choose "impact" if access-control findings already exist.
Respond with ONLY a JSON object: {"next_phase": "<phase or empty>", "rationale": "<short why>", "done": <bool>}.`

func buildPrompt(allowed []string, st *core.State) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Target: %s\n", st.Target)
	fmt.Fprintf(&b, "Allowed phases: %s\n", strings.Join(allowed, ", "))
	fmt.Fprintf(&b, "Phases already done: %s\n", strings.Join(st.PhasesDone, ", "))
	fmt.Fprintf(&b, "Findings so far: %d\n", len(st.Findings))
	for _, f := range st.Findings {
		fmt.Fprintf(&b, "  - [%s] %s (%s)\n", f.Severity, f.Title, f.Phase)
	}
	b.WriteString("Decide the next phase.")
	return b.String()
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
