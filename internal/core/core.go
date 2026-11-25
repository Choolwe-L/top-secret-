// Package core holds the shared data model: findings, severities, and the
// running assessment state the AI orchestrator reasons over.
package core

import (
	"sync"
	"time"
)

type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Finding is a single result produced by a module.
type Finding struct {
	ID        string    `json:"id"`         // stable slug, e.g. "bola-workouts"
	Title     string    `json:"title"`      // human-readable
	Severity  Severity  `json:"severity"`   //
	Phase     string    `json:"phase"`      // recon|authn|authz|impact
	OWASP     string    `json:"owasp"`      // e.g. "API1:2019"
	Target    string    `json:"target"`     // base URL
	Evidence  string    `json:"evidence"`   // what proved it (non-destructive)
	Impact    string    `json:"impact"`     // why it matters
	Remediate string    `json:"remediate"`  // how to fix
	FoundAt   time.Time `json:"found_at"`   //
}

// State is the shared, concurrency-safe memory of one assessment run. The
// planner inspects it to decide what to do next; modules append to it.
type State struct {
	mu sync.Mutex

	Target        string              `json:"target"`
	Endpoints     map[string]int      `json:"endpoints"`      // path -> last status code
	Tokens        map[string]string   `json:"-"`              // label -> token (secrets, not serialized)
	Facts         map[string]string   `json:"facts"`          // free-form notes the planner can read
	Findings      []Finding           `json:"findings"`
	PhasesDone    []string            `json:"phases_done"`
	RequestsSpent int                 `json:"requests_spent"`
}

func NewState(target string) *State {
	return &State{
		Target:    target,
		Endpoints: map[string]int{},
		Tokens:    map[string]string{},
		Facts:     map[string]string{},
	}
}

func (s *State) AddFinding(f Finding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f.FoundAt.IsZero() {
		f.FoundAt = time.Now()
	}
	s.Findings = append(s.Findings, f)
}

func (s *State) SetFact(k, v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Facts[k] = v
}

func (s *State) GetFact(k string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Facts[k]
}

func (s *State) SetToken(label, tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Tokens[label] = tok
}

func (s *State) Token(label string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Tokens[label]
}

func (s *State) NoteEndpoint(path string, status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Endpoints[path] = status
}

func (s *State) MarkPhaseDone(p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PhasesDone = append(s.PhasesDone, p)
}

// HasFindingPhase reports whether any finding came from the given phase.
func (s *State) HasFindingPhase(phase string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.Findings {
		if f.Phase == phase {
			return true
		}
	}
	return false
}

// CountSeverity tallies findings at or above the given severity.
func (s *State) CountAtLeast(min Severity) int {
	order := map[Severity]int{SevInfo: 0, SevLow: 1, SevMedium: 2, SevHigh: 3, SevCritical: 4}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, f := range s.Findings {
		if order[f.Severity] >= order[min] {
			n++
		}
	}
	return n
}
