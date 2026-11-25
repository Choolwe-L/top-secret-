// Package httpc is the only way modules make network requests. It enforces
// scope on every call, throttles to avoid hammering a target (no DoS / no mass
// scanning), caps total requests, and audits everything.
package httpc

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"autopen/internal/audit"
	"autopen/internal/core"
	"autopen/internal/scope"
)

type Client struct {
	hc    *http.Client
	sc    scope.Scope
	log   *audit.Logger
	state *core.State

	mu      sync.Mutex
	last    time.Time
	minGap  time.Duration
}

func New(sc scope.Scope, log *audit.Logger, state *core.State) *Client {
	gap := time.Duration(0)
	if sc.RequestsPerSecond > 0 {
		gap = time.Duration(float64(time.Second) / sc.RequestsPerSecond)
	}
	return &Client{
		hc:     &http.Client{Timeout: 15 * time.Second},
		sc:     sc,
		log:    log,
		state:  state,
		minGap: gap,
	}
}

// ErrOutOfScope is returned (and audited as a refusal) for any out-of-scope URL.
type ErrOutOfScope struct{ URL, Reason string }

func (e *ErrOutOfScope) Error() string { return fmt.Sprintf("refused out-of-scope request to %s: %s", e.URL, e.Reason) }

// ErrBudget is returned when the run's request budget is exhausted.
type ErrBudget struct{ Max int }

func (e *ErrBudget) Error() string { return fmt.Sprintf("request budget exhausted (max_requests=%d)", e.Max) }

type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// Do performs a scoped, throttled, audited request. headers may be nil.
func (c *Client) Do(ctx context.Context, method, url string, headers map[string]string, body []byte) (*Response, error) {
	// 1. scope gate
	if ok, reason := c.sc.Allows(url); !ok {
		c.log.Log(audit.Entry{Kind: "refusal", Method: method, URL: url, Message: reason})
		return nil, &ErrOutOfScope{URL: url, Reason: reason}
	}

	// 2. budget gate
	c.mu.Lock()
	if c.state.RequestsSpent >= c.sc.MaxRequests {
		c.mu.Unlock()
		c.log.Log(audit.Entry{Kind: "refusal", Method: method, URL: url, Message: "request budget exhausted"})
		return nil, &ErrBudget{Max: c.sc.MaxRequests}
	}
	// 3. throttle
	if c.minGap > 0 {
		wait := time.Until(c.last.Add(c.minGap))
		if wait > 0 {
			c.mu.Unlock()
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			c.mu.Lock()
		}
	}
	c.last = time.Now()
	c.state.RequestsSpent++
	c.mu.Unlock()

	// 4. perform
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "autopen-lab/0.1 (authorized-testing)")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		c.log.Log(audit.Entry{Kind: "request", Method: method, URL: url, Message: "error: " + err.Error()})
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // cap 1MB
	c.log.Log(audit.Entry{Kind: "request", Method: method, URL: url, Status: resp.StatusCode})
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: b}, nil
}

// RequestsRemaining is for UI / planner awareness.
func (c *Client) RequestsRemaining() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sc.MaxRequests - c.state.RequestsSpent
}
