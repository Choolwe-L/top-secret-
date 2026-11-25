// Package scope is the safety gate. Nothing in this framework touches a target
// until scope says it is in-bounds AND the operator has asserted authorization.
// Out-of-scope targets are refused, not best-effort attempted.
package scope

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

type Scope struct {
	AllowHosts        []string `json:"allow_hosts"`          // hostnames or IPs, e.g. "127.0.0.1", "localhost"
	AllowCIDRs        []string `json:"allow_cidrs"`          // e.g. "10.0.0.0/24"
	AllowPorts        []int    `json:"allow_ports"`          // empty = any port on an allowed host
	MaxRequests       int      `json:"max_requests"`         // hard cap for the whole run (anti-DoS)
	RequestsPerSecond float64  `json:"requests_per_second"`  // throttle (anti-DoS / anti-mass-scan)
}

// Authorization must be explicitly acknowledged or the engine refuses to run.
type Authorization struct {
	Acknowledged bool   `json:"acknowledged"`
	Statement    string `json:"statement"`
}

// Validate ensures the operator actually asserted authorization and that a
// non-empty scope was defined. This is deliberately strict.
func (a Authorization) Validate() error {
	if !a.Acknowledged {
		return fmt.Errorf("authorization not acknowledged: set authorization.acknowledged = true and only test systems you own or have written permission to test")
	}
	if strings.TrimSpace(a.Statement) == "" {
		return fmt.Errorf("authorization.statement is empty: record who authorized this test and the scope")
	}
	return nil
}

func (s Scope) Validate() error {
	if len(s.AllowHosts) == 0 && len(s.AllowCIDRs) == 0 {
		return fmt.Errorf("empty scope: define scope.allow_hosts and/or scope.allow_cidrs (this tool refuses to run against 'everything')")
	}
	if s.MaxRequests <= 0 {
		return fmt.Errorf("scope.max_requests must be > 0 (a request budget is required)")
	}
	for _, c := range s.AllowCIDRs {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", c, err)
		}
	}
	return nil
}

// Allows reports whether a full URL is within scope. Everything that makes a
// network request routes through here first.
func (s Scope) Allows(rawURL string) (bool, string) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false, "unparseable URL"
	}
	host := u.Hostname()
	if host == "" {
		return false, "no host in URL"
	}

	// port check (if restricted)
	if len(s.AllowPorts) > 0 {
		port := u.Port()
		if port == "" {
			if u.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		ok := false
		for _, p := range s.AllowPorts {
			if fmt.Sprint(p) == port {
				ok = true
				break
			}
		}
		if !ok {
			return false, fmt.Sprintf("port %s not in allow_ports", port)
		}
	}

	// hostname allowlist
	for _, h := range s.AllowHosts {
		if strings.EqualFold(h, host) {
			return true, ""
		}
	}

	// CIDR allowlist (resolve host to IPs)
	if len(s.AllowCIDRs) > 0 {
		ips, err := net.LookupIP(host)
		if err == nil {
			for _, ipnetStr := range s.AllowCIDRs {
				_, ipnet, _ := net.ParseCIDR(ipnetStr)
				for _, ip := range ips {
					if ipnet.Contains(ip) {
						return true, ""
					}
				}
			}
		}
	}

	return false, fmt.Sprintf("host %q not in scope", host)
}
