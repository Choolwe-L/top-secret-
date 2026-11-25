# autopen — AI-orchestrated assessment framework (authorized lab use)

A small, Go-based framework that coordinates assessment **phases** — recon,
authentication, authorization, and impact — against a target an AI planner
chooses the order of, based on what it finds. It is built for the **authorized,
self-contained lab in this repository** (the FitTrack `vulnerable_api`) and for
learning how an autonomous pentest pipeline is structured.

It is deliberately **not** a point-and-shoot attack tool. See *Safety model*.

## Why this exists

ARTEX-style "autonomous pentest" frameworks chain AI agents across recon →
discovery → exploitation → privilege escalation → impact. This is a compact,
readable, **safe** implementation of that idea so you can study the
architecture: a planner brain, a scoped execution layer, pluggable phase
modules, and an audit trail.

## Safety model (read this first)

This framework will not run unless it is pointed at systems you are allowed to
test, and it keeps every action bounded and logged.

| Guardrail | What it does |
|-----------|--------------|
| **Authorization gate** | Refuses to start unless `authorization.acknowledged = true` and a non-empty `statement` is recorded. |
| **Scope allowlist** | Every network request is checked against `allow_hosts` / `allow_cidrs` / `allow_ports`. Out-of-scope requests are **refused and audited**, never attempted. |
| **Request budget** | `max_requests` hard-caps the whole run (no runaway scanning / DoS). |
| **Throttle** | `requests_per_second` paces traffic. |
| **Non-destructive** | The destructive admin route (account deletion) is detected as reachable but **never executed**. The "impact" phase **measures** reachable data (counts) rather than harvesting or saving it. |
| **No evasion** | No stealth/anti-detection features. The User-Agent identifies the tool as authorized testing. |
| **Full audit** | Every decision and request is appended to a JSONL audit log. |

What this framework intentionally does **not** include: weaponized exploits,
mass/arbitrary targeting, credential-cracking wordlists, DoS, or detection
evasion. The modules demonstrate *classes* of flaw against the local lab.

## Architecture

```
cmd/autopen            CLI + safety gate wiring
internal/
  config               JSON config (stdlib only; builds offline)
  scope                authorization + scope allowlist (the gate)
  httpc                the ONLY network path: scope + throttle + budget + audit
  audit                append-only JSONL log
  core                 findings, severities, shared assessment State
  ai                   Planner brain: rule-based (default) + optional LLM
  modules/
    recon              liveness + bounded surface mapping
    authn              token analysis, username enumeration, no-lockout demo
    authz              BOLA, BFLA, privilege escalation (read-only)
    impact             bounded, counts-only blast-radius demonstration
  engine               orchestration loop (ask planner -> run phase -> repeat)
  report               Markdown report
```

The **planner** only decides *which phase runs next*; it never executes anything
and can only pick from the phases you approved in config. The rule-based planner
is fully deterministic and offline. The optional LLM planner (OpenAI-compatible)
is constrained to the same phase list and falls back to rule-based on any error.

## Quick start (against the repo's lab)

The lab target used below (the FitTrack `vulnerable_api`) lives in a separate
authorized coursework repo. Point `target.base_url` at any system you are
authorized to test.

```bash
# 1. Start an authorized lab target (separate terminal) — e.g. the FitTrack
#    vulnerable_api from the Week 5 coursework repo:
cd /path/to/vulnerable_api
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python app.py                       # serves http://127.0.0.1:5000

# 2. Build and run the framework
cd /path/to/top-secret-
go build -o autopen ./cmd/autopen
./autopen -config config.json
```

Output: live progress, a Markdown report (`assessment_report.md`), and an audit
log (`audit.log.jsonl`). Against the vulnerable build you should see ~7 findings
(2 critical, 4 high, 1 medium). Point it at the `hardened_api` build and the
findings should drop to zero.

## Configuration (`config.json`)

```jsonc
{
  "authorization": { "acknowledged": true, "statement": "who authorized this + scope" },
  "scope": {
    "allow_hosts": ["127.0.0.1", "localhost"],
    "allow_ports": [5000],
    "max_requests": 300,
    "requests_per_second": 20
  },
  "target": { "base_url": "http://127.0.0.1:5000" },
  "phases": ["recon", "authn", "authz", "impact"],
  "ai": { "provider": "rulebased" },        // or "openai"
  "credentials": {
    "test_user": { "username": "alice", "password": "Sunshine2024!" },
    "spray_username": "admin",
    "spray_passwords": ["letmein", "123456", "password", "admin", "qwerty"]
  }
}
```

### Enabling the LLM planner (optional)

```jsonc
"ai": {
  "provider": "openai",
  "api_key_env": "OPENAI_API_KEY",
  "endpoint": "https://api.openai.com/v1/chat/completions",
  "model": "gpt-4o-mini"
}
```

Set the key in your environment (`export OPENAI_API_KEY=...`). The planner still
only orders the approved phases; it cannot widen scope or run anything itself.

## Extending it

Add a phase module by implementing `modules.Module` (`Name`, `Phase`, `Run`) and
registering it in `engine.registry()`. Modules may only reach the network through
`Env.HTTP`, so new modules inherit scope, throttling, budget and auditing for
free. Keep new modules non-destructive and evidence-based.

## Legal / ethical

Use only against systems you own or have **written permission** to test. The
authorization gate records your attestation; it does not grant you permission.
Unauthorized access to computer systems is illegal in most jurisdictions.
