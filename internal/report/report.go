// Package report renders the assessment State into a Markdown report.
package report

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"autopen/internal/core"
)

var sevRank = map[core.Severity]int{
	core.SevCritical: 0, core.SevHigh: 1, core.SevMedium: 2, core.SevLow: 3, core.SevInfo: 4,
}

func Render(st *core.State, planner string) string {
	var b strings.Builder
	findings := append([]core.Finding(nil), st.Findings...)
	sort.SliceStable(findings, func(i, j int) bool {
		return sevRank[findings[i].Severity] < sevRank[findings[j].Severity]
	})

	fmt.Fprintf(&b, "# Autonomous Assessment Report\n\n")
	fmt.Fprintf(&b, "- **Target:** %s\n", st.Target)
	fmt.Fprintf(&b, "- **Generated:** %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Planner:** %s\n", planner)
	fmt.Fprintf(&b, "- **Phases executed:** %s\n", strings.Join(st.PhasesDone, ", "))
	fmt.Fprintf(&b, "- **Requests sent:** %d\n\n", st.RequestsSpent)

	// summary table
	counts := map[core.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "| Severity | Count |\n|---|---|\n")
	for _, s := range []core.Severity{core.SevCritical, core.SevHigh, core.SevMedium, core.SevLow, core.SevInfo} {
		if counts[s] > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", strings.ToUpper(string(s)), counts[s])
		}
	}
	if len(findings) == 0 {
		fmt.Fprintf(&b, "\n_No findings. The target resisted the executed checks._\n")
	}
	b.WriteString("\n")

	// findings
	if len(findings) > 0 {
		fmt.Fprintf(&b, "## Findings\n\n")
		for i, f := range findings {
			fmt.Fprintf(&b, "### %d. %s  \n", i+1, f.Title)
			fmt.Fprintf(&b, "**Severity:** %s", strings.ToUpper(string(f.Severity)))
			if f.OWASP != "" {
				fmt.Fprintf(&b, " · **OWASP:** %s", f.OWASP)
			}
			fmt.Fprintf(&b, " · **Phase:** %s\n\n", f.Phase)
			fmt.Fprintf(&b, "- **Evidence:** %s\n", f.Evidence)
			fmt.Fprintf(&b, "- **Impact:** %s\n", f.Impact)
			fmt.Fprintf(&b, "- **Remediation:** %s\n\n", f.Remediate)
		}
	}

	// surface + notes
	if len(st.Endpoints) > 0 {
		fmt.Fprintf(&b, "## Attack surface mapped\n\n| Path | Status |\n|---|---|\n")
		paths := make([]string, 0, len(st.Endpoints))
		for p := range st.Endpoints {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			fmt.Fprintf(&b, "| `%s` | %d |\n", p, st.Endpoints[p])
		}
		b.WriteString("\n")
	}
	if note := st.GetFact("destructive_admin_route"); note != "" {
		fmt.Fprintf(&b, "> **Note:** %s\n\n", note)
	}
	fmt.Fprintf(&b, "---\n_Non-destructive, scope-limited assessment. All actions were logged to the audit trail._\n")
	return b.String()
}

func Write(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}
