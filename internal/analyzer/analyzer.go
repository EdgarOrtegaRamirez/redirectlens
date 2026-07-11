package analyzer

import (
	"strings"

	"github.com/EdgarOrtegaRamirez/redirectlens/internal/checker"
	"github.com/EdgarOrtegaRamirez/redirectlens/internal/models"
)

// AnalyzeChain performs security and performance analysis on a redirect chain.
func AnalyzeChain(result *models.ChainResult) {
	var issues []models.Issue

	if result.IsLoop {
		issues = append(issues, models.Issue{
			Type:     models.IssueLoop,
			Severity: "critical",
			Message:  "Redirect loop detected — infinite loop would occur",
			URL:      result.URL,
		})
	}

	if len(result.Hops) == 0 {
		return
	}

	// Check for HTTPS downgrade
	hasHTTPS := false
	hasHTTP := false
	for _, hop := range result.Hops {
		if strings.HasPrefix(hop.URL, "https://") {
			hasHTTPS = true
		}
		if strings.HasPrefix(hop.URL, "http://") {
			hasHTTP = true
		}
	}

	if hasHTTPS && hasHTTP {
		issues = append(issues, models.Issue{
			Type:     models.IssueMixedContent,
			Severity: "warning",
			Message:  "Chain mixes HTTPS and HTTP — potential security risk",
			URL:      result.URL,
		})
	}

	// Check for HTTPS downgrade specifically (HTTPS -> HTTP transition)
	for i := 1; i < len(result.Hops); i++ {
		prev := result.Hops[i-1].URL
		curr := result.Hops[i].URL
		if strings.HasPrefix(prev, "https://") && strings.HasPrefix(curr, "http://") {
			issues = append(issues, models.Issue{
				Type:     models.IssueHTTPSDowngrade,
				Severity: "critical",
				Message:  "HTTPS to HTTP downgrade at hop " + string(rune('0'+i)),
				URL:      curr,
			})
			break
		}
	}

	// Check for excessive hops
	if len(result.Hops) > 10 {
		issues = append(issues, models.Issue{
			Type:     models.IssueExcessiveHops,
			Severity: "warning",
			Message:  "Redirect chain has " + string(rune(len(result.Hops)+'0')) + " hops (exceeds 10)",
			URL:      result.URL,
		})
	} else if len(result.Hops) > 5 {
		issues = append(issues, models.Issue{
			Type:     models.IssueLongChain,
			Severity: "info",
			Message:  "Redirect chain has " + string(rune(len(result.Hops)+'0')) + " hops (performance warning)",
			URL:      result.URL,
		})
	}

	// Check for open redirect patterns in any hop
	for _, hop := range result.Hops {
		if checker.CheckOpenRedirect(hop.URL) {
			issues = append(issues, models.Issue{
				Type:     models.IssueOpenRedirect,
				Severity: "warning",
				Message:  "URL contains potential open redirect parameter: " + hop.URL,
				URL:      hop.URL,
			})
			break // Only report once
		}
	}

	// Check for cookie leakage (redirect to different host)
	if len(result.Hops) > 1 {
		origHost := checker.GetHost(result.Hops[0].URL)
		for _, hop := range result.Hops[1:] {
			hopHost := checker.GetHost(hop.URL)
			if hopHost != "" && origHost != "" && hopHost != origHost {
				issues = append(issues, models.Issue{
					Type:     models.IssueCookieLeak,
					Severity: "info",
					Message:  "Redirect to different host " + hopHost + " — potential cookie leakage",
					URL:      hop.URL,
				})
				break // Only report once
			}
		}
	}

	// Check if final URL is secure
	if result.FinalURL != "" && !checker.IsSecure(result.FinalURL) {
		if !hasHTTPS {
			// All HTTP — not necessarily an issue, just informational
		}
	}

	result.Issues = issues
}

// HasSecurityIssues returns true if the chain has any critical or warning issues.
func HasSecurityIssues(result *models.ChainResult) bool {
	for _, issue := range result.Issues {
		if issue.Severity == "critical" || issue.Severity == "warning" {
			return true
		}
	}
	return false
}

// HasCriticalIssues returns true if the chain has any critical issues.
func HasCriticalIssues(result *models.ChainResult) bool {
	for _, issue := range result.Issues {
		if issue.Severity == "critical" {
			return true
		}
	}
	return false
}
