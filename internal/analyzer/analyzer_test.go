package analyzer

import (
	"testing"
	"time"

	"github.com/EdgarOrtegaRamirez/redirectlens/internal/models"
)

func TestAnalyzeChain_NoIssues(t *testing.T) {
	result := &models.ChainResult{
		URL: "https://example.com",
		Hops: []models.Hop{
			{Index: 0, URL: "https://example.com", StatusCode: 200, Duration: time.Millisecond},
		},
	}

	AnalyzeChain(result)

	if len(result.Issues) != 0 {
		t.Errorf("expected no issues, got %d", len(result.Issues))
	}
}

func TestAnalyzeChain_LoopDetected(t *testing.T) {
	result := &models.ChainResult{
		URL:    "https://example.com/loop",
		IsLoop: true,
		Hops: []models.Hop{
			{Index: 0, URL: "https://example.com/loop", StatusCode: 302},
			{Index: 1, URL: "https://example.com/loop", StatusCode: 0, Error: "redirect loop detected"},
		},
	}

	AnalyzeChain(result)

	if len(result.Issues) == 0 {
		t.Fatal("expected at least one issue for loop")
	}

	found := false
	for _, issue := range result.Issues {
		if issue.Type == models.IssueLoop {
			found = true
			if issue.Severity != "critical" {
				t.Errorf("expected critical severity for loop, got %s", issue.Severity)
			}
		}
	}

	if !found {
		t.Error("expected loop issue type")
	}
}

func TestAnalyzeChain_HTTPSDowngrade(t *testing.T) {
	result := &models.ChainResult{
		URL: "https://example.com",
		Hops: []models.Hop{
			{Index: 0, URL: "https://example.com", StatusCode: 301, Duration: time.Millisecond},
			{Index: 1, URL: "http://example.com", StatusCode: 200, Duration: time.Millisecond},
		},
	}

	AnalyzeChain(result)

	foundDowngrade := false
	for _, issue := range result.Issues {
		if issue.Type == models.IssueHTTPSDowngrade {
			foundDowngrade = true
		}
	}

	if !foundDowngrade {
		t.Error("expected HTTPS downgrade issue")
	}
}

func TestAnalyzeChain_ExcessiveHops(t *testing.T) {
	hops := make([]models.Hop, 12)
	for i := 0; i < 12; i++ {
		hops[i] = models.Hop{
			Index:      i,
			URL:        "https://example.com/hop" + string(rune('0'+i)),
			StatusCode: 301,
		}
	}

	result := &models.ChainResult{
		URL:  "https://example.com",
		Hops: hops,
	}

	AnalyzeChain(result)

	found := false
	for _, issue := range result.Issues {
		if issue.Type == models.IssueExcessiveHops {
			found = true
		}
	}

	if !found {
		t.Error("expected excessive hops issue")
	}
}

func TestAnalyzeChain_OpenRedirect(t *testing.T) {
	result := &models.ChainResult{
		URL: "https://example.com",
		Hops: []models.Hop{
			{Index: 0, URL: "https://example.com/page?redirect=http://evil.com", StatusCode: 200, Duration: time.Millisecond},
		},
	}

	AnalyzeChain(result)

	found := false
	for _, issue := range result.Issues {
		if issue.Type == models.IssueOpenRedirect {
			found = true
		}
	}

	if !found {
		t.Error("expected open redirect issue")
	}
}

func TestAnalyzeChain_CookieLeak(t *testing.T) {
	result := &models.ChainResult{
		URL: "https://example.com",
		Hops: []models.Hop{
			{Index: 0, URL: "https://example.com", StatusCode: 301, Duration: time.Millisecond},
			{Index: 1, URL: "https://different.com", StatusCode: 200, Duration: time.Millisecond},
		},
	}

	AnalyzeChain(result)

	found := false
	for _, issue := range result.Issues {
		if issue.Type == models.IssueCookieLeak {
			found = true
		}
	}

	if !found {
		t.Error("expected cookie leak issue")
	}
}

func TestHasSecurityIssues(t *testing.T) {
	result := &models.ChainResult{
		Issues: []models.Issue{
			{Type: models.IssueLoop, Severity: "critical", Message: "loop"},
		},
	}

	if !HasSecurityIssues(result) {
		t.Error("expected security issues detected")
	}
}

func TestHasSecurityIssues_None(t *testing.T) {
	result := &models.ChainResult{
		Issues: []models.Issue{
			{Type: models.IssueNone, Severity: "info", Message: "long chain"},
		},
	}

	if HasSecurityIssues(result) {
		t.Error("expected no security issues for info only")
	}
}

func TestHasCriticalIssues(t *testing.T) {
	result := &models.ChainResult{
		Issues: []models.Issue{
			{Type: models.IssueHTTPSDowngrade, Severity: "critical", Message: "downgrade"},
		},
	}

	if !HasCriticalIssues(result) {
		t.Error("expected critical issues detected")
	}
}

func TestHasCriticalIssues_None(t *testing.T) {
	result := &models.ChainResult{
		Issues: []models.Issue{
			{Type: models.IssueLongChain, Severity: "info", Message: "long"},
		},
	}

	if HasCriticalIssues(result) {
		t.Error("expected no critical issues")
	}
}
