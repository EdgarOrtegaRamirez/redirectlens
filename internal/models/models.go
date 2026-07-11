package models

import "time"

// Hop represents a single redirect in a chain.
type Hop struct {
	Index          int       `json:"index"`
	URL            string    `json:"url"`
	StatusCode     int       `json:"status_code"`
	LocationHeader string    `json:"location,omitempty"`
	Duration       time.Duration `json:"duration"`
	Error          string    `json:"error,omitempty"`
}

// IssueType represents a category of security/performance issue.
type IssueType string

const (
	IssueNone            IssueType = "none"
	IssueLoop            IssueType = "redirect_loop"
	IssueHTTPSDowngrade  IssueType = "https_downgrade"
	IssueExcessiveHops   IssueType = "excessive_hops"
	IssueOpenRedirect    IssueType = "open_redirect"
	IssueCookieLeak      IssueType = "cookie_leak"
	IssueMixedContent    IssueType = "mixed_content"
	IssueLongChain       IssueType = "long_chain"
)

// Issue represents a security or performance concern detected in a chain.
type Issue struct {
	Type      IssueType `json:"type"`
	Severity  string    `json:"severity"` // "critical", "warning", "info"
	Message   string    `json:"message"`
	URL       string    `json:"url,omitempty"`
}

// ChainResult holds the complete analysis of a redirect chain.
type ChainResult struct {
	URL      string   `json:"url"`
	IsSecure bool     `json:"is_secure"`
	Hops     []Hop    `json:"hops"`
	Issues   []Issue  `json:"issues"`
	TotalDuration time.Duration `json:"total_duration"`
	FinalStatusCode int     `json:"final_status_code"`
	FinalURL   string   `json:"final_url"`
	IsLoop     bool     `json:"is_loop"`
}

// ChainResult represents the analysis of multiple URLs.
type ScanResult struct {
	URLs      []ChainResult `json:"urls"`
	Total     int           `json:"total"`
	Skipped   int           `json:"skipped"`
	Errors    int           `json:"errors"`
	SecurityIssues int      `json:"security_issues"`
}

// Config holds the tool's configuration.
type Config struct {
	MaxHops        int           `json:"max_hops"`
	Timeout        time.Duration `json:"timeout"`
	Workers        int           `json:"workers"`
	FollowRedirect bool          `json:"follow_redirects"`
	StrictMode     bool          `json:"strict"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxHops:        10,
		Timeout:        30 * time.Second,
		Workers:        5,
		FollowRedirect: true,
		StrictMode:     false,
	}
}
