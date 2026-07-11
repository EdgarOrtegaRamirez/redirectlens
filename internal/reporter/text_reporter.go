package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/redirectlens/internal/analyzer"
	"github.com/EdgarOrtegaRamirez/redirectlens/internal/models"
	"github.com/fatih/color"
)

var (
	criticalColor = color.New(color.FgRed, color.Bold)
	warningColor  = color.New(color.FgYellow, color.Bold)
	infoColor     = color.New(color.FgBlue)
	greenColor    = color.New(color.FgGreen)
	whiteColor    = color.New(color.FgWhite)
	grayColor     = color.New(color.FgBlack)
)

// TextReporter outputs human-readable, colorized text.
type TextReporter struct{}

func (r *TextReporter) Report(result *models.ChainResult) error {
	fmt.Println()

	// URL header
	fmt.Printf("%s\n", whiteColor.Sprintf("URL: %s", result.URL))

	// Chain visualization
	fmt.Printf("%s\n", whiteColor.Sprintf("Chain: %d hops", len(result.Hops)))
	for i, hop := range result.Hops {
		status := hop.StatusCode
		if status == 0 {
			fmt.Printf("  %d. %s\n", i, grayColor.Sprintf("[loop detected] %s", hop.URL))
		} else {
			fmt.Printf("  %d. %3d %s (%s)\n", i, status, hop.URL, hop.Duration.Round(10*time.Millisecond))
		}
	}

	// Final result
	fmt.Printf("%s\n", whiteColor.Sprintf("Final: %d %s", result.FinalStatusCode, result.FinalURL))
	fmt.Printf("%s\n", whiteColor.Sprintf("Total time: %s", result.TotalDuration.Round(time.Millisecond)))

	// Issues
	if len(result.Issues) > 0 {
		fmt.Printf("\n%s\n", whiteColor.Sprint("Issues:"))
		for _, issue := range result.Issues {
			switch issue.Severity {
			case "critical":
				criticalColor.Printf("  ✗ [%s] %s\n", strings.ToUpper(issue.Severity), issue.Message)
			case "warning":
				warningColor.Printf("  ⚠ [%s] %s\n", strings.ToUpper(issue.Severity), issue.Message)
			default:
				infoColor.Printf("  ℹ [%s] %s\n", strings.ToUpper(issue.Severity), issue.Message)
			}
		}
	} else {
		greenColor.Println("✓ No issues detected")
	}

	fmt.Println()
	return nil
}

// JSONReporter outputs machine-readable JSON.
type JSONReporter struct{}

func (r *JSONReporter) Report(result *models.ChainResult) error {
	// Add a summary field
	output := struct {
		URL               string             `json:"url"`
		IsSecure          bool               `json:"is_secure"`
		IsLoop            bool               `json:"is_loop"`
		Hops              []models.Hop       `json:"hops"`
		Issues            []models.Issue     `json:"issues"`
		TotalDuration     string             `json:"total_duration"`
		FinalStatusCode   int                `json:"final_status_code"`
		FinalURL          string             `json:"final_url"`
		HasSecurityIssues bool               `json:"has_security_issues"`
	}{
		URL:               result.URL,
		IsSecure:          checkerIsSecure(result.FinalURL),
		IsLoop:            result.IsLoop,
		Hops:              result.Hops,
		Issues:            result.Issues,
		TotalDuration:     result.TotalDuration.String(),
		FinalStatusCode:   result.FinalStatusCode,
		FinalURL:          result.FinalURL,
		HasSecurityIssues: analyzer.HasSecurityIssues(result),
	}

	data, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// CSVReporter outputs CSV format.
type CSVReporter struct{}

func (r *CSVReporter) Report(result *models.ChainResult) error {
	// Header
	fmt.Println("url,is_loop,total_hops,total_duration_ms,final_status,final_url,has_security_issues,issues")

	// Build issues string
	issueStrs := make([]string, 0, len(result.Issues))
	for _, issue := range result.Issues {
		issueStrs = append(issueStrs, string(issue.Type))
	}
	issuesStr := strings.Join(issueStrs, ";")

	fmt.Printf("%s,%t,%d,%d,%d,%s,%t,%s\n",
		result.URL,
		result.IsLoop,
		len(result.Hops),
		result.TotalDuration.Milliseconds(),
		result.FinalStatusCode,
		result.FinalURL,
		analyzer.HasSecurityIssues(result),
		issuesStr,
	)
	return nil
}

// ScanReporter reports for batch scans.
func ReportScan(results *models.ScanResult, format string) error {
	switch format {
	case "text":
		fmt.Printf("\nScan complete: %d URLs checked, %d skipped, %d errors, %d with security issues\n",
			results.Total, results.Skipped, results.Errors, results.SecurityIssues)
		for _, r := range results.URLs {
			fmt.Printf("  %s — %d hops, %s\n", r.URL, len(r.Hops), r.FinalURL)
			if analyzer.HasSecurityIssues(&r) {
				warningColor.Printf("    ⚠ Security issues detected\n")
			}
		}
	case "json":
		data, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}
		fmt.Println(string(data))
	case "csv":
		fmt.Println("url,total_hops,total_duration_ms,final_status,final_url,has_security_issues,issues")
		for _, r := range results.URLs {
			issueStrs := make([]string, 0, len(r.Issues))
			for _, issue := range r.Issues {
				issueStrs = append(issueStrs, string(issue.Type))
			}
			issuesStr := strings.Join(issueStrs, ";")
			fmt.Printf("%s,%d,%d,%d,%s,%t,%s\n",
				r.URL, len(r.Hops), r.TotalDuration.Milliseconds(),
				r.FinalStatusCode, r.FinalURL,
				analyzer.HasSecurityIssues(&r), issuesStr,
			)
		}
	}
	return nil
}

// WriteToFile writes content to a file.
func WriteToFile(content string, path string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

// checkerIsSecure is a local copy to avoid import cycle.
func checkerIsSecure(url string) bool {
	return strings.HasPrefix(url, "https://")
}
