package checker

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/EdgarOrtegaRamirez/redirectlens/internal/models"
)

// Checker follows HTTP redirect chains and collects hop details.
type Checker struct {
	client  *http.Client
	maxHops int
	timeout time.Duration
}

// NewChecker creates a new Checker with the given config.
func NewChecker(maxHops int, timeout time.Duration) *Checker {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxHops {
				return fmt.Errorf("stopped after %d redirects", maxHops)
			}
			// Stop at 3xx if we've reached max hops
			return http.ErrUseLastResponse
		},
		Timeout: timeout,
	}

	return &Checker{
		client:  client,
		maxHops: maxHops,
		timeout: timeout,
	}
}

// FollowChain follows the redirect chain for a URL and returns all hops.
func (c *Checker) FollowChain(url string) (*models.ChainResult, error) {
	result := &models.ChainResult{
		URL: url,
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid URL %q: %w", url, err)
	}
	req.Header.Set("User-Agent", "redirectlens/1.0.0")

	hops := make([]models.Hop, 0, c.maxHops)
	visitedURLs := make(map[string]bool)
	visitedURLs[url] = true

	currentURL := url
	var totalDuration time.Duration
	var finalStatusCode int
	var finalURL string
	isLoop := false

	for i := 0; i <= c.maxHops; i++ {
		start := time.Now()

		resp, err := c.client.Do(req)
		hopDuration := time.Since(start)
		totalDuration += hopDuration

		if err != nil {
			hops = append(hops, models.Hop{
				Index:      i,
				URL:        currentURL,
				StatusCode: finalStatusCode,
				Duration:   hopDuration,
				Error:      err.Error(),
			})
			result.Hops = hops
			result.TotalDuration = totalDuration
			result.FinalStatusCode = finalStatusCode
			result.FinalURL = finalURL
			return result, fmt.Errorf("request failed at hop %d (%s): %w", i, currentURL, err)
		}

		resp.Body.Close()

		hops = append(hops, models.Hop{
			Index:          i,
			URL:            currentURL,
			StatusCode:     resp.StatusCode,
			LocationHeader: resp.Header.Get("Location"),
			Duration:       hopDuration,
		})

		finalStatusCode = resp.StatusCode
		finalURL = currentURL

		// Not a redirect — chain is complete
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			break
		}

		// Check for redirect loop
		location := resp.Header.Get("Location")
		if location == "" {
			break
		}

		// Resolve relative URLs
		nextURL, err := resolveURL(currentURL, location)
		if err != nil {
			hops[len(hops)-1].Error = fmt.Sprintf("invalid redirect URL: %v", err)
			result.Hops = hops
			result.TotalDuration = totalDuration
			result.FinalStatusCode = finalStatusCode
			result.FinalURL = finalURL
			return result, fmt.Errorf("invalid redirect URL at hop %d: %w", i, err)
		}

		if visitedURLs[nextURL] {
			isLoop = true
			hops = append(hops, models.Hop{
				Index:      i + 1,
				URL:        nextURL,
				StatusCode: 0,
				Duration:   0,
				Error:      "redirect loop detected",
			})
			result.Hops = hops
			result.TotalDuration = totalDuration
			result.FinalStatusCode = finalStatusCode
			result.FinalURL = finalURL
			result.IsLoop = true
			return result, nil
		}

		visitedURLs[nextURL] = true
		currentURL = nextURL

		// Create new request for next hop
		req, err = http.NewRequest("GET", currentURL, nil)
		if err != nil {
			return nil, fmt.Errorf("invalid URL at hop %d: %w", i, err)
		}
		req.Header.Set("User-Agent", "redirectlens/1.0.0")
	}

	result.Hops = hops
	result.TotalDuration = totalDuration
	result.FinalStatusCode = finalStatusCode
	result.FinalURL = finalURL
	result.IsLoop = isLoop

	return result, nil
}

// resolveURL resolves a relative URL against a base URL.
func resolveURL(base, relative string) (string, error) {
	// If already absolute, return as-is
	if strings.HasPrefix(relative, "http://") || strings.HasPrefix(relative, "https://") {
		return relative, nil
	}
	// Handle protocol-relative URLs
	if strings.HasPrefix(relative, "//") {
		return "https:" + relative, nil
	}

	// Parse base and join
	baseParsed, err := parseBaseURL(base)
	if err != nil {
		return "", err
	}

	if strings.HasPrefix(relative, "/") {
		return baseParsed.scheme + "://" + baseParsed.host + relative, nil
	}

	return baseParsed.scheme + "://" + baseParsed.host + "/" + baseParsed.path + relative, nil
}

type baseURL struct {
	scheme string
	host   string
	path   string
}

func parseBaseURL(url string) (*baseURL, error) {
	scheme := "https"
	host := ""
	path := ""

	// Find scheme
	if idx := strings.Index(url, "://"); idx != -1 {
		scheme = url[:idx]
		url = url[idx+3:]
	} else if strings.HasPrefix(url, "http://") {
		scheme = "http"
		url = url[7:]
	} else if strings.HasPrefix(url, "https://") {
		scheme = "https"
		url = url[8:]
	}

	// Find host and path
	slashIdx := strings.Index(url, "/")
	if slashIdx != -1 {
		host = url[:slashIdx]
		path = url[slashIdx:]
	} else {
		host = url
		path = "/"
	}

	return &baseURL{scheme: scheme, host: host, path: path}, nil
}

// IsSecure checks if the final URL uses HTTPS.
func IsSecure(url string) bool {
	return strings.HasPrefix(url, "https://")
}

// GetHost extracts the host from a URL.
func GetHost(url string) string {
	parsed, err := parseBaseURL(url)
	if err != nil {
		return ""
	}
	return parsed.host
}

// CheckOpenRedirect checks if the URL looks like an open redirect vulnerability.
func CheckOpenRedirect(url string) bool {
	lower := strings.ToLower(url)
	openRedirectPatterns := []string{
		"redirect=", "url=", "next=", "return=", "goto=", "dest=",
		"destination=", "r=", "redir=", "path=", "uri=",
	}
	for _, pattern := range openRedirectPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}
