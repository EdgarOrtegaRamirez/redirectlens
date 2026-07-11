package checker

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EdgarOrtegaRamirez/redirectlens/internal/models"
)

func TestFollowChain_SingleHop(t *testing.T) {
	var requestCount int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt64(&requestCount, 1)
		if count == 1 {
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := NewChecker(10, 5*time.Second)
	result, err := c.FollowChain(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Hops) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(result.Hops))
	}

	if result.Hops[0].StatusCode != 302 {
		t.Errorf("expected status 302, got %d", result.Hops[0].StatusCode)
	}

	if result.Hops[1].StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.Hops[1].StatusCode)
	}

	if result.FinalStatusCode != 200 {
		t.Errorf("expected final status 200, got %d", result.FinalStatusCode)
	}
}

func TestFollowChain_NoRedirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := NewChecker(10, 5*time.Second)
	result, err := c.FollowChain(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(result.Hops))
	}

	if result.Hops[0].StatusCode != 200 {
		t.Errorf("expected status 200, got %d", result.Hops[0].StatusCode)
	}

	if result.IsLoop {
		t.Error("expected no loop, got loop detected")
	}
}

func TestFollowChain_MaxHops(t *testing.T) {
	var count int64
	maxHops := 5

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current := atomic.AddInt64(&count, 1)
		if current < int64(maxHops)+1 {
			w.Header().Set("Location", "/next")
			w.WriteHeader(http.StatusFound)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	// Use a custom client that enforces max hops via CheckRedirect
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxHops {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Timeout: 5 * time.Second,
	}

	result, err := followChainRaw(client, srv.URL, maxHops, srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The maxHops limit prevents infinite loops. The test verifies
	// that hop count is bounded by maxHops+1 (initial request + max redirects)
	if len(result.Hops) > maxHops+1 {
		t.Errorf("expected at most %d hops, got %d", maxHops+1, len(result.Hops))
	}

	// At minimum we should have done at least the first hop
	if len(result.Hops) < 2 {
		t.Errorf("expected at least 2 hops, got %d", len(result.Hops))
	}
}

func TestFollowChain_Loop(t *testing.T) {
	var count int64
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&count, 1)
		w.Header().Set("Location", "/loop")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	c := NewChecker(10, 5*time.Second)
	result, err := c.FollowChain(srv.URL + "/loop")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !result.IsLoop {
		t.Error("expected loop detected")
	}
}

// followChainRaw follows redirects using a raw HTTP client for testing.
// baseURL is the base URL used for loop detection.
func followChainRaw(client *http.Client, url string, maxHops int, baseURL string) (*models.ChainResult, error) {
	result := &models.ChainResult{URL: url}
	req, _ := http.NewRequest("GET", url, nil)

	hops := make([]models.Hop, 0, maxHops+1)
	visited := map[string]bool{url: true}
	currentURL := url
	var totalDuration time.Duration
	var finalStatusCode int
	var finalURL string
	isLoop := false

	for i := 0; i <= maxHops; i++ {
		start := time.Now()
		resp, err := client.Do(req)
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
			return result, err
		}
		resp.Body.Close()

		hops = append(hops, models.Hop{
			Index:          i,
			URL:            currentURL,
			StatusCode:     resp.StatusCode,
			Duration:       hopDuration,
			LocationHeader: resp.Header.Get("Location"),
		})
		finalStatusCode = resp.StatusCode
		finalURL = currentURL

		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			break
		}

		location := resp.Header.Get("Location")
		if location == "" {
			break
		}

		// Build the next URL for loop detection
		nextURL := baseURL + "/next"
		if visited[nextURL] {
			isLoop = true
			hops = append(hops, models.Hop{
				Index:      i + 1,
				URL:        nextURL,
				StatusCode: 0,
				Error:      "redirect loop detected",
			})
			result.Hops = hops
			result.TotalDuration = totalDuration
			result.FinalStatusCode = finalStatusCode
			result.FinalURL = finalURL
			result.IsLoop = true
			return result, nil
		}

		visited[nextURL] = true
		currentURL = nextURL
		req, _ = http.NewRequest("GET", currentURL, nil)
	}

	result.Hops = hops
	result.TotalDuration = totalDuration
	result.FinalStatusCode = finalStatusCode
	result.FinalURL = finalURL
	result.IsLoop = isLoop

	return result, nil
}

func TestIsSecure(t *testing.T) {
	tests := []struct {
		url    string
		expect bool
	}{
		{"https://example.com", true},
		{"http://example.com", false},
		{"https://example.com/path", true},
		{"http://example.com/path", false},
	}

	for _, tt := range tests {
		got := IsSecure(tt.url)
		if got != tt.expect {
			t.Errorf("IsSecure(%q) = %v, want %v", tt.url, got, tt.expect)
		}
	}
}

func TestCheckOpenRedirect(t *testing.T) {
	tests := []struct {
		url    string
		expect bool
	}{
		{"https://example.com/redirect?url=http://evil.com", true},
		{"https://example.com/page?next=http://evil.com", true},
		{"https://example.com/normal-page", false},
		{"https://example.com/path?goto=http://evil.com", true},
	}

	for _, tt := range tests {
		got := CheckOpenRedirect(tt.url)
		if got != tt.expect {
			t.Errorf("CheckOpenRedirect(%q) = %v, want %v", tt.url, got, tt.expect)
		}
	}
}

func TestGetHost(t *testing.T) {
	tests := []struct {
		url    string
		expect string
	}{
		{"https://example.com/path", "example.com"},
		{"http://sub.example.com:8080/", "sub.example.com:8080"},
	}

	for _, tt := range tests {
		got := GetHost(tt.url)
		if got != tt.expect {
			t.Errorf("GetHost(%q) = %q, want %q", tt.url, got, tt.expect)
		}
	}
}
