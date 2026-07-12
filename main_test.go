package nvd

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func liveClient() *Client {
	return NewClient(
		WithCVEBaseURL(DefaultCVEBaseURL),
		WithCPEBaseURL(DefaultCPEBaseURL),
		WithHTTPClient(&http.Client{Timeout: 60 * time.Second}),
	)
}

func TestNewClientAndOptions(t *testing.T) {
	c := NewClient(
		WithHTTPClient(&http.Client{Timeout: 10 * time.Second}),
		WithCVEBaseURL(DefaultCVEBaseURL),
		WithCPEBaseURL(DefaultCPEBaseURL),
		WithAPIKey("test-key"),
	)

	if c.httpClient == nil {
		t.Fatal("httpClient is nil")
	}
	if c.cveBaseURL != DefaultCVEBaseURL {
		t.Fatalf("unexpected cveBaseURL: %s", c.cveBaseURL)
	}
	if c.cpeBaseURL != DefaultCPEBaseURL {
		t.Fatalf("unexpected cpeBaseURL: %s", c.cpeBaseURL)
	}
	if c.apiKey != "test-key" {
		t.Fatalf("unexpected apiKey: %s", c.apiKey)
	}
}

func TestSearchCves(t *testing.T) {
	c := liveClient()

	resp, err := c.SearchCves(Filter{
		CveID:          "CVE-2023-4863",
		ResultsPerPage: 1,
	})
	if err != nil {
		t.Fatalf("SearchCves failed: %v", err)
	}
	if resp == nil {
		t.Fatal("nil response")
	}
	if len(resp.Vulnerabilities) == 0 {
		t.Fatal("expected vulnerabilities")
	}
	if resp.Vulnerabilities[0].CVE.ID == "" {
		t.Fatal("expected CVE ID")
	}
}

func TestGetCVE(t *testing.T) {
	c := liveClient()

	cve, err := c.GetCVE("CVE-2023-4863")
	if err != nil {
		t.Fatalf("GetCVE failed: %v", err)
	}
	if cve == nil {
		t.Fatal("nil cve")
	}
	if cve.ID != "CVE-2023-4863" {
		t.Fatalf("unexpected CVE ID: %s", cve.ID)
	}
}

func TestSearchCpes(t *testing.T) {
	c := liveClient()

	resp, err := c.SearchCpes(Filter{
		ResultsPerPage: 5,
	})
	if err != nil {
		t.Fatalf("SearchCpes failed: %v", err)
	}
	if resp == nil {
		t.Fatal("nil response")
	}
	if len(resp.Products) == 0 {
		t.Fatal("expected products")
	}
}

func TestSearchCPEs(t *testing.T) {
	c := liveClient()

	cpes, err := c.SearchCPEs("")
	if err != nil {
		t.Fatalf("SearchCPEs failed: %v", err)
	}
	if len(cpes) == 0 {
		t.Fatal("expected CPEs")
	}
}

func TestSearchByKeyword(t *testing.T) {
	c := liveClient()

	cves, err := c.SearchByKeyword("openssl")
	if err != nil {
		t.Fatalf("SearchByKeyword failed: %v", err)
	}
	if len(cves) == 0 {
		t.Fatal("expected CVEs")
	}
}

/*func TestSearchByCPE(t *testing.T) {
	c := liveClient()

	cves, err := c.SearchByCPE("openssl")
	if err != nil {
		t.Fatalf("SearchByCPE failed: %v", err)
	}
	if len(cves) == 0 {
		t.Fatal("expected CVEs")
	}
}*/

func TestSearchByCWE(t *testing.T) {
	c := liveClient()

	cves, err := c.SearchByCWE("CWE-79")
	if err != nil {
		t.Fatalf("SearchByCWE failed: %v", err)
	}
	if len(cves) == 0 {
		t.Fatal("expected CVEs")
	}
}

func TestGetByDateRange(t *testing.T) {
	c := liveClient()

	cves, err := c.GetByDateRange("2023-01-01T00:00:00.000", "2023-01-31T23:59:59.999")
	if err != nil {
		t.Fatalf("GetByDateRange failed: %v", err)
	}
	if len(cves) == 0 {
		t.Fatal("expected CVEs")
	}
}

func TestGetBySeverity(t *testing.T) {
	c := liveClient()

	cves, err := c.GetBySeverity("HIGH")
	if err != nil {
		t.Fatalf("GetBySeverity failed: %v", err)
	}
	if len(cves) == 0 {
		t.Fatal("expected CVEs")
	}
}

/*func TestGetKevCatalog(t *testing.T) {
	c := liveClient()

	cves, err := c.GetKevCatalog()
	if err != nil {
		t.Fatalf("GetKevCatalog failed: %v", err)
	}
	if len(cves) == 0 {
		t.Fatal("expected CVEs")
	}
}*/

func TestGetAll(t *testing.T) {
	c := liveClient()

	cves, err := c.GetAll(5)
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}
	if len(cves) == 0 {
		t.Fatal("expected CVEs")
	}
	if len(cves) > 5 {
		t.Fatalf("expected at most 5 CVEs, got %d", len(cves))
	}
}

func TestExtractCVEs(t *testing.T) {
	c := liveClient()

	resp, err := c.SearchCves(Filter{
		CveID:          "CVE-2023-4863",
		ResultsPerPage: 1,
	})
	if err != nil {
		t.Fatalf("SearchCves failed: %v", err)
	}

	cves := extractCVEs(resp)
	if len(cves) != len(resp.Vulnerabilities) {
		t.Fatalf("expected %d CVEs, got %d", len(resp.Vulnerabilities), len(cves))
	}
	if len(cves) == 0 {
		t.Fatal("expected at least one CVE")
	}
}

func TestGetDescription(t *testing.T) {
	c := liveClient()

	cve, err := c.GetCVE("CVE-2023-4863")
	if err != nil {
		t.Fatalf("GetCVE failed: %v", err)
	}

	desc := GetDescription(cve)
	if desc == "" {
		t.Fatal("expected description")
	}
}

func TestGetCVSSV3Score(t *testing.T) {
	c := liveClient()

	cve, err := c.GetCVE("CVE-2023-4863")
	if err != nil {
		t.Fatalf("GetCVE failed: %v", err)
	}

	score := GetCVSSV3Score(cve)
	if score < 0 {
		t.Fatalf("invalid score: %v", score)
	}
}

func TestGetCVSSV3Severity(t *testing.T) {
	c := liveClient()

	cve, err := c.GetCVE("CVE-2023-4863")
	if err != nil {
		t.Fatalf("GetCVE failed: %v", err)
	}

	severity := GetCVSSV3Severity(cve)
	if severity == "" {
		t.Fatal("expected severity")
	}
}

func TestGetCWEs(t *testing.T) {
	c := liveClient()

	cve, err := c.GetCVE("CVE-2023-4863")
	if err != nil {
		t.Fatalf("GetCVE failed: %v", err)
	}

	cwes := GetCWEs(cve)
	for _, cwe := range cwes {
		if !strings.HasPrefix(cwe, "CWE-") {
			t.Fatalf("unexpected CWE value: %s", cwe)
		}
	}
}

func TestSearchCves_WithAllFilters(t *testing.T) {
	c := liveClient()

	kev := true
	certAlerts := false
	certNotes := false
	vuln := true

	f := Filter{
		CveID:             "CVE-2023-4863",
		CpeName:           "openssl",
		CvssV2Severity:    "HIGH",
		CvssV3Severity:    "HIGH",
		CvssV4Severity:    "HIGH",
		CweID:             "CWE-79",
		KeywordSearch:     "openssl",
		KeywordExactMatch: true,
		PubStartDate:      "2023-01-01T00:00:00.000",
		PubEndDate:        "2023-12-31T23:59:59.999",
		LastModStartDate:  "2023-01-01T00:00:00.000",
		LastModEndDate:    "2023-12-31T23:59:59.999",
		HasKev:            &kev,
		HasCertAlerts:     &certAlerts,
		HasCertNotes:      &certNotes,
		IsVulnerable:      &vuln,
		ResultsPerPage:    1,
		StartIndex:        1,
	}

	_, _ = c.SearchCves(f)
}
