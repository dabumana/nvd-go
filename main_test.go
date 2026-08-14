package nvd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// testCVEJSON mirrors the real /cves/2.0 response shape and exercises every
// CVE object field supported by the client.
const testCVEJSON = `{
  "resultsPerPage": 1,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2026-08-14T00:00:00.000",
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2023-4863",
        "sourceIdentifier": "chrome-cve-admin@google.com",
        "published": "2023-09-12T15:15:24.327",
        "lastModified": "2026-06-17T06:38:46.547",
        "vulnStatus": "Analyzed",
        "cveTags": [
          {"sourceIdentifier": "cisa@example.gov", "tags": ["kev"]}
        ],
        "descriptions": [
          {"lang": "en", "value": "Heap buffer overflow in libwebp."},
          {"lang": "es", "value": "Desbordamiento de bufer."}
        ],
        "affected": [
          {
            "source": "chrome-cve-admin@google.com",
            "affectedData": [
              {
                "vendor": "Google",
                "product": "Chrome",
                "versions": [
                  {"version": "116.0.5845.187", "lessThan": "116.0.5845.187", "versionType": "custom", "status": "affected"}
                ]
              }
            ]
          }
        ],
        "metrics": {
          "cvssMetricV2": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "2.0",
                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "accessVector": "NETWORK",
                "accessComplexity": "LOW",
                "authentication": "NONE",
                "confidentialityImpact": "PARTIAL",
                "integrityImpact": "PARTIAL",
                "availabilityImpact": "PARTIAL",
                "baseScore": 7.5
              },
              "baseSeverity": "HIGH",
              "exploitabilityScore": 10.0,
              "impactScore": 6.4,
              "acInsufInfo": false,
              "obtainAllPrivilege": false,
              "obtainUserPrivilege": false,
              "obtainOtherPrivilege": false,
              "userInteractionRequired": false
            }
          ],
          "cvssMetricV31": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "3.1",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                "baseScore": 8.8,
                "baseSeverity": "HIGH",
                "attackVector": "NETWORK",
                "attackComplexity": "LOW",
                "privilegesRequired": "NONE",
                "userInteraction": "REQUIRED",
                "scope": "UNCHANGED",
                "confidentialityImpact": "HIGH",
                "integrityImpact": "HIGH",
                "availabilityImpact": "HIGH"
              },
              "exploitabilityScore": 2.8,
              "impactScore": 5.9
            }
          ],
          "cvssMetricV40": [
            {
              "source": "nvd@nist.gov",
              "type": "Primary",
              "cvssData": {
                "version": "4.0",
                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                "baseScore": 10.0,
                "baseSeverity": "CRITICAL",
                "attackVector": "NETWORK",
                "attackComplexity": "LOW",
                "attackRequirements": "NONE",
                "privilegesRequired": "NONE",
                "userInteraction": "NONE",
                "vulnConfidentialityImpact": "HIGH",
                "vulnIntegrityImpact": "HIGH",
                "vulnAvailabilityImpact": "HIGH",
                "subConfidentialityImpact": "NONE",
                "subIntegrityImpact": "NONE",
                "subAvailabilityImpact": "NONE"
              }
            }
          ],
          "ssvcV203": [
            {
              "source": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
              "ssvcData": {
                "timestamp": "2023-11-28T05:00:18.341149Z",
                "id": "CVE-2023-4863",
                "options": [
                  {"exploitation": "active"},
                  {"automatable": "no"},
                  {"technicalImpact": "total"}
                ],
                "role": "CISA Coordinator",
                "version": "2.0.3"
              }
            }
          ]
        },
        "cisaExploitAdd": "2023-09-13",
        "cisaActionDue": "2023-10-04",
        "cisaRequiredAction": "Apply mitigations per vendor instructions.",
        "cisaVulnerabilityName": "Google Chromium WebP Heap-Based Buffer Overflow Vulnerability",
        "weaknesses": [
          {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-787"}]}
        ],
        "configurations": [
          {
            "nodes": [
              {
                "operator": "OR",
                "negate": false,
                "cpeMatch": [
                  {
                    "vulnerable": true,
                    "criteria": "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
                    "versionEndExcluding": "116.0.5845.187",
                    "matchCriteriaId": "856C1821-5D22-4A4E-859D-8F5305255AB7"
                  }
                ]
              }
            ]
          }
        ],
        "references": [
          {
            "url": "http://www.openwall.com/lists/oss-security/2023/09/21/4",
            "source": "chrome-cve-admin@google.com",
            "tags": ["Mailing List"]
          }
        ]
      }
    }
  ]
}`

// testCPEJSON mirrors the real /cpes/2.0 response shape.
const testCPEJSON = `{
  "resultsPerPage": 2,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_CPE",
  "version": "2.0",
  "timestamp": "2026-08-14T00:00:00.000",
  "products": [
    {
      "cpe": {
        "deprecated": false,
        "cpeName": "cpe:2.3:a:3com:3cdaemon:-:*:*:*:*:*:*:*",
        "cpeNameId": "BAE41D20-D4AF-4AF0-AA7D-3BD04DA402A7",
        "lastModified": "2011-01-12T14:35:43.723",
        "created": "2007-08-23T21:05:57.937",
        "titles": [
          {"title": "3Com 3CDaemon", "lang": "en"},
          {"title": "3Com 3CDaemon", "lang": "ja"}
        ]
      }
    }
  ]
}`

// testSourceJSON mirrors the real /source/2.0 response shape.
const testSourceJSON = `{
  "resultsPerPage": 2,
  "startIndex": 0,
  "totalResults": 1,
  "format": "NVD_SOURCE",
  "version": "2.0",
  "timestamp": "2026-08-14T00:00:00.000",
  "sources": [
    {
      "name": "MITRE",
      "contactEmail": "cve@mitre.org",
      "sourceIdentifiers": ["cve@mitre.org", "8254265b-2729-46b6-b9e3-3dfca2d5bfca"],
      "lastModified": "2019-09-09T16:18:45.930",
      "created": "2019-09-09T16:18:45.930",
      "v3AcceptanceLevel": {"description": "Contributor", "lastModified": "2026-07-21T00:00:26.043"},
      "cweAcceptanceLevel": {"description": "Provider", "lastModified": "2026-07-08T00:00:00.157"}
    }
  ]
}`

const testEmptyCVEResponse = `{
  "resultsPerPage": 0,
  "startIndex": 0,
  "totalResults": 0,
  "format": "NVD_CVE",
  "version": "2.0",
  "timestamp": "2026-08-14T00:00:00.000",
  "vulnerabilities": []
}`

// newTestServer starts an httptest server with the given handler.
func newTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// testClient builds a Client pointed at a test server with optional options.
func testClient(srv *httptest.Server, opts ...Option) *Client {
	base := []Option{
		WithHTTPClient(srv.Client()),
		WithCVEBaseURL(srv.URL + "/cves/2.0"),
		WithCPEBaseURL(srv.URL + "/cpes/2.0"),
		WithSourceBaseURL(srv.URL + "/source/2.0"),
	}
	return NewClient(append(base, opts...)...)
}

func assertQueryParam(t *testing.T, q url.Values, key, want string) {
	t.Helper()
	if got := q.Get(key); got != want {
		t.Errorf("query param %q = %q, want %q", key, got, want)
	}
}

func TestNewClientAndOptions(t *testing.T) {
	c := NewClient()
	if c.httpClient == nil {
		t.Fatal("httpClient is nil")
	}
	if c.cveBaseURL != DefaultCVEBaseURL {
		t.Fatalf("unexpected cveBaseURL: %s", c.cveBaseURL)
	}
	if c.cpeBaseURL != DefaultCPEBaseURL {
		t.Fatalf("unexpected cpeBaseURL: %s", c.cpeBaseURL)
	}
	if c.sourceBaseURL != DefaultSourceBaseURL {
		t.Fatalf("unexpected sourceBaseURL: %s", c.sourceBaseURL)
	}
	if c.apiKey != "" {
		t.Fatalf("unexpected apiKey: %s", c.apiKey)
	}
	if c.requestDelay != 0 {
		t.Fatalf("unexpected requestDelay: %s", c.requestDelay)
	}

	c = NewClient(
		WithHTTPClient(&http.Client{Timeout: 10 * time.Second}),
		WithCVEBaseURL("http://example.test/cves"),
		WithCPEBaseURL("http://example.test/cpes"),
		WithSourceBaseURL("http://example.test/source"),
		WithAPIKey("test-key"),
		WithRequestDelay(6*time.Second),
	)
	if c.httpClient.Timeout != 10*time.Second {
		t.Fatalf("unexpected httpClient timeout: %s", c.httpClient.Timeout)
	}
	if c.cveBaseURL != "http://example.test/cves" {
		t.Fatalf("unexpected cveBaseURL: %s", c.cveBaseURL)
	}
	if c.cpeBaseURL != "http://example.test/cpes" {
		t.Fatalf("unexpected cpeBaseURL: %s", c.cpeBaseURL)
	}
	if c.sourceBaseURL != "http://example.test/source" {
		t.Fatalf("unexpected sourceBaseURL: %s", c.sourceBaseURL)
	}
	if c.apiKey != "test-key" {
		t.Fatalf("unexpected apiKey: %s", c.apiKey)
	}
	if c.requestDelay != 6*time.Second {
		t.Fatalf("unexpected requestDelay: %s", c.requestDelay)
	}
}

func TestSearchCves_AllFilters(t *testing.T) {
	kev, certAlerts, certNotes := true, false, true
	hasOval, vulnerable, noRejected := false, true, true
	f := Filter{
		CveID:              "CVE-2023-4863",
		CpeName:            "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*",
		CvssV2Severity:     "HIGH",
		CvssV2Metrics:      "AV:N/AC:L/Au:N/C:P/I:P/A:P",
		CvssV3Severity:     "HIGH",
		CvssV3Metrics:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		CvssV4Severity:     "CRITICAL",
		CvssV4Metrics:      "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
		CweID:              "CWE-79",
		KeywordSearch:      "openssl",
		KeywordExactMatch:  true,
		PubStartDate:       "2023-01-01T00:00:00.000",
		PubEndDate:         "2023-12-31T23:59:59.999",
		LastModStartDate:   "2023-01-01T00:00:00.000",
		LastModEndDate:     "2023-12-31T23:59:59.999",
		SourceIdentifier:   "nvd@nist.gov",
		HasKev:             &kev,
		HasCertAlerts:      &certAlerts,
		HasCertNotes:       &certNotes,
		HasOval:            &hasOval,
		IsVulnerable:       &vulnerable,
		VirtualMatchString: "cpe:2.3:a:microsoft:windows_11:*:*:*:*:*:*:*:*",
		NoRejected:         &noRejected,
		ResultsPerPage:     10,
		StartIndex:         5,
	}

	var got url.Values
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testCVEJSON)
	})
	c := testClient(srv)

	resp, err := c.SearchCves(f)
	if err != nil {
		t.Fatalf("SearchCves failed: %v", err)
	}
	if resp.TotalResults != 1 || len(resp.Vulnerabilities) != 1 {
		t.Fatalf("unexpected response: total=%d vulns=%d", resp.TotalResults, len(resp.Vulnerabilities))
	}

	assertQueryParam(t, got, "cveId", "CVE-2023-4863")
	assertQueryParam(t, got, "cpeName", "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*")
	assertQueryParam(t, got, "cvssV2Severity", "HIGH")
	assertQueryParam(t, got, "cvssV2Metrics", "AV:N/AC:L/Au:N/C:P/I:P/A:P")
	assertQueryParam(t, got, "cvssV3Severity", "HIGH")
	assertQueryParam(t, got, "cvssV3Metrics", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	assertQueryParam(t, got, "cvssV4Severity", "CRITICAL")
	assertQueryParam(t, got, "cvssV4Metrics", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
	assertQueryParam(t, got, "cweId", "CWE-79")
	assertQueryParam(t, got, "keywordSearch", "openssl")
	assertQueryParam(t, got, "keywordExactMatch", "true")
	assertQueryParam(t, got, "pubStartDate", "2023-01-01T00:00:00.000")
	assertQueryParam(t, got, "pubEndDate", "2023-12-31T23:59:59.999")
	assertQueryParam(t, got, "lastModStartDate", "2023-01-01T00:00:00.000")
	assertQueryParam(t, got, "lastModEndDate", "2023-12-31T23:59:59.999")
	assertQueryParam(t, got, "sourceIdentifier", "nvd@nist.gov")
	assertQueryParam(t, got, "hasKev", "true")
	assertQueryParam(t, got, "hasCertAlerts", "false")
	assertQueryParam(t, got, "hasCertNotes", "true")
	assertQueryParam(t, got, "hasOval", "false")
	assertQueryParam(t, got, "isVulnerable", "true")
	assertQueryParam(t, got, "virtualMatchString", "cpe:2.3:a:microsoft:windows_11:*:*:*:*:*:*:*:*")
	assertQueryParam(t, got, "noRejected", "true")
	assertQueryParam(t, got, "resultsPerPage", "10")
	assertQueryParam(t, got, "startIndex", "5")

	// CPE- and source-only parameters must not be sent to the CVE endpoint.
	for _, key := range []string{"cpeMatchString", "cpeNameId", "sourceName"} {
		if got.Get(key) != "" {
			t.Errorf("query param %q should not be sent to the CVE endpoint, got %q", key, got.Get(key))
		}
	}
}

func TestGetCVE(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		assertQueryParam(t, r.URL.Query(), "cveId", "CVE-2023-4863")
		assertQueryParam(t, r.URL.Query(), "resultsPerPage", "1")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testCVEJSON)
	})
	c := testClient(srv)

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
	if cve.SourceIdentifier != "chrome-cve-admin@google.com" {
		t.Fatalf("unexpected sourceIdentifier: %s", cve.SourceIdentifier)
	}
	if cve.Published == "" || cve.LastModified == "" {
		t.Fatalf("missing dates: published=%q lastModified=%q", cve.Published, cve.LastModified)
	}
	if cve.VulnStatus != "Analyzed" {
		t.Fatalf("unexpected vulnStatus: %s", cve.VulnStatus)
	}

	if len(cve.CveTags) != 1 || cve.CveTags[0].SourceIdentifier != "cisa@example.gov" || cve.CveTags[0].Tags[0] != "kev" {
		t.Fatalf("unexpected cveTags: %+v", cve.CveTags)
	}
	if len(cve.Descriptions) != 2 || cve.Descriptions[0].Lang != "en" {
		t.Fatalf("unexpected descriptions: %+v", cve.Descriptions)
	}
	if len(cve.Affected) != 1 || len(cve.Affected[0].AffectedData) != 1 {
		t.Fatalf("unexpected affected: %+v", cve.Affected)
	}
	if ad := cve.Affected[0].AffectedData[0]; ad.Vendor != "Google" || ad.Product != "Chrome" {
		t.Fatalf("unexpected affected data: %+v", ad)
	}
	if av := cve.Affected[0].AffectedData[0].Versions[0]; av.Version != "116.0.5845.187" || av.LessThan != "116.0.5845.187" || av.Status != "affected" {
		t.Fatalf("unexpected affected version: %+v", av)
	}

	if len(cve.Metrics.CVSSMetricV2) != 1 || cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore != 7.5 {
		t.Fatalf("unexpected cvssMetricV2: %+v", cve.Metrics.CVSSMetricV2)
	}
	if len(cve.Metrics.CVSSMetricV31) != 1 || cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore != 8.8 {
		t.Fatalf("unexpected cvssMetricV31: %+v", cve.Metrics.CVSSMetricV31)
	}
	if len(cve.Metrics.CVSSMetricV40) != 1 || cve.Metrics.CVSSMetricV40[0].CVSSData.BaseScore != 10.0 {
		t.Fatalf("unexpected cvssMetricV40: %+v", cve.Metrics.CVSSMetricV40)
	}
	if len(cve.Metrics.SSVCV203) != 1 {
		t.Fatalf("unexpected ssvcV203: %+v", cve.Metrics.SSVCV203)
	}
	if ssvc := cve.Metrics.SSVCV203[0]; ssvc.SSVCData.Role != "CISA Coordinator" || len(ssvc.SSVCData.Options) != 3 || ssvc.SSVCData.Version != "2.0.3" {
		t.Fatalf("unexpected ssvc data: %+v", ssvc)
	}

	if cve.CisaExploitAdd != "2023-09-13" || cve.CisaActionDue != "2023-10-04" ||
		cve.CisaRequiredAction == "" || cve.CisaVulnerabilityName == "" {
		t.Fatalf("unexpected cisa fields: %+v", cve)
	}
	if len(cve.References) != 1 || cve.References[0].URL == "" || cve.References[0].Tags[0] != "Mailing List" {
		t.Fatalf("unexpected references: %+v", cve.References)
	}
	if len(cve.Configurations) != 1 || len(cve.Configurations[0].Nodes) != 1 {
		t.Fatalf("unexpected configurations: %+v", cve.Configurations)
	}
	cm := cve.Configurations[0].Nodes[0].CPEMatch[0]
	if cm.Criteria != "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*" {
		t.Fatalf("unexpected criteria: %s", cm.Criteria)
	}
	if cm.MatchCriteriaID != "856C1821-5D22-4A4E-859D-8F5305255AB7" {
		t.Fatalf("unexpected matchCriteriaId: %s", cm.MatchCriteriaID)
	}
	if cm.VersionEndExcluding != "116.0.5845.187" {
		t.Fatalf("unexpected versionEndExcluding: %s", cm.VersionEndExcluding)
	}
	if len(cve.Weaknesses) != 1 {
		t.Fatalf("unexpected weaknesses: %+v", cve.Weaknesses)
	}
}

func TestGetCVE_NotFound(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testEmptyCVEResponse)
	})
	c := testClient(srv)

	_, err := c.GetCVE("CVE-9999-0001")
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not-found error, got: %v", err)
	}
}

func TestSearchCpes_AllFilters(t *testing.T) {
	f := Filter{
		CpeName:          "cpe:2.3:a:3com:3cdaemon:-:*:*:*:*:*:*:*",
		CpeMatchString:   "cpe:2.3:a:3com:3cdaemon:*:*:*:*:*:*:*:*",
		CpeNameID:        "BAE41D20-D4AF-4AF0-AA7D-3BD04DA402A7",
		KeywordSearch:    "3cdaemon",
		LastModStartDate: "2023-01-01T00:00:00.000",
		LastModEndDate:   "2023-12-31T23:59:59.999",
		ResultsPerPage:   10,
		StartIndex:       2,
	}

	var got url.Values
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testCPEJSON)
	})
	c := testClient(srv)

	resp, err := c.SearchCpes(f)
	if err != nil {
		t.Fatalf("SearchCpes failed: %v", err)
	}
	if resp.TotalResults != 1 || len(resp.Products) != 1 {
		t.Fatalf("unexpected response: total=%d products=%d", resp.TotalResults, len(resp.Products))
	}

	assertQueryParam(t, got, "cpeName", "cpe:2.3:a:3com:3cdaemon:-:*:*:*:*:*:*:*")
	assertQueryParam(t, got, "cpeMatchString", "cpe:2.3:a:3com:3cdaemon:*:*:*:*:*:*:*:*")
	assertQueryParam(t, got, "cpeNameId", "BAE41D20-D4AF-4AF0-AA7D-3BD04DA402A7")
	assertQueryParam(t, got, "keywordSearch", "3cdaemon")
	assertQueryParam(t, got, "lastModStartDate", "2023-01-01T00:00:00.000")
	assertQueryParam(t, got, "lastModEndDate", "2023-12-31T23:59:59.999")
	assertQueryParam(t, got, "resultsPerPage", "10")
	assertQueryParam(t, got, "startIndex", "2")

	cpe := resp.Products[0].CPE
	if cpe.Name != "cpe:2.3:a:3com:3cdaemon:-:*:*:*:*:*:*:*" {
		t.Fatalf("unexpected cpeName: %s", cpe.Name)
	}
	if cpe.ID != "BAE41D20-D4AF-4AF0-AA7D-3BD04DA402A7" {
		t.Fatalf("unexpected cpeNameId: %s", cpe.ID)
	}
	if cpe.Deprecated {
		t.Fatal("unexpected deprecated=true")
	}
	if cpe.LastModified == "" || cpe.Created == "" {
		t.Fatalf("missing CPE dates: %+v", cpe)
	}
	if len(cpe.Titles) != 2 || cpe.Titles[0].Title != "3Com 3CDaemon" || cpe.Titles[0].Lang != "en" {
		t.Fatalf("unexpected titles: %+v", cpe.Titles)
	}
}

func TestSearchCPEs(t *testing.T) {
	var got url.Values
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testCPEJSON)
	})
	c := testClient(srv)

	cpes, err := c.SearchCPEs("cpe:2.3:a:3com:3cdaemon:-:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("SearchCPEs failed: %v", err)
	}
	assertQueryParam(t, got, "cpeName", "cpe:2.3:a:3com:3cdaemon:-:*:*:*:*:*:*:*")
	if len(cpes) != 1 || cpes[0].Name != "cpe:2.3:a:3com:3cdaemon:-:*:*:*:*:*:*:*" {
		t.Fatalf("unexpected CPEs: %+v", cpes)
	}
}

func TestSearchSources_AllFilters(t *testing.T) {
	f := Filter{
		SourceIdentifier: "cve@mitre.org",
		SourceName:       "MITRE",
		ResultsPerPage:   10,
		StartIndex:       3,
	}

	var got url.Values
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testSourceJSON)
	})
	c := testClient(srv)

	resp, err := c.SearchSources(f)
	if err != nil {
		t.Fatalf("SearchSources failed: %v", err)
	}
	assertQueryParam(t, got, "sourceIdentifier", "cve@mitre.org")
	assertQueryParam(t, got, "sourceName", "MITRE")
	assertQueryParam(t, got, "resultsPerPage", "10")
	assertQueryParam(t, got, "startIndex", "3")

	if len(resp.Sources) != 1 {
		t.Fatalf("expected 1 source, got %d", len(resp.Sources))
	}
	src := resp.Sources[0]
	if src.Name != "MITRE" || src.ContactEmail != "cve@mitre.org" {
		t.Fatalf("unexpected source: %+v", src)
	}
	if len(src.SourceIdentifiers) != 2 || src.SourceIdentifiers[0] != "cve@mitre.org" {
		t.Fatalf("unexpected sourceIdentifiers: %+v", src.SourceIdentifiers)
	}
	if src.V3AcceptanceLevel.Description != "Contributor" || src.CWEAcceptanceLevel.Description != "Provider" {
		t.Fatalf("unexpected acceptance levels: %+v", src)
	}
}

func TestGetSources(t *testing.T) {
	var got url.Values
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testSourceJSON)
	})
	c := testClient(srv)

	sources, err := c.GetSources("cve@mitre.org")
	if err != nil {
		t.Fatalf("GetSources failed: %v", err)
	}
	assertQueryParam(t, got, "sourceIdentifier", "cve@mitre.org")
	if len(sources) != 1 || sources[0].Name != "MITRE" {
		t.Fatalf("unexpected sources: %+v", sources)
	}
}

func TestCVEConvenienceMethods(t *testing.T) {
	tests := []struct {
		name string
		call func(*Client) ([]CVE, error)
		want map[string]string
	}{
		{
			name: "SearchByKeyword",
			call: func(c *Client) ([]CVE, error) { return c.SearchByKeyword("openssl") },
			want: map[string]string{"keywordSearch": "openssl"},
		},
		{
			name: "SearchByCPE",
			call: func(c *Client) ([]CVE, error) { return c.SearchByCPE("cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*") },
			want: map[string]string{"cpeName": "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*"},
		},
		{
			name: "SearchByCWE",
			call: func(c *Client) ([]CVE, error) { return c.SearchByCWE("CWE-79") },
			want: map[string]string{"cweId": "CWE-79"},
		},
		{
			name: "GetByDateRange",
			call: func(c *Client) ([]CVE, error) {
				return c.GetByDateRange("2023-01-01T00:00:00.000", "2023-01-31T23:59:59.999")
			},
			want: map[string]string{
				"pubStartDate": "2023-01-01T00:00:00.000",
				"pubEndDate":   "2023-01-31T23:59:59.999",
			},
		},
		{
			name: "GetBySeverity",
			call: func(c *Client) ([]CVE, error) { return c.GetBySeverity("HIGH") },
			want: map[string]string{"cvssV3Severity": "HIGH"},
		},
		{
			name: "GetKevCatalog",
			call: func(c *Client) ([]CVE, error) { return c.GetKevCatalog() },
			want: map[string]string{"hasKev": "true"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got url.Values
			srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				got = r.URL.Query()
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprint(w, testCVEJSON)
			})
			c := testClient(srv)

			cves, err := tt.call(c)
			if err != nil {
				t.Fatalf("%s failed: %v", tt.name, err)
			}
			if len(cves) != 1 || cves[0].ID != "CVE-2023-4863" {
				t.Fatalf("%s: unexpected CVEs: %+v", tt.name, cves)
			}
			for key, want := range tt.want {
				assertQueryParam(t, got, key, want)
			}
		})
	}
}

func TestGetModifiedCVEs(t *testing.T) {
	var got url.Values
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testCVEJSON)
	})
	c := testClient(srv)

	cves, err := c.GetModifiedCVEs("2026-08-01T00:00:00.000", "2026-08-13T23:59:59.999")
	if err != nil {
		t.Fatalf("GetModifiedCVEs failed: %v", err)
	}
	assertQueryParam(t, got, "lastModStartDate", "2026-08-01T00:00:00.000")
	assertQueryParam(t, got, "lastModEndDate", "2026-08-13T23:59:59.999")
	assertQueryParam(t, got, "resultsPerPage", "2000")
	if len(cves) != 1 {
		t.Fatalf("expected 1 CVE, got %d", len(cves))
	}
}

func TestGetModifiedCPEs(t *testing.T) {
	var got url.Values
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, testCPEJSON)
	})
	c := testClient(srv)

	cpes, err := c.GetModifiedCPEs("2026-08-01T00:00:00.000", "2026-08-13T23:59:59.999")
	if err != nil {
		t.Fatalf("GetModifiedCPEs failed: %v", err)
	}
	assertQueryParam(t, got, "lastModStartDate", "2026-08-01T00:00:00.000")
	assertQueryParam(t, got, "lastModEndDate", "2026-08-13T23:59:59.999")
	if len(cpes) != 1 || cpes[0].Name != "cpe:2.3:a:3com:3cdaemon:-:*:*:*:*:*:*:*" {
		t.Fatalf("unexpected CPEs: %+v", cpes)
	}
}

// cvePageJSON builds a CVE API page where each page holds up to perPage
// records out of a total of total records.
func cvePageJSON(startIndex, perPage, total int) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{"resultsPerPage":%d,"startIndex":%d,"totalResults":%d,"format":"NVD_CVE","version":"2.0","timestamp":"2026-08-14T00:00:00.000","vulnerabilities":[`,
		perPage, startIndex, total)
	n := perPage
	if startIndex+n > total {
		n = total - startIndex
	}
	for i := 0; i < n; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"cve":{"id":"CVE-2024-%04d"}}`, startIndex+i+1)
	}
	b.WriteString(`]}`)
	return b.String()
}

func TestGetAll_PaginatesByResultsPerPage(t *testing.T) {
	var starts, perPages []string
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		starts = append(starts, q.Get("startIndex"))
		perPages = append(perPages, q.Get("resultsPerPage"))
		start, _ := strconv.Atoi(q.Get("startIndex"))
		perPage, _ := strconv.Atoi(q.Get("resultsPerPage"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, cvePageJSON(start, perPage, 2500))
	})
	c := testClient(srv)

	cves, err := c.GetAll(0)
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}
	if len(cves) != 2500 {
		t.Fatalf("expected 2500 CVEs, got %d", len(cves))
	}
	if cves[0].ID != "CVE-2024-0001" || cves[2499].ID != "CVE-2024-2500" {
		t.Fatalf("unexpected first/last IDs: %s / %s", cves[0].ID, cves[2499].ID)
	}
	wantStarts := []string{"0", "2000"}
	if len(starts) != len(wantStarts) {
		t.Fatalf("expected %d requests, got %d (starts=%v)", len(wantStarts), len(starts), starts)
	}
	for i, want := range wantStarts {
		if starts[i] != want {
			t.Errorf("request %d startIndex = %s, want %s", i, starts[i], want)
		}
	}
	for i, want := range []string{"2000", "2000"} {
		if perPages[i] != want {
			t.Errorf("request %d resultsPerPage = %s, want %s", i, perPages[i], want)
		}
	}
}

func TestGetAll_Limit(t *testing.T) {
	var starts []string
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		starts = append(starts, q.Get("startIndex"))
		start, _ := strconv.Atoi(q.Get("startIndex"))
		perPage, _ := strconv.Atoi(q.Get("resultsPerPage"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, cvePageJSON(start, perPage, 10))
	})
	c := testClient(srv)

	cves, err := c.GetAll(3)
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}
	if len(cves) != 3 {
		t.Fatalf("expected 3 CVEs, got %d", len(cves))
	}
	if len(starts) != 1 || starts[0] != "0" {
		t.Fatalf("expected a single request at startIndex 0, got %v", starts)
	}
}

func TestGetAll_AppliesRequestDelay(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		start, _ := strconv.Atoi(q.Get("startIndex"))
		perPage, _ := strconv.Atoi(q.Get("resultsPerPage"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, cvePageJSON(start, perPage, 3000))
	})
	c := testClient(srv, WithRequestDelay(60*time.Millisecond))

	start := time.Now()
	cves, err := c.GetAll(0)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}
	if len(cves) != 3000 {
		t.Fatalf("expected 3000 CVEs, got %d", len(cves))
	}
	if elapsed < 50*time.Millisecond {
		t.Fatalf("expected request delay between pages, elapsed=%s", elapsed)
	}
}

func TestHTTPError_MessageHeader(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("message", "Invalid parameter: bogusParam.")
		w.WriteHeader(http.StatusNotFound)
	})
	c := testClient(srv)

	_, err := c.SearchCves(Filter{})
	if err == nil || !strings.Contains(err.Error(), "Invalid parameter: bogusParam.") {
		t.Fatalf("expected error to surface the NVD message header, got: %v", err)
	}
}

func TestHTTPError_ResponseBody(t *testing.T) {
	srv := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"bad request"}`)
	})
	c := testClient(srv)

	_, err := c.SearchCpes(Filter{})
	if err == nil || !strings.Contains(err.Error(), "bad request") {
		t.Fatalf("expected error to surface the response body, got: %v", err)
	}
}

func TestExtractCVEs(t *testing.T) {
	var resp CVEResponse
	if err := json.Unmarshal([]byte(testCVEJSON), &resp); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	cves := extractCVEs(&resp)
	if len(cves) != len(resp.Vulnerabilities) {
		t.Fatalf("expected %d CVEs, got %d", len(resp.Vulnerabilities), len(cves))
	}
	if len(cves) == 0 || cves[0].ID != "CVE-2023-4863" {
		t.Fatalf("unexpected CVEs: %+v", cves)
	}
}

func TestGetDescription(t *testing.T) {
	cve := &CVE{Descriptions: []Description{{Lang: "es", Value: "es"}, {Lang: "en", Value: "en"}}}
	if got := GetDescription(cve); got != "en" {
		t.Fatalf("expected English description, got %q", got)
	}

	cve = &CVE{Descriptions: []Description{{Lang: "fr", Value: "fr"}}}
	if got := GetDescription(cve); got != "fr" {
		t.Fatalf("expected fallback description, got %q", got)
	}

	if got := GetDescription(&CVE{}); got != "" {
		t.Fatalf("expected empty description, got %q", got)
	}
}

func TestGetCVSSV3Score(t *testing.T) {
	cve := &CVE{Metrics: Metrics{
		CVSSMetricV3:  []CVSSV3{{CVSSData: CVSSV3Data{BaseScore: 7.5}}},
		CVSSMetricV31: []CVSSV31{{CVSSData: CVSSV31Data{BaseScore: 8.8}}},
	}}
	if got := GetCVSSV3Score(cve); got != 8.8 {
		t.Fatalf("expected v3.1 score to win, got %v", got)
	}

	cve = &CVE{Metrics: Metrics{CVSSMetricV3: []CVSSV3{{CVSSData: CVSSV3Data{BaseScore: 7.5}}}}}
	if got := GetCVSSV3Score(cve); got != 7.5 {
		t.Fatalf("expected v3 fallback score, got %v", got)
	}

	if got := GetCVSSV3Score(&CVE{}); got != 0 {
		t.Fatalf("expected 0 with no metrics, got %v", got)
	}
}

func TestGetCVSSV3Severity(t *testing.T) {
	cve := &CVE{Metrics: Metrics{
		CVSSMetricV3:  []CVSSV3{{BaseSeverity: "HIGH"}},
		CVSSMetricV31: []CVSSV31{{BaseSeverity: "CRITICAL"}},
	}}
	if got := GetCVSSV3Severity(cve); got != "CRITICAL" {
		t.Fatalf("expected v3.1 severity to win, got %q", got)
	}

	cve = &CVE{Metrics: Metrics{CVSSMetricV3: []CVSSV3{{BaseSeverity: "HIGH"}}}}
	if got := GetCVSSV3Severity(cve); got != "HIGH" {
		t.Fatalf("expected v3 fallback severity, got %q", got)
	}

	if got := GetCVSSV3Severity(&CVE{}); got != "" {
		t.Fatalf("expected empty severity with no metrics, got %q", got)
	}
}

func TestGetCWEs(t *testing.T) {
	cve := &CVE{Weaknesses: []Weakness{
		{Description: []Description{{Lang: "en", Value: "CWE-787"}}},
		{Description: []Description{{Lang: "en", Value: "CWE-79"}, {Lang: "en", Value: "NoCWE"}}},
	}}
	cwes := GetCWEs(cve)
	if len(cwes) != 2 || cwes[0] != "CWE-787" || cwes[1] != "CWE-79" {
		t.Fatalf("unexpected CWEs: %+v", cwes)
	}
	if got := GetCWEs(&CVE{}); len(got) != 0 {
		t.Fatalf("expected no CWEs, got %+v", got)
	}
}

// TestLiveNVDEndpoints validates the client against the real NVD API.
// Run with NVD_LIVE=1. Requests are spaced 6 seconds apart per the NVD
// best practices.
func TestLiveNVDEndpoints(t *testing.T) {
	if os.Getenv("NVD_LIVE") != "1" {
		t.Skip("set NVD_LIVE=1 to run live tests against the NVD API")
	}
	c := NewClient(WithHTTPClient(&http.Client{Timeout: 60 * time.Second}))

	resp, err := c.SearchCves(Filter{CveID: "CVE-2023-4863", ResultsPerPage: 1})
	if err != nil {
		t.Fatalf("live SearchCves failed: %v", err)
	}
	if len(resp.Vulnerabilities) != 1 || resp.Vulnerabilities[0].CVE.ID != "CVE-2023-4863" {
		t.Fatalf("unexpected live CVE response: %+v", resp)
	}
	time.Sleep(RecommendedRequestDelay)

	// CVSS v4 metrics (CVE-2024-0012 is scored with CVSS v4.0).
	v4resp, err := c.SearchCves(Filter{CveID: "CVE-2024-0012", ResultsPerPage: 1})
	if err != nil {
		t.Fatalf("live SearchCves (v4) failed: %v", err)
	}
	if len(v4resp.Vulnerabilities) != 1 || len(v4resp.Vulnerabilities[0].CVE.Metrics.CVSSMetricV40) == 0 {
		t.Fatalf("expected cvssMetricV40 in live response: %+v", v4resp)
	}
	time.Sleep(RecommendedRequestDelay)

	// CVSS v2 metrics (CVE-2017-0144 is scored with CVSS v2.0).
	v2resp, err := c.SearchCves(Filter{CveID: "CVE-2017-0144", ResultsPerPage: 1})
	if err != nil {
		t.Fatalf("live SearchCves (v2) failed: %v", err)
	}
	if len(v2resp.Vulnerabilities) != 1 || len(v2resp.Vulnerabilities[0].CVE.Metrics.CVSSMetricV2) == 0 {
		t.Fatalf("expected cvssMetricV2 in live response: %+v", v2resp)
	}
	time.Sleep(RecommendedRequestDelay)

	cpeResp, err := c.SearchCpes(Filter{ResultsPerPage: 1})
	if err != nil {
		t.Fatalf("live SearchCpes failed: %v", err)
	}
	if len(cpeResp.Products) != 1 || cpeResp.Products[0].CPE.Name == "" {
		t.Fatalf("unexpected live CPE response: %+v", cpeResp)
	}
	time.Sleep(RecommendedRequestDelay)

	srcResp, err := c.SearchSources(Filter{ResultsPerPage: 1})
	if err != nil {
		t.Fatalf("live SearchSources failed: %v", err)
	}
	if len(srcResp.Sources) != 1 || srcResp.Sources[0].Name == "" {
		t.Fatalf("unexpected live Source response: %+v", srcResp)
	}
}
