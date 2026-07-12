# NVD (National Vulnerability Database) - Go Client

A complete Go client for the NVD API 2.0 - the US government's public repository of vulnerability data. This package provides full access to CVE details, search, filtering, and CVSS scoring.

---

## Installation

```bash
go get github.com/dabumana/nvd-go
```

Replace with your actual module path if publishing.

### Quick Start

```go
package main

import (
    "fmt"
    "log"
    nvd "github.com/dabumana/nvd-go"
)

func main() {
    client := nvd.NewClient()
    
    // Search for a specific CVE
    cve, err := client.GetCVE("CVE-2024-6387")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("ID: %s, Score: %.1f\n", cve.ID, nvd.GetCVSSV3Score(cve))
}
```

## Authentication

The NVD API uses API keys to increase rate limits.

* Without an API key: 50 requests per rolling 5‑minute window.
* With an API key: 100 requests per rolling 5‑minute window.

Obtain a free API key from NVD's request page.

Pass it to NewClient:

```go
client := nvd.NewClient(
    nvd.WithAPIKey("your-api-key"),
)
```

### Client Configuration

You can customise the client with optional Option functions:

### Option Description
* **WithHTTPClient(http.Client)** Use a custom HTTP client (e.g., with proxy).
* **WithBaseURL(string)** Override the base URL (for testing).
* **WithAPIKey(string)** Set your NVD API key.

Example with custom timeout:

```go
customClient := &http.Client{Timeout: 15 * time.Second}
client := nvd.NewClient(
    nvd.WithHTTPClient(customClient),
    nvd.WithAPIKey("your-key"),
)
```

## API Methods

|Method | Description|
|-------|------------|
|GetCVE(cveID string) (*CVE, error) | Fetch a single CVE by its ID.|
|SearchCves(filter Filter) (*CVEResponse, error) | Advanced search with all NVD filters.|
|SearchByKeyword(keyword string) ([]CVE, error) | Quick full text search.|
|SearchByCPE(cpeName string) ([]CVE, error) | Search by CPE name (affected product).|
|SearchByCWE(cweID string) ([]CVE, error) | Search by CWE ID.|
|GetByDateRange(pubStart, pubEnd string) ([]CVE, error) | Get CVEs published in a date range.|
|GetBySeverity(severity string) ([]CVE, error) | Filter by CVSS V3 severity (LOW, MEDIUM, HIGH, CRITICAL).|
|GetKevCatalog() ([]CVE, error) | Returns CVEs with hasKev=true (CISA KEV matching).|
|GetAll(limit int) ([]CVE, error) | Fetches all CVEs (paginated), with optional limit.|

### Data Types

The package implements all NVD 2.0 response fields:

* CVEResponse - Top‑level response wrapper; contains Vulnerabilities and pagination info.
* CVE - The full vulnerability record, including:
  * ID, Published, LastModified, VulnStatus.
  * Descriptions - language‑localised description.
  * Metrics - CVSS V2, V3, V3.1, and V4 scores.
  * References - external links.
  * Configurations - affected product/version information.
  * Weaknesses - CWE details.
  * CWEs - list of CWE IDs.
* Filter - struct for search parameters.
* Helper functions:
  * GetDescription(cve *CVE) string - returns the English description.
  * GetCVSSV3Score(cve *CVE) float64 - returns the V3 base score (prefers V3.1).
  * GetCVSSV3Severity(cve *CVE) string - returns the V3 severity rating.
  * GetCWEs(cve *CVE) []string - extracts CWE IDs.

All methods return lists of CVE objects (except GetCVE and SearchCves).

### Filtering (Filter struct)

SearchCves accepts a Filter struct with the following optional fields:

|Field | Type | Description|
|------|------|------------|
|CveID | string | Exact CVE ID.|
|CpeName | string | Full CPE name (e.g., cpe:2.3:o:microsoft:windows_11:22h2:*:*:*:*:*:*:*).|
|CvssV2Severity | string | LOW, MEDIUM, HIGH.|
|CvssV3Severity | string | LOW, MEDIUM, HIGH, CRITICAL.|
|CvssV4Severity | string | LOW, MEDIUM, HIGH, CRITICAL.|
|CweID | string | Exact CWE ID (e.g., CWE-79).|
|KeywordSearch | string | Full‑text search.|
|KeywordExactMatch | bool | Whether keyword must be exact.|
|PubStartDate | string | ISO‑8601 date (e.g., 2024-01-01T00:00:00.000).|
|PubEndDate | string | Same format.|
|LastModStartDate | string | Last modified start.|
|LastModEndDate | string | Last modified end.|
|HasKev | *bool | Filter by CISA KEV status.|
|HasCertAlerts | *bool | Filter by CERT alerts.|
|HasCertNotes | *bool | Filter by CERT notes.|
|IsVulnerable | *bool | Whether the CPE is vulnerable.|
|ResultsPerPage | int | Max 2000.|
|StartIndex | int | Pagination offset.|

### Error Handling

The client returns standard Go errors.
Common errors:

* HTTP non‑200 (e.g., 401 for invalid API key).
* JSON unmarshalling.
* CVE not found (returns a custom error from GetCVE).

Always check err != nil.

### Examples

1. Get a Specific CVE

```go
cve, err := client.GetCVE("CVE-2024-6387")
if err != nil {
    log.Fatal(err)
}
desc := nvd.GetDescription(cve)
score := nvd.GetCVSSV3Score(cve)
fmt.Printf("%s (score: %.1f)\n", desc, score)
```

2. Keyword Search

```go
cves, err := client.SearchByKeyword("remote code execution")
if err != nil {
    log.Fatal(err)
}
for _, c := range cves {
    fmt.Printf("%s: %s\n", c.ID, nvd.GetDescription(c))
}
```

3. Filter by Severity and Date

```go
filter := nvd.Filter{
    CvssV3Severity: "CRITICAL",
    PubStartDate:   "2024-06-01T00:00:00.000",
    PubEndDate:     "2024-06-30T23:59:59.999",
}
resp, err := client.SearchCves(filter)
if err != nil {
    log.Fatal(err)
}
for _, v := range resp.Vulnerabilities {
    c := v.CVE
    fmt.Printf("%s: %s\n", c.ID, nvd.GetDescription(c))
}
```

4. Get CISA KEV Catalog

```go
cves, err := client.GetKevCatalog()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Found %d CVEs in KEV\n", len(cves))
```

5. Paginate All CVEs

```go
allCVEs, err := client.GetAll(100) // get first 100
if err != nil {
    log.Fatal(err)
}
```

6. Use API Key for Higher Rate Limits

```go
client := nvd.NewClient(
    nvd.WithAPIKey(os.Getenv("NVD_API_KEY")),
)
// all subsequent requests use the key
```

---

## Important Notes

* Date Formats - NVD expects ISO‑8601 with time zone. The examples use YYYY-MM-DDTHH:MM:SS.mmm (UTC). You can also use date‑only if the API accepts it (check NVD docs).
* Rate Limits - Unauthenticated: 50 req/5 min, authenticated: 100 req/5 min.
* Pagination - For large result sets, use ResultsPerPage and StartIndex or the convenience method GetAll.
* CVSS Versions - V3.1 is preferred, the helper functions handle both V3 and V3.1.
