package nvd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	DefaultTimeout = 30 * time.Second
)

type Client struct {
	httpClient *http.Client
	baseURL    string
	apiKey     string
}

type Option func(*Client)

func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.httpClient = c }
}

func WithBaseURL(baseURL string) Option {
	return func(cl *Client) { cl.baseURL = baseURL }
}

func WithAPIKey(key string) Option {
	return func(cl *Client) { cl.apiKey = key }
}

func NewClient(opts ...Option) *Client {
	c := &Client{
		httpClient: &http.Client{Timeout: DefaultTimeout},
		baseURL:    DefaultBaseURL,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

type CVEResponse struct {
	ResultsPerPage int            `json:"resultsPerPage"`
	StartIndex     int            `json:"startIndex"`
	TotalResults   int            `json:"totalResults"`
	Format         string         `json:"format"`
	Version        string         `json:"version"`
	Timestamp      string         `json:"timestamp"`
	Vulnerabilities []VulnWrapper `json:"vulnerabilities"`
}

type VulnWrapper struct {
	CVE CVE `json:"cve"`
}

type CVE struct {
	ID               string                 `json:"id"`
	SourceIdentifier string                 `json:"sourceIdentifier"`
	Published        string                 `json:"published"`
	LastModified     string                 `json:"lastModified"`
	VulnStatus       string                 `json:"vulnStatus"`
	Descriptions     []Description          `json:"descriptions"`
	Metrics          Metrics                `json:"metrics"`
	References       []Reference            `json:"references"`
	Configurations   []Configuration        `json:"configurations"`
	Weaknesses       []Weakness             `json:"weaknesses"`
	CWEs             []CWE                  `json:"cwe"`
	CPEs             []CPE                  `json:"cpe"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Metrics struct {
	CVSSMetricV2  []CVSSV2  `json:"cvssMetricV2,omitempty"`
	CVSSMetricV31 []CVSSV31 `json:"cvssMetricV31,omitempty"`
	CVSSMetricV3  []CVSSV3  `json:"cvssMetricV3,omitempty"`
	CVSSMetricV40 []CVSSV40 `json:"cvssMetricV40,omitempty"`
}

type CVSSV2 struct {
	Source   string  `json:"source"`
	Type     string  `json:"type"`
	CVSSData CVSSV2Data `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore float64 `json:"impactScore"`
	ACInsufInfo bool `json:"acInsufInfo"`
	ObtainAllPrivilege bool `json:"obtainAllPrivilege"`
	ObtainUserPrivilege bool `json:"obtainUserPrivilege"`
	ObtainOtherPrivilege bool `json:"obtainOtherPrivilege"`
	UserInteractionRequired bool `json:"userInteractionRequired"`
}

type CVSSV2Data struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
}

type CVSSV31 struct {
	Source   string    `json:"source"`
	Type     string    `json:"type"`
	CVSSData CVSSV31Data `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore float64 `json:"impactScore"`
}

type CVSSV31Data struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
}

type CVSSV3 struct {
	Source   string    `json:"source"`
	Type     string    `json:"type"`
	CVSSData CVSSV3Data `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
	ExploitabilityScore float64 `json:"exploitabilityScore"`
	ImpactScore float64 `json:"impactScore"`
}

type CVSSV3Data struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
}

type CVSSV40 struct {
	Source   string    `json:"source"`
	Type     string    `json:"type"`
	CVSSData CVSSV40Data `json:"cvssData"`
}

type CVSSV40Data struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	AttackRequirements    string  `json:"attackRequirements"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	VulnConfidentialityImpact string `json:"vulnConfidentialityImpact"`
	VulnIntegrityImpact   string  `json:"vulnIntegrityImpact"`
	VulnAvailabilityImpact string  `json:"vulnAvailabilityImpact"`
	SubConfidentialityImpact string `json:"subConfidentialityImpact"`
	SubIntegrityImpact    string  `json:"subIntegrityImpact"`
	SubAvailabilityImpact string  `json:"subAvailabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
}

type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

type Configuration struct {
	ID      string        `json:"id"`
	Nodes   []ConfigNode  `json:"nodes"`
	Operator string       `json:"operator"`
}

type ConfigNode struct {
	Operator string        `json:"operator"`
	Negate   bool          `json:"negate"`
	CPEMatch []CPEMatch    `json:"cpeMatch"`
}

type CPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	CPE                   string `json:"cpe"`
	CPEURI                string `json:"cpeUri"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
}

type Weakness struct {
	Source      string            `json:"source"`
	Type        string            `json:"type"`
	Description []Description     `json:"description"`
}

type CWE struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
}

type CPE struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Deprecated  bool   `json:"deprecated"`
}

type Filter struct {
	CveID              string
	CpeName            string
	CvssV2Severity     string
	CvssV3Severity     string
	CvssV4Severity     string
	CweID              string
	KeywordSearch      string
	KeywordExactMatch  bool
	PubStartDate       string
	PubEndDate         string
	LastModStartDate   string
	LastModEndDate     string
	HasKev             *bool
	HasCertAlerts      *bool
	HasCertNotes       *bool
	IsVulnerable       *bool
	ResultsPerPage     int
	StartIndex         int
}

func (c *Client) GetCVE(cveID string) (*CVE, error) {
	resp, err := c.SearchCves(Filter{CveID: cveID, ResultsPerPage: 1})
	if err != nil {
		return nil, err
	}
	if len(resp.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("CVE %s not found", cveID)
	}
	return &resp.Vulnerabilities[0].CVE, nil
}

func (c *Client) SearchCves(filter Filter) (*CVEResponse, error) {
	params := url.Values{}

	if filter.CveID != "" {
		params.Set("cveId", filter.CveID)
	}
	if filter.CpeName != "" {
		params.Set("cpeName", filter.CpeName)
	}
	if filter.CvssV2Severity != "" {
		params.Set("cvssV2Severity", filter.CvssV2Severity)
	}
	if filter.CvssV3Severity != "" {
		params.Set("cvssV3Severity", filter.CvssV3Severity)
	}
	if filter.CvssV4Severity != "" {
		params.Set("cvssV4Severity", filter.CvssV4Severity)
	}
	if filter.CweID != "" {
		params.Set("cweId", filter.CweID)
	}
	if filter.KeywordSearch != "" {
		params.Set("keywordSearch", filter.KeywordSearch)
	}
	if filter.KeywordExactMatch {
		params.Set("keywordExactMatch", "true")
	}
	if filter.PubStartDate != "" {
		params.Set("pubStartDate", filter.PubStartDate)
	}
	if filter.PubEndDate != "" {
		params.Set("pubEndDate", filter.PubEndDate)
	}
	if filter.LastModStartDate != "" {
		params.Set("lastModStartDate", filter.LastModStartDate)
	}
	if filter.LastModEndDate != "" {
		params.Set("lastModEndDate", filter.LastModEndDate)
	}
	if filter.HasKev != nil {
		params.Set("hasKev", strconv.FormatBool(*filter.HasKev))
	}
	if filter.HasCertAlerts != nil {
		params.Set("hasCertAlerts", strconv.FormatBool(*filter.HasCertAlerts))
	}
	if filter.HasCertNotes != nil {
		params.Set("hasCertNotes", strconv.FormatBool(*filter.HasCertNotes))
	}
	if filter.IsVulnerable != nil {
		params.Set("isVulnerable", strconv.FormatBool(*filter.IsVulnerable))
	}
	if filter.ResultsPerPage > 0 {
		params.Set("resultsPerPage", strconv.Itoa(filter.ResultsPerPage))
	}
	if filter.StartIndex > 0 {
		params.Set("startIndex", strconv.Itoa(filter.StartIndex))
	}

	reqURL := c.baseURL
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result CVEResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *Client) SearchByKeyword(keyword string) ([]CVE, error) {
	resp, err := c.SearchCves(Filter{KeywordSearch: keyword})
	if err != nil {
		return nil, err
	}
	return extractCVEs(resp), nil
}

func (c *Client) SearchByCPE(cpeName string) ([]CVE, error) {
	resp, err := c.SearchCves(Filter{CpeName: cpeName})
	if err != nil {
		return nil, err
	}
	return extractCVEs(resp), nil
}

func (c *Client) SearchByCWE(cweID string) ([]CVE, error) {
	resp, err := c.SearchCves(Filter{CweID: cweID})
	if err != nil {
		return nil, err
	}
	return extractCVEs(resp), nil
}

func (c *Client) GetByDateRange(pubStart, pubEnd string) ([]CVE, error) {
	resp, err := c.SearchCves(Filter{
		PubStartDate: pubStart,
		PubEndDate:   pubEnd,
	})
	if err != nil {
		return nil, err
	}
	return extractCVEs(resp), nil
}

func (c *Client) GetBySeverity(severity string) ([]CVE, error) {
	resp, err := c.SearchCves(Filter{CvssV3Severity: severity})
	if err != nil {
		return nil, err
	}
	return extractCVEs(resp), nil
}

func (c *Client) GetKevCatalog() ([]CVE, error) {
	kev := true
	resp, err := c.SearchCves(Filter{HasKev: &kev})
	if err != nil {
		return nil, err
	}
	return extractCVEs(resp), nil
}

func (c *Client) GetAll(limit int) ([]CVE, error) {
	var all []CVE
	startIndex := 0
	perPage := 2000
	if limit > 0 && limit < perPage {
		perPage = limit
	}

	for {
		resp, err := c.SearchCves(Filter{
			ResultsPerPage: perPage,
			StartIndex:     startIndex,
		})
		if err != nil {
			return nil, err
		}

		cves := extractCVEs(resp)
		all = append(all, cves...)

		if len(all) >= resp.TotalResults || (limit > 0 && len(all) >= limit) {
			break
		}
		startIndex += len(cves)
	}

	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

func extractCVEs(resp *CVEResponse) []CVE {
	cves := make([]CVE, len(resp.Vulnerabilities))
	for i, v := range resp.Vulnerabilities {
		cves[i] = v.CVE
	}
	return cves
}

func GetDescription(cve *CVE) string {
	for _, desc := range cve.Descriptions {
		if desc.Lang == "en" {
			return desc.Value
		}
	}
	if len(cve.Descriptions) > 0 {
		return cve.Descriptions[0].Value
	}
	return ""
}

func GetCVSSV3Score(cve *CVE) float64 {
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		return cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
	}
	if len(cve.Metrics.CVSSMetricV3) > 0 {
		return cve.Metrics.CVSSMetricV3[0].CVSSData.BaseScore
	}
	return 0
}

func GetCVSSV3Severity(cve *CVE) string {
	if len(cve.Metrics.CVSSMetricV31) > 0 {
		return cve.Metrics.CVSSMetricV31[0].BaseSeverity
	}
	if len(cve.Metrics.CVSSMetricV3) > 0 {
		return cve.Metrics.CVSSMetricV3[0].BaseSeverity
	}
	return ""
}

func GetCWEs(cve *CVE) []string {
	var cwes []string
	for _, w := range cve.Weaknesses {
		for _, desc := range w.Description {
			if strings.HasPrefix(desc.Value, "CWE-") {
				cwes = append(cwes, desc.Value)
			}
		}
	}
	return cwes
}
