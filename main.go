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
	DefaultCVEBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	DefaultCPEBaseURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
	DefaultSourceBaseURL = "https://services.nvd.nist.gov/rest/json/source/2.0"

	DefaultResultsPerPage = 2000
	MaxResultsPerPage = 2000
	RecommendedRequestDelay = 6 * time.Second

	DefaultTimeout = 30 * time.Second
)

type Client struct {
	httpClient    *http.Client
	cveBaseURL    string
	cpeBaseURL    string
	sourceBaseURL string
	apiKey        string
	requestDelay  time.Duration
}

type Option func(*Client)

type CVEResponse struct {
	ResultsPerPage  int           `json:"resultsPerPage"`
	StartIndex      int           `json:"startIndex"`
	TotalResults    int           `json:"totalResults"`
	Format          string        `json:"format"`
	Version         string        `json:"version"`
	Timestamp       string        `json:"timestamp"`
	Vulnerabilities []VulnWrapper `json:"vulnerabilities"`
}

type CPEResponse struct {
	ResultsPerPage int          `json:"resultsPerPage"`
	StartIndex     int          `json:"startIndex"`
	TotalResults   int          `json:"totalResults"`
	Format         string       `json:"format"`
	Version        string       `json:"version"`
	Timestamp      string       `json:"timestamp"`
	Products       []CPEWrapper `json:"products"`
}

type SourceResponse struct {
	ResultsPerPage int      `json:"resultsPerPage"`
	StartIndex     int      `json:"startIndex"`
	TotalResults   int      `json:"totalResults"`
	Format         string   `json:"format"`
	Version        string   `json:"version"`
	Timestamp      string   `json:"timestamp"`
	Sources        []Source `json:"sources"`
}

type VulnWrapper struct {
	CVE CVE `json:"cve"`
}

type CPEWrapper struct {
	CPE CPE `json:"cpe"`
}

type CVE struct {
	ID                    string          `json:"id"`
	SourceIdentifier      string          `json:"sourceIdentifier"`
	Published             string          `json:"published"`
	LastModified          string          `json:"lastModified"`
	VulnStatus            string          `json:"vulnStatus"`
	CveTags               []CVETag        `json:"cveTags"`
	Descriptions          []Description   `json:"descriptions"`
	Affected              []Affected      `json:"affected"`
	Metrics               Metrics         `json:"metrics"`
	CisaExploitAdd        string          `json:"cisaExploitAdd"`
	CisaActionDue         string          `json:"cisaActionDue"`
	CisaRequiredAction    string          `json:"cisaRequiredAction"`
	CisaVulnerabilityName string          `json:"cisaVulnerabilityName"`
	Weaknesses            []Weakness      `json:"weaknesses"`
	Configurations        []Configuration `json:"configurations"`
	References            []Reference     `json:"references"`
}

type CVETag struct {
	SourceIdentifier string   `json:"sourceIdentifier"`
	Tags             []string `json:"tags"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Affected struct {
	Source       string         `json:"source"`
	AffectedData []AffectedData `json:"affectedData"`
}

type AffectedData struct {
	Vendor   string            `json:"vendor"`
	Product  string            `json:"product"`
	Versions []AffectedVersion `json:"versions"`
}

type AffectedVersion struct {
	Version     string `json:"version"`
	LessThan    string `json:"lessThan"`
	VersionType string `json:"versionType"`
	Status      string `json:"status"`
}

type Metrics struct {
	CVSSMetricV2  []CVSSV2   `json:"cvssMetricV2,omitempty"`
	CVSSMetricV3  []CVSSV3   `json:"cvssMetricV3,omitempty"`
	CVSSMetricV31 []CVSSV31  `json:"cvssMetricV31,omitempty"`
	CVSSMetricV40 []CVSSV40  `json:"cvssMetricV40,omitempty"`
	SSVCV203      []SSVCV203 `json:"ssvcV203,omitempty"`
}

type CVSSV2 struct {
	Source                  string     `json:"source"`
	Type                    string     `json:"type"`
	CVSSData                CVSSV2Data `json:"cvssData"`
	BaseSeverity            string     `json:"baseSeverity"`
	ExploitabilityScore     float64    `json:"exploitabilityScore"`
	ImpactScore             float64    `json:"impactScore"`
	ACInsufInfo             bool       `json:"acInsufInfo"`
	ObtainAllPrivilege      bool       `json:"obtainAllPrivilege"`
	ObtainUserPrivilege     bool       `json:"obtainUserPrivilege"`
	ObtainOtherPrivilege    bool       `json:"obtainOtherPrivilege"`
	UserInteractionRequired bool       `json:"userInteractionRequired"`
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
	Source              string      `json:"source"`
	Type                string      `json:"type"`
	CVSSData            CVSSV31Data `json:"cvssData"`
	BaseSeverity        string      `json:"baseSeverity"`
	ExploitabilityScore float64     `json:"exploitabilityScore"`
	ImpactScore         float64     `json:"impactScore"`
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
	Source              string     `json:"source"`
	Type                string     `json:"type"`
	CVSSData            CVSSV3Data `json:"cvssData"`
	BaseSeverity        string     `json:"baseSeverity"`
	ExploitabilityScore float64    `json:"exploitabilityScore"`
	ImpactScore         float64    `json:"impactScore"`
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
	Source              string      `json:"source"`
	Type                string      `json:"type"`
	CVSSData            CVSSV40Data `json:"cvssData"`
	ExploitabilityScore float64     `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64     `json:"impactScore,omitempty"`
}

type CVSSV40Data struct {
	Version                   string  `json:"version"`
	VectorString              string  `json:"vectorString"`
	BaseScore                 float64 `json:"baseScore"`
	BaseSeverity              string  `json:"baseSeverity"`
	AttackVector              string  `json:"attackVector"`
	AttackComplexity          string  `json:"attackComplexity"`
	AttackRequirements        string  `json:"attackRequirements"`
	PrivilegesRequired        string  `json:"privilegesRequired"`
	UserInteraction           string  `json:"userInteraction"`
	VulnConfidentialityImpact string  `json:"vulnConfidentialityImpact"`
	VulnIntegrityImpact       string  `json:"vulnIntegrityImpact"`
	VulnAvailabilityImpact    string  `json:"vulnAvailabilityImpact"`
	SubConfidentialityImpact  string  `json:"subConfidentialityImpact"`
	SubIntegrityImpact        string  `json:"subIntegrityImpact"`
	SubAvailabilityImpact     string  `json:"subAvailabilityImpact"`
}

type SSVCV203 struct {
	Source   string   `json:"source"`
	SSVCData SSVCData `json:"ssvcData"`
}

type SSVCData struct {
	Timestamp string       `json:"timestamp"`
	ID        string       `json:"id"`
	Options   []SSVCOption `json:"options"`
	Role      string       `json:"role"`
	Version   string       `json:"version"`
}

type SSVCOption struct {
	Exploitation    string `json:"exploitation"`
	Automatable     string `json:"automatable"`
	TechnicalImpact string `json:"technicalImpact"`
}

type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

type Configuration struct {
	Nodes []ConfigNode `json:"nodes"`
}

type ConfigNode struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []CPEMatch `json:"cpeMatch"`
}

type CPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
}

type Weakness struct {
	Source      string        `json:"source"`
	Type        string        `json:"type"`
	Description []Description `json:"description"`
}

type CPE struct {
	Deprecated   bool       `json:"deprecated"`
	Name         string     `json:"cpeName"`
	ID           string     `json:"cpeNameId"`
	LastModified string     `json:"lastModified"`
	Created      string     `json:"created"`
	Titles       []CPETitle `json:"titles"`
}

type CPETitle struct {
	Title string `json:"title"`
	Lang  string `json:"lang"`
}

type Source struct {
	Name               string          `json:"name"`
	ContactEmail       string          `json:"contactEmail"`
	SourceIdentifiers  []string        `json:"sourceIdentifiers"`
	LastModified       string          `json:"lastModified"`
	Created            string          `json:"created"`
	V3AcceptanceLevel  AcceptanceLevel `json:"v3AcceptanceLevel"`
	CWEAcceptanceLevel AcceptanceLevel `json:"cweAcceptanceLevel"`
}

type AcceptanceLevel struct {
	Description  string `json:"description"`
	LastModified string `json:"lastModified"`
}

type Filter struct {
	CveID              string
	CpeName            string
	CpeMatchString     string
	CpeNameID          string
	CvssV2Severity     string
	CvssV2Metrics      string
	CvssV3Severity     string
	CvssV3Metrics      string
	CvssV4Severity     string
	CvssV4Metrics      string
	CweID              string
	KeywordSearch      string
	KeywordExactMatch  bool
	PubStartDate       string
	PubEndDate         string
	LastModStartDate   string
	LastModEndDate     string
	SourceIdentifier   string
	SourceName         string
	HasKev             *bool
	HasCertAlerts      *bool
	HasCertNotes       *bool
	HasOval            *bool
	IsVulnerable       *bool
	VirtualMatchString string
	NoRejected         *bool
	ResultsPerPage     int
	StartIndex         int
}

func WithHTTPClient(c *http.Client) Option {
	return func(cl *Client) { cl.httpClient = c }
}

func WithCVEBaseURL(baseURL string) Option {
	return func(cl *Client) { cl.cveBaseURL = baseURL }
}

func WithCPEBaseURL(baseURL string) Option {
	return func(cl *Client) { cl.cpeBaseURL = baseURL }
}

func WithSourceBaseURL(baseURL string) Option {
	return func(cl *Client) { cl.sourceBaseURL = baseURL }
}

func WithAPIKey(key string) Option {
	return func(cl *Client) { cl.apiKey = key }
}

func WithRequestDelay(d time.Duration) Option {
	return func(cl *Client) { cl.requestDelay = d }
}

func NewClient(opts ...Option) *Client {
	c := &Client{
		httpClient:    &http.Client{Timeout: DefaultTimeout},
		cveBaseURL:    DefaultCVEBaseURL,
		cpeBaseURL:    DefaultCPEBaseURL,
		sourceBaseURL: DefaultSourceBaseURL,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func setBool(params url.Values, key string, v *bool) {
	if v != nil {
		params.Set(key, strconv.FormatBool(*v))
	}
}

// cveParams returns the query parameters valid for the CVE endpoint.
func (f Filter) cveParams() url.Values {
	p := url.Values{}
	if f.CveID != "" {
		p.Set("cveId", f.CveID)
	}
	if f.CpeName != "" {
		p.Set("cpeName", f.CpeName)
	}
	if f.CvssV2Severity != "" {
		p.Set("cvssV2Severity", f.CvssV2Severity)
	}
	if f.CvssV2Metrics != "" {
		p.Set("cvssV2Metrics", f.CvssV2Metrics)
	}
	if f.CvssV3Severity != "" {
		p.Set("cvssV3Severity", f.CvssV3Severity)
	}
	if f.CvssV3Metrics != "" {
		p.Set("cvssV3Metrics", f.CvssV3Metrics)
	}
	if f.CvssV4Severity != "" {
		p.Set("cvssV4Severity", f.CvssV4Severity)
	}
	if f.CvssV4Metrics != "" {
		p.Set("cvssV4Metrics", f.CvssV4Metrics)
	}
	if f.CweID != "" {
		p.Set("cweId", f.CweID)
	}
	if f.KeywordSearch != "" {
		p.Set("keywordSearch", f.KeywordSearch)
	}
	if f.KeywordExactMatch {
		p.Set("keywordExactMatch", "true")
	}
	if f.PubStartDate != "" {
		p.Set("pubStartDate", f.PubStartDate)
	}
	if f.PubEndDate != "" {
		p.Set("pubEndDate", f.PubEndDate)
	}
	if f.LastModStartDate != "" {
		p.Set("lastModStartDate", f.LastModStartDate)
	}
	if f.LastModEndDate != "" {
		p.Set("lastModEndDate", f.LastModEndDate)
	}
	if f.SourceIdentifier != "" {
		p.Set("sourceIdentifier", f.SourceIdentifier)
	}
	setBool(p, "hasKev", f.HasKev)
	setBool(p, "hasCertAlerts", f.HasCertAlerts)
	setBool(p, "hasCertNotes", f.HasCertNotes)
	setBool(p, "hasOval", f.HasOval)
	setBool(p, "isVulnerable", f.IsVulnerable)
	if f.VirtualMatchString != "" {
		p.Set("virtualMatchString", f.VirtualMatchString)
	}
	setBool(p, "noRejected", f.NoRejected)
	if f.ResultsPerPage > 0 {
		p.Set("resultsPerPage", strconv.Itoa(f.ResultsPerPage))
	}
	p.Set("startIndex", strconv.Itoa(f.StartIndex))
	return p
}

func (f Filter) cpeParams() url.Values {
	p := url.Values{}
	if f.CpeName != "" {
		p.Set("cpeName", f.CpeName)
	}
	if f.CpeMatchString != "" {
		p.Set("cpeMatchString", f.CpeMatchString)
	}
	if f.CpeNameID != "" {
		p.Set("cpeNameId", f.CpeNameID)
	}
	if f.KeywordSearch != "" {
		p.Set("keywordSearch", f.KeywordSearch)
	}
	if f.LastModStartDate != "" {
		p.Set("lastModStartDate", f.LastModStartDate)
	}
	if f.LastModEndDate != "" {
		p.Set("lastModEndDate", f.LastModEndDate)
	}
	if f.ResultsPerPage > 0 {
		p.Set("resultsPerPage", strconv.Itoa(f.ResultsPerPage))
	}
	p.Set("startIndex", strconv.Itoa(f.StartIndex))
	return p
}

func (f Filter) sourceParams() url.Values {
	p := url.Values{}
	if f.SourceIdentifier != "" {
		p.Set("sourceIdentifier", f.SourceIdentifier)
	}
	if f.SourceName != "" {
		p.Set("sourceName", f.SourceName)
	}
	if f.ResultsPerPage > 0 {
		p.Set("resultsPerPage", strconv.Itoa(f.ResultsPerPage))
	}
	p.Set("startIndex", strconv.Itoa(f.StartIndex))
	return p
}

func (c *Client) getJSON(reqURL string, out interface{}) error {
	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Header.Get("message")
		}
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("NVD API request failed: HTTP %d: %s", resp.StatusCode, msg)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) SearchCves(filter Filter) (*CVEResponse, error) {
	params := filter.cveParams()
	reqURL := c.cveBaseURL
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}
	var result CVEResponse
	if err := c.getJSON(reqURL, &result); err != nil {
		return nil, err
	}
	return &result, nil
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

func (c *Client) SearchCpes(filter Filter) (*CPEResponse, error) {
	params := filter.cpeParams()
	reqURL := c.cpeBaseURL
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}
	var result CPEResponse
	if err := c.getJSON(reqURL, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *Client) SearchSources(filter Filter) (*SourceResponse, error) {
	params := filter.sourceParams()
	reqURL := c.sourceBaseURL
	if len(params) > 0 {
		reqURL += "?" + params.Encode()
	}
	var result SourceResponse
	if err := c.getJSON(reqURL, &result); err != nil {
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
	resp, err := c.SearchCves(Filter{PubStartDate: pubStart, PubEndDate: pubEnd})
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

func (c *Client) GetModifiedCVEs(lastModStartDate, lastModEndDate string) ([]CVE, error) {
	return c.collectCVEs(Filter{
		LastModStartDate: lastModStartDate,
		LastModEndDate:   lastModEndDate,
	}, 0)
}

func (c *Client) GetModifiedCPEs(lastModStartDate, lastModEndDate string) ([]CPE, error) {
	return c.collectCPEs(Filter{
		LastModStartDate: lastModStartDate,
		LastModEndDate:   lastModEndDate,
	}, 0)
}

func (c *Client) GetAll(limit int) ([]CVE, error) {
	return c.collectCVEs(Filter{}, limit)
}

func (c *Client) collectCVEs(filter Filter, limit int) ([]CVE, error) {
	var all []CVE
	perPage := DefaultResultsPerPage
	if limit > 0 && limit < perPage {
		perPage = limit
	}
	startIndex := 0
	for {
		filter.ResultsPerPage = perPage
		filter.StartIndex = startIndex
		resp, err := c.SearchCves(filter)
		if err != nil {
			return nil, err
		}
		all = append(all, extractCVEs(resp)...)
		next := startIndex + perPage
		if next >= resp.TotalResults || (limit > 0 && len(all) >= limit) {
			break
		}
		startIndex = next
		if c.requestDelay > 0 {
			time.Sleep(c.requestDelay)
		}
	}
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

func (c *Client) collectCPEs(filter Filter, limit int) ([]CPE, error) {
	var all []CPE
	perPage := DefaultResultsPerPage
	if limit > 0 && limit < perPage {
		perPage = limit
	}
	startIndex := 0
	for {
		filter.ResultsPerPage = perPage
		filter.StartIndex = startIndex
		resp, err := c.SearchCpes(filter)
		if err != nil {
			return nil, err
		}
		for _, p := range resp.Products {
			all = append(all, p.CPE)
		}
		next := startIndex + perPage
		if next >= resp.TotalResults || (limit > 0 && len(all) >= limit) {
			break
		}
		startIndex = next
		if c.requestDelay > 0 {
			time.Sleep(c.requestDelay)
		}
	}
	if limit > 0 && len(all) > limit {
		all = all[:limit]
	}
	return all, nil
}

func (c *Client) SearchCPEs(cpeName string) ([]CPE, error) {
	resp, err := c.SearchCpes(Filter{CpeName: cpeName})
	if err != nil {
		return nil, err
	}
	out := make([]CPE, len(resp.Products))
	for i, p := range resp.Products {
		out[i] = p.CPE
	}
	return out, nil
}

func (c *Client) GetSources(sourceIdentifier string) ([]Source, error) {
	resp, err := c.SearchSources(Filter{SourceIdentifier: sourceIdentifier})
	if err != nil {
		return nil, err
	}
	return resp.Sources, nil
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
