/*
goxforce is a library implementing the IBM X-Force Exchange API.

Written by Slavik Markovich at Demisto
*/
package goxforce

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultURL  = "https://xforce-api.mybluemix.net:443/"
	DefaultLang = "en"
)

type Error struct {
	Id     string `json:"id"`
	Detail string `json:"detail"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Id, e.Detail)
}

var (
	ErrBadToken = &Error{"bad_token", "Bad token was provided to the API"}
)

// Client interacts with the services provided by X-Force.
type Client struct {
	token    string       // The token to use for requests. If not provided, we will try and get an anonymous token.
	url      string       // X-Force URL
	lang     string       // The language to receive responses in
	errorlog *log.Logger  // Optional logger to write errors to
	tracelog *log.Logger  // Optional logger to write trace and debug data to
	c        *http.Client // The client to use for requests
}

// OptionFunc is a function that configures a Client.
// It is used in New
type OptionFunc func(*Client) error

// errorf logs to the error log.
func (c *Client) errorf(format string, args ...interface{}) {
	if c.errorlog != nil {
		c.errorlog.Printf(format, args...)
	}
}

// tracef logs to the trace log.
func (c *Client) tracef(format string, args ...interface{}) {
	if c.tracelog != nil {
		c.tracelog.Printf(format, args...)
	}
}

// New creates a new X-Force client.
//
// The caller can configure the new client by passing configuration options to the func.
//
// Example:
//
//   client, err := goxforce.New(
//     goxforce.SetUrl("https://some.url.com:port/"),
//     goxforce.SetErrorLog(log.New(os.Stderr, "X-Force: ", log.Lshortfile))
//
// If no URL is configured, Client uses DefaultURL by default.
//
// If no HttpClient is configured, then http.DefaultClient is used.
// You can use your own http.Client with some http.Transport for advanced scenarios.
//
// An error is also returned when some configuration option is invalid.
func New(options ...OptionFunc) (*Client, error) {
	// Set up the client
	c := &Client{
		url:  "",
		c:    http.DefaultClient,
		lang: DefaultLang,
	}

	// Run the options on it
	for _, option := range options {
		if err := option(c); err != nil {
			return nil, err
		}
	}
	if c.url == "" {
		c.url = DefaultURL
	}
	c.tracef("Using URL [%s]\n", c.url)

	// If no API key was specified
	if c.token == "" {
		c.tracef("No token provided, using anonymous\n")
		token, err := c.AnonymousToken()
		if err != nil {
			return nil, err
		}
		c.token = token.Token
	}

	return c, nil
}

// Initialization functions

// SetToken sets the X-Force API token to use
func SetToken(token string) OptionFunc {
	return func(c *Client) error {
		if token == "" {
			c.errorf("%v\n", ErrBadToken)
			return ErrBadToken
		}
		c.token = token
		return nil
	}
}

// SetHttpClient can be used to specify the http.Client to use when making
// HTTP requests to X-Force.
func SetHttpClient(httpClient *http.Client) OptionFunc {
	return func(c *Client) error {
		if httpClient != nil {
			c.c = httpClient
		} else {
			c.c = http.DefaultClient
		}
		return nil
	}
}

// SetUrl defines the URL endpoint X-Force
func SetUrl(rawurl string) OptionFunc {
	return func(c *Client) error {
		if rawurl == "" {
			rawurl = DefaultURL
		}
		u, err := url.Parse(rawurl)
		if err != nil {
			c.errorf("Invalid URL [%s] - %v\n", rawurl, err)
			return err
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			err := Error{"bad_url", fmt.Sprintf("Invalid schema specified [%s]", rawurl)}
			c.errorf("%v", err)
			return err
		}
		c.url = rawurl
		if !strings.HasSuffix(c.url, "/") {
			c.url += "/"
		}
		return nil
	}
}

func SetLang(lang string) OptionFunc {
	return func(c *Client) error {
		if lang == "" {
			lang = DefaultLang
		}
		c.lang = lang
		return nil
	}
}

// SetErrorLog sets the logger for critical messages. It is nil by default.
func SetErrorLog(logger *log.Logger) func(*Client) error {
	return func(c *Client) error {
		c.errorlog = logger
		return nil
	}
}

// SetTraceLog specifies the logger to use for output of trace messages like
// HTTP requests and responses. It is nil by default.
func SetTraceLog(logger *log.Logger) func(*Client) error {
	return func(c *Client) error {
		c.tracelog = logger
		return nil
	}
}

// dumpRequest dumps a request to the debug logger if it was defined
func (c *Client) dumpRequest(req *http.Request) {
	if c.tracelog != nil {
		out, err := httputil.DumpRequestOut(req, true)
		if err == nil {
			c.tracef("%s\n", string(out))
		}
	}
}

// dumpResponse dumps a response to the debug logger if it was defined
func (c *Client) dumpResponse(resp *http.Response) {
	if c.tracelog != nil {
		out, err := httputil.DumpResponse(resp, true)
		if err == nil {
			c.tracef("%s\n", string(out))
		}
	}
}

// Request handling functions

// handleError will handle responses with status code different from success
func (c *Client) handleError(resp *http.Response) error {
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		if c.errorlog != nil {
			out, err := httputil.DumpResponse(resp, true)
			if err == nil {
				c.errorf("%s\n", string(out))
			}
		}
		msg := fmt.Sprintf("Unexpected status code: %d (%s)", resp.StatusCode, http.StatusText(resp.StatusCode))
		c.errorf(msg)
		return Error{"http_error", msg}
	}
	return nil
}

// do executes the API request.
// Returns the response if the status code is between 200 and 299
// `body` is an optional body for the POST requests.
func (c *Client) do(method, rawurl string, params map[string]string, body io.Reader, result interface{}) error {
	if len(params) > 0 {
		values := url.Values{}
		for k, v := range params {
			values.Add(k, v)
		}
		rawurl += "?" + values.Encode()
	}

	req, err := http.NewRequest(method, c.url+rawurl, body)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.token))
	}
	if c.lang != "" {
		req.Header.Set("Accept-Language", c.lang)
	}
	req.Header.Set("Accept", "application/json")
	var t time.Time
	if c.tracelog != nil {
		c.dumpRequest(req)
		t = time.Now()
		c.tracef("Start request %s at %v", rawurl, t)
	}
	resp, err := c.c.Do(req)
	if c.tracelog != nil {
		c.tracef("End request %s at %v - took %v", rawurl, time.Now(), time.Since(t))
	}
	if err != nil {
		return err
	}
	if resp.Body != nil {
		defer resp.Body.Close()
	}
	if err = c.handleError(resp); err != nil {
		return err
	}
	c.dumpResponse(resp)
	if result != nil {
		switch result.(type) {
		// Should we just dump the response body
		case io.Writer:
			if _, err = io.Copy(result.(io.Writer), resp.Body); err != nil {
				return err
			}
		default:
			if err = json.NewDecoder(resp.Body).Decode(result); err != nil {
				return err
			}
		}
	}
	return nil
}

// Structs for responses

type AuthResp struct {
	Token string `json:"token"`
}

type AppResp struct {
	CanonicalNames []string `json:"canonicalNames"`
}

type AppBaseDetails struct {
	CanonicalName string  `json:"canonicalName"`
	Name          string  `json:"name"`
	Description   string  `json:"description"`
	Score         float32 `json:"score"`
}

type AppsFullTextResp struct {
	Applications []AppBaseDetails `json:"applications"`
}

type ValueDesc struct {
	Value       int    `json:"value"`
	Description string `json:"description"`
}

type AppDetails struct {
	CanonicalName string               `json:"canonicalName"`
	Name          string               `json:"name"`
	Description   string               `json:"description"`
	Categories    map[string]bool      `json:"categories"`
	Actions       map[string]bool      `json:"actions"`
	Rlfs          map[string]ValueDesc `json:"rlfs"`
	Score         float32              `json:"score"`
	BaseURL       string               `json:"baseurl"`
	URLs          []string             `json:"urls"`
}

type AppProfile struct {
	Application AppDetails `json:"application"`
}

type IPDetails struct {
	Geo     map[string]interface{} `json:"geo"`
	IP      string                 `json:"ip"`
	Reason  string                 `json:"reason"`
	Created time.Time              `json:"created"`
	Score   float32                `json:"score"`
	Cats    map[string]int         `json:"cats"`
	Subnet  string                 `json:"subnet"`
}

type IPReputation struct {
	IP      string                 `json:"ip"`
	Subnets []IPDetails            `json:"subnets"`
	Cats    map[string]int         `json:"cats"`
	Geo     map[string]interface{} `json:"geo"`
	Score   float32                `json:"score"`
}

type IPHistory struct {
	IP      string      `json:"ip"`
	Subnets []IPDetails `json:"subnets"`
	History []IPDetails `json:"history"`
}

type IPMalware struct {
	First  time.Time `json:"first"`
	Last   time.Time `json:"last"`
	MD5    string    `json:"md5"`
	Family []string  `json:"family"`
	Origin string    `json:"origin"`
	URI    string    `json:"uri"`
}

type IPMalwareResp struct {
	Malware []IPMalware `json:"malware"`
}

type MX struct {
	Exchange string `json:"exchange"`
	Priority int    `json:"priority"`
}

type ResolveResp struct {
	A    []string
	AAAA []string
	TXT  []string
	MX   []MX
}

type Url struct {
	Url   string          `json:"url"`
	Cats  map[string]bool `json:"cats"`
	Score float32         `json:"score"`
}

type UrlResp struct {
	Result Url `json:"result"`
}

type UrlMalwareResp struct {
	Malware []Details `json:"malware"`
	Count   int       `json:count"`
}

type Details struct {
	Type      string    `json:"type"`
	MD5       string    `json:"md5"`
	Domain    string    `json:"domain"`
	FirstSeen time.Time `json:"firstseen"`
	LastSeen  time.Time `json:"lastseen"`
	IP        string    `json:"ip"`
	Count     int       `json:"count"`
	Filepath  string    `json:"filepath"`
	Origin    string    `json:"origin"`
	URI       string    `json:"uri"`
	// Download servers specific
	Host   string `json:"host"`
	Schema string `json:"schema"`
	// Subject specific
	Subject string   `json"subject"`
	IPs     []string `json:"ips"`
	// CnC specific
	Family []string `json:"family"`
}

type DetailsCount struct {
	Rows  []Details `json:"rows"`
	Count int       `json:"count"`
}

type Count struct {
	Count int `json:"count"`
}

type Origins struct {
	Emails          DetailsCount `json:"emails"`
	Subjects        DetailsCount `json:"subjects"`
	DownloadServers DetailsCount `json:"downloadServers"`
	CnCServers      DetailsCount `json:"CnCServers"`
	External        struct {
		DetectionCoverage int      `json:"detectionCoverage"`
		Family            []string `json:"family"`
	} `json:"external"`
}

type MalwareBase struct {
	Type     string    `json:"type"`
	Created  time.Time `json:"created"`
	MD5      string    `json:"md5"`
	Family   []string  `json:"family"`
	MimeType string    `json:"mimetype"`
}

type Malware struct {
	MalwareBase
	Origins       Origins          `json:"origins"`
	FamilyMembers map[string]Count `json:"familyMembers"`
}

type MalwareResp struct {
	Malware Malware `json:"malware"`
}

type MalwareFamilyResp struct {
	FirstSeen time.Time     `json:"firstseen"`
	LastSeen  time.Time     `json:"lastseen"`
	Family    []string      `json:"family"`
	Malware   []MalwareBase `json:"malware"`
}

type Reference struct {
	LinkTarget  string `json:"link_target"`
	LinkName    string `json:"link_name"`
	Description string `json:"description"`
}

type Signature struct {
	Coverage     string    `json:"coverage"`
	CoverageDate time.Time `json:"coverage_date"`
}

type Vulnerability struct {
	Type                  string      `json:"type"`
	Xfdbid                int         `json:"xfdbid"`
	Updateid              int         `json:"updateid"`
	Updated               bool        `json:"updated"`
	Inserted              bool        `json:"inserted"`
	Variant               string      `json:"variant"`
	Title                 string      `json:"title"`
	Description           string      `json:"description"`
	DescriptionFmt        string      `json:"description_fmt"`
	RiskLevel             float32     `json:"risk_level"`
	AccessVector          string      `json:"access_vector"`
	AccessComplexity      string      `json:"access_complexity"`
	Authentication        string      `json:"authentication"`
	ConfidentialityImpact string      `json:"confidentiality_impact"`
	IntegrityImpact       string      `json:"integrity_impact"`
	AvailabilityImpact    string      `json:"availability_impact"`
	TemporalScore         float32     `json:"temporal_score"`
	RemediationLevel      string      `json:"remediation_level"`
	Remedy                string      `json:"remedy"`
	RemedyFmt             string      `json:"remedy_fmt"`
	Reported              time.Time   `json:"reported"`
	Tagname               string      `json:"tagname"`
	Stdcode               []string    `json:"stdcode"`
	PlatformsAffected     []string    `json:"platforms_affected"`
	PlatformsDependent    []string    `json:"platforms_dependent"`
	Exploitability        string      `json:"exploitability"`
	Consequences          string      `json:"consequences"`
	References            []Reference `json:"references"`
	Signatures            []Signature `json:"signatures"`
	ReportConfidence      string      `json:"report_confidence"`
}

type VulnerabilitySearchResp struct {
	TotalRows int             `json:"total_rows"`
	Bookmark  string          `json:"bookmark"`
	Rows      []Vulnerability `json:"rows"`
}

// See https://xforce-api.mybluemix.net/doc/#!/Authentication/auth_anonymousToken_get
func (c *Client) AnonymousToken() (*AuthResp, error) {
	var result AuthResp
	err := c.do("GET", "auth/anonymousToken", nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/Internet_Application_Profile/app__get
func (c *Client) InternetAppProfiles() (*AppResp, error) {
	var result AppResp
	err := c.do("GET", "app/", nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/Internet_Application_Profile/apps_fulltext_get
func (c *Client) InternetAppsSearch(q string) (*AppsFullTextResp, error) {
	var result AppsFullTextResp
	err := c.do("GET", "apps/fulltext", map[string]string{"q": q}, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/Internet_Application_Profile/apps_fulltext_get
func (c *Client) InternetAppByName(name string) (*AppProfile, error) {
	var result AppProfile
	err := c.do("GET", "app/"+name, nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/IP_Reputation/ipr_ip_get
func (c *Client) IPR(ip string) (*IPReputation, error) {
	var result IPReputation
	err := c.do("GET", "ipr/"+ip, nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/IP_Reputation/ipr_history_ip_get
func (c *Client) IPRHistory(ip string) (*IPHistory, error) {
	var result IPHistory
	err := c.do("GET", "ipr/history/"+ip, nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/IP_Reputation/ipr_malware_ip_get
func (c *Client) IPRMalware(ip string) (*IPMalwareResp, error) {
	var result IPMalwareResp
	err := c.do("GET", "ipr/malware/"+ip, nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/DNS/resolve_input_get
func (c *Client) Resolve(q string) (*ResolveResp, error) {
	var result ResolveResp
	err := c.do("GET", "resolve/"+q, nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/URL/url_url_get
func (c *Client) Url(q string) (*UrlResp, error) {
	var result UrlResp
	err := c.do("GET", "url/"+q, nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/URL/url_malware_url_get
func (c *Client) UrlMalware(q string) (*UrlMalwareResp, error) {
	var result UrlMalwareResp
	err := c.do("GET", "url/malware/"+q, nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/Malware/malware_md5_get
func (c *Client) MalwareDetails(md5 string) (*MalwareResp, error) {
	var result MalwareResp
	err := c.do("GET", "malware/"+md5, nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/Malware/malware_family_family_get
func (c *Client) MalwareFamilyDetails(name string) (*MalwareFamilyResp, error) {
	var result MalwareFamilyResp
	err := c.do("GET", "malware/family/"+name, nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/Vulnerabilities/vulnerabilities__get
func (c *Client) Vulnerabilities(limit int) ([]Vulnerability, error) {
	var result []Vulnerability
	err := c.do("GET", "vulnerabilities", map[string]string{"limit": strconv.Itoa(limit)}, nil, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/Vulnerabilities/vulnerabilities_fulltext_get
// TODO - You should be able to use the bookmark to scroll the results if more than 200 rows - currently not officially supported
func (c *Client) VulnerabilitiesFullText(q, bookmark string) (*VulnerabilitySearchResp, error) {
	var result VulnerabilitySearchResp
	params := make(map[string]string)
	params["q"] = q
	if bookmark != "" {
		params["bookmark"] = bookmark
	}
	err := c.do("GET", "vulnerabilities/fulltext", params, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/Vulnerabilities/vulnerabilities_xfid_get
func (c *Client) VulnerabilityByXFID(xfid int) (*Vulnerability, error) {
	var result Vulnerability
	err := c.do("GET", "vulnerabilities/"+strconv.Itoa(xfid), nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/Vulnerabilities/vulnerabilities_search_stdcode_get
func (c *Client) VulnerabilityByCVE(cve string) ([]Vulnerability, error) {
	var result []Vulnerability
	err := c.do("GET", "vulnerabilities/search/"+cve, nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
