/*
goxforce is a library implementing the IBM X-Force Exchange API.

Written by Slavik Markovich at Demisto
*/
package goxforce

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultURL = "https://xforce-api.mybluemix.net:443/"
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
		url: "",
		c:   http.DefaultClient,
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
		c.tracef("No token provided, using anonymous")
		if err := c.AnonymousToken(); err != nil {
			return nil, err
		}
	}

	return c, nil
}

// Initialization functions

// SetToken sets the X-Force API token to use
func SetToken(token string) OptionFunc {
	return func(c *Client) error {
		if token == "" {
			c.errorf("%v", ErrBadToken)
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
			err := fmt.Errorf("Invalid schema specified [%s]", rawurl)
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
		return errors.New(msg)
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

type Token struct {
	Token string `json:"token"`
}

type AppProfileNames struct {
	CanonicalNames []string `json:"canonicalNames"`
}

type AppBaseDetails struct {
	CanonicalName string  `json:"canonicalName"`
	Name          string  `json:"name"`
	Description   string  `json:"description"`
	Score         float32 `json:"score"`
}

type Apps struct {
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
	Score   int                    `json:"score"`
	Cats    map[string]int         `json:"cats"`
	Subnet  string                 `json:"subnet"`
}

type IPReputation struct {
	IP      string                 `json:"ip"`
	Subnets []IPDetails            `json:"subnets"`
	Cats    map[string]int         `json:"cats"`
	Geo     map[string]interface{} `json:"geo"`
	Score   int                    `json:"score"`
}

type IPHistory struct {
	IP      string      `json:"ip"`
	Subnets []IPDetails `json:"subnets"`
	History []IPDetails `json:"history"`
}

type Malware struct {
	First  time.Time `json:"first"`
	Last   time.Time `json:"last"`
	MD5    string    `json:"md5"`
	Family string    `json:"family"`
	Origin string    `json:"origin"`
	URI    string    `json:"uri"`
}

type IPMalware struct {
	Malware []Malware `json:"malware"`
}

type MX struct {
	Exchange string `json:"exchange"`
	Priority int    `json:"priority"`
}

type Resolution struct {
	A    []string
	AAAA []string
	TXT  []string
	MX   []MX
}

// See https://xforce-api.mybluemix.net/doc/#!/Authentication/auth_anonymousToken_get
func (c *Client) AnonymousToken() error {
	var result Token
	err := c.do("GET", "auth/anonymousToken", nil, nil, &result)
	if err == nil {
		c.token = result.Token
	}
	return err
}

// See https://xforce-api.mybluemix.net/doc/#!/Internet_Application_Profile/app__get
func (c *Client) InternetAppProfiles() (*AppProfileNames, error) {
	var result AppProfileNames
	err := c.do("GET", "app/", nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/Internet_Application_Profile/apps_fulltext_get
func (c *Client) InternetApps(q string) (*Apps, error) {
	var result Apps
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
func (c *Client) IPRMalware(ip string) (*IPMalware, error) {
	var result IPMalware
	err := c.do("GET", "ipr/malware/"+ip, nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

// See https://xforce-api.mybluemix.net/doc/#!/DNS/resolve_input_get
func (c *Client) Resolve(q string) (*Resolution, error) {
	var result Resolution
	err := c.do("GET", "resolve/"+q, nil, nil, &result)
	if err != nil {
		return nil, err
	}
	return &result, nil
}
