// xfe.go - command line interface to IBM X-force Exchange
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/demisto/goxforce"
	"log"
	"os"
	"strconv"
	"strings"
)

var token string
var url string
var lang string
var cmd string
var q string
var q2 string
var v bool

func init() {
	flag.StringVar(&token, "token", os.Getenv("XFE_TOKEN"), "The token to use for X-Force access. Can be provided as an environment variable XFE_TOKEN. If not specified, anonymous access will be used.")
	flag.StringVar(&url, "url", goxforce.DefaultURL, "URL of the X-Force API to be used.")
	flag.StringVar(&lang, "lang", goxforce.DefaultLang, "The language to accept responses in")
	flag.StringVar(&cmd, "cmd", "", "The command to execute: listApps/searchApp/appDetails/ipr/iprhist/iprmalware/resolve/url/urlmalware/malware/malwarefamily/vulns/searchVulns/xfid/cve")
	flag.StringVar(&q, "q", "", "The search or parameter for the command")
	flag.StringVar(&q2, "q2", "", "Additional parameter for commands that might require 2 parameters")
	flag.BoolVar(&v, "v", false, "Verbosity. If specified will trace the requests.")
}

func check(e error) {
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error - %v\n", e)
		os.Exit(2)
	}
}

func main() {
	flag.Parse()
	if cmd == "" {
		fmt.Fprintf(os.Stderr, "No command given\n")
		os.Exit(1)
	}
	c, err := goxforce.New(goxforce.SetErrorLog(log.New(os.Stderr, "", log.Lshortfile)),
		goxforce.SetUrl(url), goxforce.SetLang(lang))
	check(err)
	if v {
		goxforce.SetTraceLog(log.New(os.Stderr, "", log.Lshortfile))(c)
	}
	var res interface{}
	switch strings.ToLower(cmd) {
	case "listapps":
		res, err = c.InternetAppProfiles()
	case "searchapp":
		if q == "" {
			fmt.Fprintf(os.Stderr, "You must specify the app text you are searching\n")
			os.Exit(1)
		}
		res, err = c.InternetAppsSearch(q)
	case "appdetails":
		if q == "" {
			fmt.Fprintf(os.Stderr, "You must specify the app name\n")
			os.Exit(1)
		}
		res, err = c.InternetAppByName(q)
	case "ipr":
		if q == "" {
			fmt.Fprintf(os.Stderr, "You must specify the IP\n")
			os.Exit(1)
		}
		res, err = c.IPR(q)
	case "iprhist":
		if q == "" {
			fmt.Fprintf(os.Stderr, "You must specify the IP\n")
			os.Exit(1)
		}
		res, err = c.IPRHistory(q)
	case "iprmalware":
		if q == "" {
			fmt.Fprintf(os.Stderr, "You must specify the IP\n")
			os.Exit(1)
		}
		res, err = c.IPRMalware(q)
	case "resolve":
		if q == "" {
			fmt.Fprintf(os.Stderr, "You must specify what to resolve (domain/IP/URL)\n")
			os.Exit(1)
		}
		res, err = c.Resolve(q)
	case "url":
		if q == "" {
			fmt.Fprintf(os.Stderr, "You must specify the URL\n")
			os.Exit(1)
		}
		res, err = c.Url(q)
	case "urlmalware":
		if q == "" {
			fmt.Fprintf(os.Stderr, "You must specify the URL\n")
			os.Exit(1)
		}
		res, err = c.UrlMalware(q)
	case "malware":
		if q == "" {
			fmt.Fprintf(os.Stderr, "You must specify the MD5 of the malware\n")
			os.Exit(1)
		}
		res, err = c.MalwareDetails(q)
	case "malwarefamily":
		if q == "" {
			fmt.Fprintf(os.Stderr, "You must specify the name of the malware family\n")
			os.Exit(1)
		}
		res, err = c.MalwareFamilyDetails(q)
	case "vulns":
		if q == "" {
			q = "10"
		}
		limit, convErr := strconv.Atoi(q)
		check(convErr)
		res, err = c.Vulnerabilities(limit)
	case "searchvulns":
		if q == "" {
			fmt.Fprintf(os.Stderr, "You must specify the text to search\n")
			os.Exit(1)
		}
		res, err = c.VulnerabilitiesFullText(q, q2)
	case "xfid":
		if q == "" {
			fmt.Fprintf(os.Stderr, "You must specify the XFID to retrieve\n")
			os.Exit(1)
		}
		xfid, convErr := strconv.Atoi(q)
		check(convErr)
		res, err = c.VulnerabilityByXFID(xfid)
	case "cve":
		if q == "" {
			fmt.Fprintf(os.Stderr, "You must specify the CVE to retrieve\n")
			os.Exit(1)
		}
		res, err = c.VulnerabilityByCVE(q)
	default:
		fmt.Fprintf(os.Stderr, "Command [%s] is not recognized\n", cmd)
		os.Exit(1)
	}
	check(err)
	b, err := json.MarshalIndent(res, "", "\t")
	check(err)
	fmt.Println(string(b))
}
