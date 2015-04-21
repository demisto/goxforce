// xfx.go - command line interface to IBM X-force Exchange
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/demisto/goxforce"
	"log"
	"os"
	"strings"
)

var token string
var url string
var cmd string
var q string
var v bool

func init() {
	flag.StringVar(&token, "token", os.Getenv("XFX_TOKEN"), "The token to use for X-Force access. Can be provided as an environment variable XFX_TOKEN. If not specified, anonymous access will be used.")
	flag.StringVar(&url, "url", goxforce.DefaultURL, "URL of the X-Force API to be used.")
	flag.StringVar(&cmd, "cmd", "", "The command to execute: listApps/searchApp/appDetails/ipr/iprhist/iprmalware")
	flag.StringVar(&q, "q", "", "The search or parameter for the command")
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
		goxforce.SetUrl(url))
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
		res, err = c.InternetApps(q)
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
	default:
		fmt.Fprintf(os.Stderr, "Command [%s] is not recognized\n", cmd)
		os.Exit(1)
	}
	check(err)
	b, err := json.MarshalIndent(res, "", "\t")
	check(err)
	fmt.Println(string(b))
}
