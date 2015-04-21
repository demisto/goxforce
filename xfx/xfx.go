// xfx.go - command line interface to IBM X-force Exchange
package main

import (
	"flag"
	"fmt"
	"github.com/demisto/goxforce"
	"log"
	"os"
)

var token string
var url string
var rsrc string

func init() {
	flag.StringVar(&token, "token", os.Getenv("XFX_TOKEN"), "The token to use for X-Force access. Can be provided as an environment variable XFX_TOKEN. If not specified, anonymous access will be used.")
	flag.StringVar(&url, "url", goxforce.DefaultURL, "URL of the X-Force API to be used.")
	flag.StringVar(&rsrc, "rsrc", "8ac31b7350a95b0b492434f9ae2f1cde", "resource of file to check VT for. Resource should be md5 sum of a file.")
}

func check(e error) {
	if e != nil {
		fmt.Fprintf(os.Stderr, "Error - %v", e)
		os.Exit(1)
	}
}

func main() {
	flag.Parse()
	_, err := goxforce.New(goxforce.SetErrorLog(log.New(os.Stdout, "", log.Lshortfile)),
		goxforce.SetTraceLog(log.New(os.Stdout, "", log.Lshortfile)), goxforce.SetUrl(url))
	check(err)
}
