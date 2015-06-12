package goxforce

import (
	"testing"
)

func check(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}

func TestInternetAppProfiles(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.InternetAppProfiles()
	check(t, err)
	if len(r.CanonicalNames) <= 0 {
		t.Errorf("Could not load internet profile names - %v\n", r)
	}
}

func TestInternetAppsSearch(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.InternetAppsSearch("youtube.com")
	check(t, err)
	if len(r.Applications) <= 0 {
		t.Errorf("Could not find the YouTube app profile - %v\n", r)
	}
}

func TestInternetAppByName(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.InternetAppByName("youtube")
	check(t, err)
	if r.Application.Name == "" {
		t.Errorf("Could not find the YouTube app profile by name - %v\n", r)
	}
}

func TestIPR(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.IPR("72.52.4.119")
	check(t, err)
	if r.IP == "" || len(r.Geo) == 0 {
		t.Errorf("Could not get IP Reputation - %v\n", r)
	}
}

func TestIPRHistory(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.IPRHistory("72.52.4.119")
	check(t, err)
	if r.IP == "" || len(r.History) == 0 {
		t.Errorf("Could not get IP history - %v\n", r)
	}
}

func TestIPRMalware(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.IPRMalware("72.52.4.119")
	check(t, err)
	if len(r.Malware) == 0 {
		t.Errorf("Could not get IP malware - %v\n", r)
	}
}

func TestResolve(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.Resolve("http://www.e-realize.com/netenum4941b.exe")
	check(t, err)
	if len(r.A) == 0 {
		t.Errorf("Could not get resolve URL - %v\n", r)
	}
}

func TestURL(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.URL("http://www.e-realize.com/netenum4941b.exe")
	check(t, err)
	if r.Result.URL == "" || len(r.Result.Cats) == 0 {
		t.Errorf("Could not get URL reputation - %v\n", r)
	}
}

func TestURLMalware(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.URLMalware("mediaget.com")
	check(t, err)
	if len(r.Malware) == 0 {
		t.Errorf("Could not get URL malware - %v\n", r)
	}
}

func TestMalwareDetails(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.MalwareDetails("3018E99857F31A59E0777396AE634A8F")
	check(t, err)
	if r.Malware.MD5 == "" || r.Malware.Type == "" {
		t.Errorf("Could not get malware details - %v\n", r)
	}
}

func TestMalwareFamilyDetails(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.MalwareFamilyDetails("Worm.NetSky-14")
	check(t, err)
	if len(r.Malware) == 0 {
		t.Errorf("Could not get malware family details - %v\n", r)
	}
}

func TestVulnerabilities(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.Vulnerabilities(10)
	check(t, err)
	if len(r) != 10 {
		t.Errorf("Did not retrieve the first 10 vulnerabilities - %v\n", r)
	}
}

func TestVulnerabilitiesFullText(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.VulnerabilitiesFullText("Heartbleed", "")
	check(t, err)
	if len(r.Rows) == 0 {
		t.Errorf("Did not find Heartbleed vulnerability - %v\n", r)
	}
}

func TestVulnerabilityByXFID(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.VulnerabilityByXFID(92744)
	check(t, err)
	if r.Xfdbid == 0 {
		t.Errorf("Did not find vulnerability by XFID - %v\n", r)
	}
}

func TestVulnerabilityByCVE(t *testing.T) {
	c, err := New()
	check(t, err)
	r, err := c.VulnerabilityByCVE("CVE-2014-2601")
	check(t, err)
	if len(r) == 0 {
		t.Errorf("Did not find vulnerability by CVE - %v\n", r)
	}
}
