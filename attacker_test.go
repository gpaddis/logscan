package main

import "testing"

func TestIncrementMaliciousRequests(t *testing.T) {
	a := attacker{maliciousRequests: 1}
	a.incrementMaliciousRequests()
	if got := a.maliciousRequests; got != 2 {
		t.Errorf("Expecting 2 malicious requests, got %d.", got)
	}
}

func TestUpdateStatusCodes(t *testing.T) {
	a := attacker{statusCodes: []string{"200"}}
	a.updateStatusCodes("200")
	a.updateStatusCodes("400")
	if got := a.statusCodes; len(got) != 2 {
		t.Errorf("Expecting 2 status codes, got %d.", len(got))
	}
}

func TestUpdateLastRequestShouldKeepMostRecentDateTime(t *testing.T) {
	a := attacker{lastRequest: "11/Mar/2019:12:36:29 +0100"}
	a.updateLastRequest("11/Mar/2019:12:36:28 +0100")
	if a.lastRequest != "11/Mar/2019:12:36:29 +0100" {
		t.Errorf("updateLastRequest should have kept the most recent date/time.")
	}

	a.updateLastRequest("11/Mar/2019:12:39:28 +0100")
	if a.lastRequest != "11/Mar/2019:12:39:28 +0100" {
		t.Errorf("updateLastRequest should have updated the lastRequest field with the most recent date/time.")
	}
}

func TestQueryIpApi(t *testing.T) {
	res := queryIpApi("172.217.18.174")
	expected := `{"as":"AS15169 Google LLC","city":"Frankfurt am Main","country":"Germany","countryCode":"DE","isp":"Google LLC","lat":50.1109,"lon":8.68213,"org":"Google LLC","query":"172.217.18.174","region":"HE","regionName":"Hesse","status":"success","timezone":"Europe/Berlin","zip":"60313"}`
	if string(res) != expected {
		t.Errorf("Error: got %s", res)
	}
}

func TestGeoLocateExistingIp(t *testing.T) {
	ip := "172.217.18.174"
	locInfo, _ := geoLocate(ip)
	if locInfo["as"] != "AS15169 Google LLC" {
		t.Errorf("Expecting AS15169 Google LLC, got %s.", locInfo["as"])
	}
}

func TestGeoLocateReservedIp(t *testing.T) {
	ip := "127.0.0.1"
	_, err := geoLocate(ip)
	if err == nil {
		t.Errorf("Expecting geoLocate() to fail, got a positive response instead..")
	}
}
