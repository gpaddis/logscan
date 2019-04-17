package main

import "testing"

func TestHasIP(t *testing.T) {
	ip := "127.0.0.1"
	r := make(report)

	if r.hasIP(ip) {
		t.Error("Got true, expecting false.")
	}

	r[ip] = &attacker{}
	if r.hasIP(ip) == false {
		t.Error("Got false, expecting true.")
	}
}

func TestInitReportEntry(t *testing.T) {
	r := make(report)
	l := logEntry{
		ip:       "127.0.0.1",
		status:   "200",
		uri:      "/test?%20AND%20SELECT",
		agent:    "malicious agent",
		datetime: "11/Mar/2019:12:36:29 +0100",
	}

	r.update(l)
	expected := attacker{
		ip:                l.ip,
		userAgent:         l.agent,
		statusCodes:       []string{"200"},
		exampleRequest:    l.uri,
		maliciousRequests: 1,
	}

	// Test a random struct field
	if r[l.ip].exampleRequest != expected.exampleRequest {
		t.Error("Expecting the report to contain an attacker.")
	}
}

func TestUpdateReportEntry(t *testing.T) {
	r := make(report)
	l := logEntry{
		ip:       "127.0.0.1",
		status:   "200",
		uri:      "/test?%20AND%20SELECT",
		agent:    "malicious agent",
		datetime: "11/Mar/2019:12:36:29 +0100",
	}

	r.update(l)
	l.status = "400"
	r.update(l)

	if got := r[l.ip].maliciousRequests; got != 2 {
		t.Errorf("Expecting 2 malicious requests, got %d.", got)
	}

	if got := r[l.ip].statusCodes; len(got) != 2 {
		t.Errorf("Expecting 2 status codes, got %d.", len(got))
	}
}

func TestScan(t *testing.T) {
	r := scan("testdata/example-access.log")

	if got := len(r); got != 2 {
		t.Errorf("Expected 2 attacks in the report, got %d.", got)
	}
}
