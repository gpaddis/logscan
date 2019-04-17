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
