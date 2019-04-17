package main

type attacker struct {
	ip                string
	userAgent         string
	statusCodes       []string
	exampleRequest    string
	maliciousRequests int
}

// Increment the count of malicious requests from an attacker.
func (a *attacker) incrementMaliciousRequests() {
	a.maliciousRequests++
}

func (a *attacker) updateStatusCodes(s string) {
	if a.hasStatusCode(s) == false {
		a.statusCodes = append(a.statusCodes, s)
	}
}

func (a *attacker) hasStatusCode(s string) bool {
	for _, a := range a.statusCodes {
		if a == s {
			return true
		}
	}
	return false
}
