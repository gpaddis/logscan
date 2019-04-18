package main

import (
	"fmt"

	. "github.com/logrusorgru/aurora"
)

type attacker struct {
	ip                string
	userAgent         string
	statusCodes       []string
	exampleRequest    string
	firstRequest      string
	lastRequest       string
	maliciousRequests int
}

// Increment the count of malicious requests from an attacker.
func (a *attacker) incrementMaliciousRequests() {
	a.maliciousRequests++
}

// Add new status codes to the existing slice.
func (a *attacker) updateStatusCodes(s string) {
	if a.hasStatusCode(s) == false {
		a.statusCodes = append(a.statusCodes, s)
	}
}

// Update the datetime of the last request.
func (a *attacker) updateLastRequest(d string) {
	a.lastRequest = d
}

// Return true if the status code is already in the slice.
func (a *attacker) hasStatusCode(s string) bool {
	for _, a := range a.statusCodes {
		if a == s {
			return true
		}
	}
	return false
}

// Print aggregated info on an attacker in the log file.
func (a *attacker) printRecap() {
	fmt.Printf("%s Found %d malicious requests from IP address %s ", Red("[+]"), Bold(a.maliciousRequests), Bold(a.ip))
	fmt.Printf("between %s and %s\n", a.firstRequest, a.lastRequest)
	fmt.Printf("User agent: %s\n", a.userAgent)
	fmt.Printf("Status codes: ")
	for _, s := range a.statusCodes {
		fmt.Printf("%s ", Bold(s))
	}
	fmt.Printf("\nExample request: %s\n\n", a.exampleRequest)
}
