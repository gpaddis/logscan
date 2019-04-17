package main

import (
	"bufio"
	"fmt"
	"os"
)

type report map[string]*attacker

// Check if the report already contains the IP of an attacker.
func (r report) hasIP(ip string) bool {
	if _, ok := r[ip]; ok {
		return true
	}
	return false
}

// Add an attacker entry to the report or update an existing one.
func (r report) update(l logEntry) {
	if r.hasIP(l.ip) {
		r[l.ip].incrementMaliciousRequests()
		r[l.ip].updateStatusCodes(l.status)
	} else {
		r[l.ip] = &attacker{
			ip:                l.ip,
			userAgent:         l.agent,
			exampleRequest:    l.uri,
			statusCodes:       []string{l.status},
			maliciousRequests: 1,
		}
	}
}

// Print a report on screen with the list of attackers.
func (r report) print() {
	for _, a := range r {
		fmt.Println("Potential threat:")
		fmt.Printf("Got %d malicious requests from %s with following status codes: ", a.maliciousRequests, a.ip)
		for _, s := range a.statusCodes {
			fmt.Printf("%s ", s)
		}
		fmt.Printf("\nExample request: %s\n", a.exampleRequest)
	}
}

// Scan all entries and collect the ones containing suspicious requests.
func scan(logfile string) report {
	report := make(report)

	f, err := os.Open(logfile)
	check(err)
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		l := createLogEntry(scanner.Text())
		if l.hasPotentialThreats() {
			report.update(l)
		}
	}

	return report
}
