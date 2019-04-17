package main

import (
	"bufio"
	"fmt"
	"os"

	. "github.com/logrusorgru/aurora"
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
		r[l.ip].updateLastRequest(l.datetime)
	} else {
		r[l.ip] = &attacker{
			ip:                l.ip,
			userAgent:         l.agent,
			exampleRequest:    l.uri,
			statusCodes:       []string{l.status},
			firstRequest:      l.datetime,
			lastRequest:       l.datetime,
			maliciousRequests: 1,
		}
	}
}

// Print a report on screen with the list of attackers.
func (r report) print() {
	if len(r) == 0 {
		fmt.Println(Green("No threats found."))
		os.Exit(0)
	}

	fmt.Println(Red("Potential threats found:"))
	for _, a := range r {
		a.printRecap()
	}
}

// Scan all entries and return the ones containing suspicious
// requests in a report.
func scan(logfile string) report {
	report := make(report)
	f, err := os.Open(logfile)
	check(err)
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		raw := scanner.Text()
		if hasPotentialThreats(raw) {
			l := createLogEntry(raw)
			report.update(l)
		}
	}

	return report
}
