package main

import (
	"bufio"
	"fmt"
	"os"
)

type report map[string]attacker

type attacker struct {
	ip                string
	userAgent         string
	statusCodes       []string
	exampleRequest    string
	maliciousRequests int
}

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
		// TODO: how to work with a pointer and update the struct field?
		a := r[l.ip]
		a.incrementMaliciousRequests()
		r[l.ip] = a
	} else {
		r[l.ip] = attacker{
			ip:                l.ip,
			userAgent:         l.agent,
			exampleRequest:    l.uri,
			statusCodes:       []string{l.status},
			maliciousRequests: 1,
		}
	}
}

// Increment the count of malicious requests from an attacker.
func (a *attacker) incrementMaliciousRequests() {
	a.maliciousRequests++
}

// Scan all entries and collect the ones containing suspicious requests.
func scan(logfile string) {
	report := make(report)

	f, err := os.Open(logfile)
	check(err)
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		e := createLogEntry(scanner.Text())
		if e.hasPotentialThreats() {
			// check if report already contains an attacker
			if report.hasIP(e.ip) {
				// update the attacker info
				fmt.Println("Ip is in map")
			} else {
				// otherwise create an attacker and add it to the report
				fmt.Println("Value not in map. Adding...")
				report[e.ip] = attacker{}
			}
			// add the info
		}
	}
}