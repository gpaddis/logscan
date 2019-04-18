package main

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
