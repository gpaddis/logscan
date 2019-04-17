package main

import (
	"strings"
)

type logEntry struct {
	ip       string
	status   string
	uri      string
	agent    string
	datetime string
}

// Create a logEntry from a raw Apache access.log string.
func createLogEntry(s string) logEntry {
	return logEntry{
		ip:       getIPAddress(s),
		status:   getResponseStatus(s),
		uri:      getRequestURI(s),
		agent:    getUserAgent(s),
		datetime: getDateTime(s),
	}
}

// Return true if a logEntry URI matches the threat pattern.
// The patterns are matched both in lower and upper case.
func (l logEntry) hasPotentialThreats() bool {
	threats := []string{"%20AND", "UNION", "SELECT%20", "CONCAT", "%20WHERE"}
	URI := strings.ToUpper(l.uri)
	for _, t := range threats {
		if strings.Contains(URI, t) {
			return true
		}
	}
	return false
}

func getIPAddress(s string) string {
	return strings.Fields(s)[0]
}

func getResponseStatus(s string) string {
	return strings.Split(s, " ")[8]
}

func getRequestURI(s string) string {
	return strings.Split(s, " ")[6]
}

func getUserAgent(s string) string {
	return strings.Split(s, "\"")[5]
}

func getDateTime(s string) string {
	splitted := strings.Split(s, " ")
	dateTime := splitted[3] + " " + splitted[4]
	return strings.Trim(dateTime, "[]")
}
