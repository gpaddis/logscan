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

// Return true if a raw entry matches the threat pattern.
// The patterns are matched both in lower and upper case.
func hasPotentialThreats(raw string) bool {
	threats := []string{"%20AND", "UNION", "SELECT%20", "CONCAT", "%20WHERE"}
	for _, t := range threats {
		if strings.Contains(strings.ToUpper(raw), t) {
			return true
		}
	}
	return false
}

func getIPAddress(s string) string {
	return strings.Fields(s)[0]
}

func getResponseStatus(s string) string {
	return strings.Fields(s)[8]
}

func getRequestURI(s string) string {
	return strings.Fields(s)[6]
}

func getUserAgent(s string) string {
	return strings.Split(s, "\"")[5]
}

func getDateTime(s string) string {
	splitted := strings.Fields(s)
	dateTime := splitted[3] + " " + splitted[4]
	return strings.Trim(dateTime, "[]")
}
