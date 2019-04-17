package main

import (
	"regexp"
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
func (l logEntry) hasPotentialThreats() bool {
	threats := `%20AND|UNION|SELECT|CHAR|CONCAT`
	match, _ := regexp.Match(threats, []byte(l.uri))
	return match
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
