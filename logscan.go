package main

// Ideas:
// * http://ip-api.com/
// * https://metrics.torproject.org/exonerator.html

import (
	"fmt"
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

func createLogEntry(s string) logEntry {
	return logEntry{
		ip:       getIPAddress(s),
		status:   getResponseStatus(s),
		uri:      getRequestURI(s),
		agent:    getUserAgent(s),
		datetime: getDateTime(s),
	}
}

func (l logEntry) hasPotentialThreats() bool {
	threats := `UNION|SELECT|CHAR|CONCAT`
	match, _ := regexp.Match(threats, []byte(l.uri))
	return match
}

func getIPAddress(s string) string {
	return strings.Fields(s)[0]
}

func getResponseStatus(s string) string {
	r, _ := regexp.Compile(`\s(\d{3})\s`)
	status := r.FindString(s)
	return strings.TrimSpace(status)
}

func getRequestURI(s string) string {
	r, _ := regexp.Compile(`\s/\S+.\b`)
	URI := r.FindString(s)
	return strings.TrimSpace(URI)
}

func getUserAgent(s string) string {
	return strings.Split(s, "\"")[5]
}

func getDateTime(s string) string {
	r, _ := regexp.Compile(`\[.+\]`)
	dateTime := r.FindString(s)
	return strings.Trim(dateTime, "[]")
}

func main() {
	fmt.Println("Logscan")
}
