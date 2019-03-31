package main

// Ideas:
// * http://ip-api.com/
// * https://metrics.torproject.org/exonerator.html

import (
	"fmt"
	"regexp"
	"strings"
)

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

func main() {
	fmt.Println("Logscan")
}
