package main

// Ideas:
// * http://ip-api.com/
// * https://metrics.torproject.org/exonerator.html

import (
	"fmt"
	"strings"
)

func getIPAddress(s string) string {
	return strings.Fields(s)[0]
}

func getResponseStatus(s string) string {
	return strings.Fields(s)[8]
}

func main() {
	fmt.Println("Logscan")
}
