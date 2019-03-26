package main

// Ideas:
// * http://ip-api.com/
// * https://metrics.torproject.org/exonerator.html

import (
	"fmt"
	"strings"
)

func getIpAddress(logEntry string) string {
	return strings.Fields(logEntry)[0]
}

func main() {
	fmt.Println("Logscan")
}
