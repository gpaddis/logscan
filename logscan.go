package main

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
