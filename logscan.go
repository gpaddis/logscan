package main

import (
	"flag"
	"fmt"
	"os"
)

// Ideas:
// * http://ip-api.com/
// * https://metrics.torproject.org/exonerator.html

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	// Get and parse parameters
	accesslogPtr := flag.String("logfile", "", "The access.log file you want to analyze")
	flag.Parse()

	if _, err := os.Stat(*accesslogPtr); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Scan the access.log file
	// Aggregate data
	// Print the data to stdout
	// Exit with status 0 or 1
	fmt.Println("Logscan")
	report := scan(*accesslogPtr)
	report.print()
}
