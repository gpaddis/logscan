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
	strictPtr := flag.Bool("strict", false, "Strict mode: return with error code 1 when threats are found")
	flag.Parse()

	if *accesslogPtr == "" {
		flag.Usage()
		os.Exit(1)
	}

	if _, err := os.Stat(*accesslogPtr); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error - %v\n", err)
		os.Exit(1)
	}

	// Scan the access.log file
	fmt.Println("Scanning the access.log...")
	report := scan(*accesslogPtr)

	// Print the data to stdout
	report.print()

	if *strictPtr == true {
		os.Exit(1)
	}
}
