package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	. "github.com/logrusorgru/aurora"
)

// Ideas:
// * http://ip-api.com/
// * https://check.torproject.org/cgi-bin/TorBulkExitList.py

// Panic when an error occurs.
func check(e error) {
	if e != nil {
		panic(e)
	}
}

func main() {
	// Collect and parse parameters
	accesslogPtr := flag.String("logfile", "", "The access.log file you want to analyze")
	strictPtr := flag.Bool("strict", false, "Strict mode: return with error code 1 when threats are found")
	stdinPtr := flag.Bool("stdin", false, "Parse information from stdin instead of scanning a log file")
	flag.Parse()

	if *stdinPtr == true {
		fmt.Println("Scanning stdin... (press CTRL+C to exit)")
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if raw := scanner.Text(); hasPotentialThreats(raw) {
				l := createLogEntry(raw)
				fmt.Printf("%s attack detected from %s: %s (on %s)\n", Red("[+]"), Bold(l.ip), l.uri, l.datetime)
			}
		}
		os.Exit(1)
	}

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
	if len(report) == 0 {
		fmt.Println(Green("No threats found."))
		os.Exit(0)
	}

	// Print the data to stdout
	report.print()
	if *strictPtr == true {
		os.Exit(1)
	}
}
