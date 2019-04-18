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

// Scan all entries and return the ones containing suspicious
// requests in a report.
func scan(logfile string) report {
	fmt.Printf("Scanning %s...\n", logfile)
	report := make(report)
	f, err := os.Open(logfile)
	check(err)
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		raw := scanner.Text()
		if hasPotentialThreats(raw) {
			l := createLogEntry(raw)
			report.update(l)
		}
	}

	return report
}

// Parse the stdin and report each attack.
func scanStdin(verbose bool) {
	fmt.Println("Scanning stdin... (press CTRL+C to exit)")
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		l := createLogEntry(scanner.Text())
		if hasPotentialThreats(l.uri) {
			fmt.Printf("%s attack detected from %s: %s\n", Red("[+]"), Red(l.ip), l.uri)
			if verbose == true {
				fmt.Printf("Status: %s, Time: %s, User Agent: %s\n", l.status, l.datetime, l.agent)
			}
		}
	}
}

func main() {
	// Collect and parse parameters
	accesslogPtr := flag.String("l", "", "The access.log file you want to analyze")
	strictPtr := flag.Bool("s", false, "Strict mode: return with error code 1 when threats are found")
	stdinPtr := flag.Bool("i", false, "Parse information from stdin instead of scanning a log file")
	verbosePtr := flag.Bool("v", false, "Print verbose information")
	flag.Parse()

	if *stdinPtr == true {
		scanStdin(*verbosePtr)
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
