package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"time"

	. "github.com/logrusorgru/aurora"
)

const AppVersion = "1.0.0"

// Ideas:
// * https://check.torproject.org/cgi-bin/TorBulkExitList.py

// Panic when an error occurs.
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// Scan all entries and return the ones containing suspicious
// requests in a report.
func scan(logfile string, verbose bool) report {
	fmt.Printf("Scanning %s...\n", logfile)
	report := make(report)
	f, err := os.Open(logfile)
	check(err)
	defer f.Close()

	scanner := bufio.NewScanner(f)
	start := time.Now()
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		raw := scanner.Text()
		if hasPotentialThreats(raw) {
			l := createLogEntry(raw)
			report.update(l)
		}
	}

	if verbose {
		elapsed := time.Since(start)
		handle, _ := f.Stat()
		sizeMB := handle.Size() / 1000000
		fmt.Printf("Scanned %d requests (%d MB) in %.2f seconds.\n\n", lineCount, sizeMB, elapsed.Seconds())
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
	os.Exit(0)
}

func main() {
	// Collect and parse parameters
	logfile := flag.String("l", "", "The access.log file you want to analyze")
	strict := flag.Bool("s", false, "Strict mode: return with error code 1 when threats are found")
	stdin := flag.Bool("i", false, "Parse information from stdin instead of scanning a log file")
	verbose := flag.Bool("v", false, "Print verbose information")
	version := flag.Bool("version", false, "Print the logscan version and exit")
	flag.Parse()

	if *version == true {
		fmt.Println("logscan version:", AppVersion)
		os.Exit(0)
	}

	if *stdin == true {
		scanStdin(*verbose)
	}

	if *logfile == "" {
		flag.Usage()
		os.Exit(1)
	}

	if _, err := os.Stat(*logfile); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error - %v\n", err)
		os.Exit(1)
	}

	// Scan the access.log file
	report := scan(*logfile, *verbose)
	if len(report) == 0 {
		fmt.Println(Green("No threats found."))
		os.Exit(0)
	}

	// Print the data to stdout
	fmt.Println(Red("Potential threats found:"))
	for _, a := range report {
		a.printRecap(*verbose)
	}

	if *strict == true {
		os.Exit(1)
	}
}
