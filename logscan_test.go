package main

import "testing"

func TestScanThreatfulLog(t *testing.T) {
	r := scan("testdata/example-access.log", false)

	if got := len(r); got != 2 {
		t.Errorf("Expected 2 attacks in the report, got %d.", got)
	}
}

func TestScanCleanLog(t *testing.T) {
	r := scan("testdata/example-access-clean.log", false)

	if got := len(r); got != 0 {
		t.Errorf("Expected no attacks in the report, got %d.", got)
	}
}
