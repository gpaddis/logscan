package main

import "testing"

func TestHasIP(t *testing.T) {
	ip := "127.0.0.1"
	r := make(report)

	if r.hasIP(ip) {
		t.Error("Got true, expecting false.")
	}

	r[ip] = attacker{}
	if r.hasIP(ip) == false {
		t.Error("Got false, expecting true.")
	}
}
