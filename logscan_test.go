package main

import "testing"

var rawEntry = `127.0.0.1 - peter [9/Feb/2017:10:34:12 -0700] "GET /sample-image.png HTTP/2" 200 1479`

func TestGetIPAddress(t *testing.T) {
	ip := getIPAddress(rawEntry)
	if ip != "127.0.0.1" {
		t.Errorf("Expected 127.0.0.1, got %s.", ip)
	}
}

func TestGetResponseStatus(t *testing.T) {
	status := getResponseStatus(rawEntry)
	if status != "200" {
		t.Errorf("Expected 200, got %s.", status)
	}
}

func TestGetRequestURI(t *testing.T) {
	URI := getRequestURI(rawEntry)
	if URI != "/sample-image.png" {
		t.Errorf("Expected /sample-image.png, got %s.", URI)
	}
}
