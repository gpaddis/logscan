package main

import "testing"

var rawEntry = `127.0.0.1 - - [12/Dec/2015:18:25:11 +0100] "GET /modules/mod_bowslideshow/tmpl/images/image_shadow.png HTTP/1.1" 200 4263 "-" "Mozilla/5.0 (Windows NT 6.0; rv:34.0) Gecko/20100101 Firefox/34.0" "-"`

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
	expected := "/modules/mod_bowslideshow/tmpl/images/image_shadow.png"
	got := getRequestURI(rawEntry)
	if got != expected {
		t.Errorf("Expected %s, got %s.", expected, got)
	}
}
