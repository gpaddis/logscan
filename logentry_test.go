package main

import "testing"

var rawEntry = `127.0.0.1 - - [12/Dec/2015:18:25:11 +0100] "GET /modules/mod_bowslideshow/tmpl/images/image_shadow.png HTTP/1.1" 200 4263 "-" "Mozilla/5.0 (Windows NT 6.0; rv:34.0) Gecko/20100101 Firefox/34.0" "-"`

func assertEquals(t *testing.T, expected, got string) {
	if got != expected {
		t.Errorf("Expected %s, got %s.", expected, got)
	}
}

func TestGetIPAddress(t *testing.T) {
	expected := "127.0.0.1"
	got := getIPAddress(rawEntry)
	assertEquals(t, expected, got)
}

func TestGetResponseStatus(t *testing.T) {
	expected := "200"
	got := getResponseStatus(rawEntry)
	assertEquals(t, expected, got)
}

func TestGetRequestURI(t *testing.T) {
	expected := "/modules/mod_bowslideshow/tmpl/images/image_shadow.png"
	got := getRequestURI(rawEntry)
	assertEquals(t, expected, got)
}

func TestGetUserAgent(t *testing.T) {
	expected := "Mozilla/5.0 (Windows NT 6.0; rv:34.0) Gecko/20100101 Firefox/34.0"
	got := getUserAgent(rawEntry)
	assertEquals(t, expected, got)
}

func TestGetDateTime(t *testing.T) {
	expected := "12/Dec/2015:18:25:11 +0100"
	got := getDateTime(rawEntry)
	assertEquals(t, expected, got)
}

func TestCreateLogEntry(t *testing.T) {
	raw := `127.0.0.1 - - [12/Dec/2015:18:25:11 +0100] "GET /test.php HTTP/1.1" 200 4263 "-" "Mozilla/5.0 (Windows NT 6.0; rv:34.0) Gecko/20100101 Firefox/34.0" "-"`
	expected := logEntry{
		ip:       "127.0.0.1",
		status:   "200",
		uri:      "/test.php",
		agent:    "Mozilla/5.0 (Windows NT 6.0; rv:34.0) Gecko/20100101 Firefox/34.0",
		datetime: "12/Dec/2015:18:25:11 +0100",
	}
	got := createLogEntry(raw)
	if got != expected {
		t.Error("Error creating a log entry.")
	}
}

func TestHasPotentialThreats(t *testing.T) {
	// Uppercase
	raw := `127.0.0.1 - - [12/Dec/2015:18:25:11 +0100] "GET /test.php?name=Downloads&d_op=modifydownloadrequest&%20lid=-1%20UNION%20SELECT%200,username,user_id,user_password,name,%20user_email,user_level,0,0%20FROM%20nuke_users HTTP/1.1" 200 4263 "-" "Mozilla/5.0 (Windows NT 6.0; rv:34.0) Gecko/20100101 Firefox/34.0" "-"`
	if hasPotentialThreats(raw) != true {
		t.Error("Error: potential threats were not identified.")
	}

	// Lowercase
	raw = `127.0.0.1 - - [12/Dec/2015:18:25:11 +0100] "GET /test.php?name=Downloads&d_op=modifydownloadrequest&%20lid=-1%20union%20select%200,username,user_id,user_password,name,%20user_email,user_level,0,0%20from%20nuke_users HTTP/1.1" 200 4263 "-" "Mozilla/5.0 (Windows NT 6.0; rv:34.0) Gecko/20100101 Firefox/34.0" "-"`
	if hasPotentialThreats(raw) != true {
		t.Error("Error: potential threats were not identified.")
	}
}
