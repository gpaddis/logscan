package main

import "testing"

func TestGetIpAddress(t *testing.T) {
	entry := "127.0.0.1 - peter [9/Feb/2017:10:34:12 -0700] \"GET /sample-image.png HTTP/2\" 200 1479"
	ip := getIpAddress(entry)
	if ip != "127.0.0.1" {
		t.Errorf("Expected 127.0.0.1, got %s.", ip)
	}
}
