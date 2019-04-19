package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	. "github.com/logrusorgru/aurora"
)

type geoLocationInfo map[string]interface{}

type attacker struct {
	ip                string
	userAgent         string
	statusCodes       []string
	exampleRequest    string
	firstRequest      string
	lastRequest       string
	maliciousRequests int
}

// Increment the count of malicious requests from an attacker.
func (a *attacker) incrementMaliciousRequests() {
	a.maliciousRequests++
}

// Add new status codes to the existing slice.
func (a *attacker) updateStatusCodes(s string) {
	if a.hasStatusCode(s) == false {
		a.statusCodes = append(a.statusCodes, s)
	}
}

// Update the datetime of the last request, if later than
// the current lastRequest field.
func (a *attacker) updateLastRequest(d string) {
	if a.lastRequest < d {
		a.lastRequest = d
	}
}

// Return true if the status code is already in the slice.
func (a *attacker) hasStatusCode(s string) bool {
	for _, a := range a.statusCodes {
		if a == s {
			return true
		}
	}
	return false
}

// Query the ip api and return the response.
func queryIpApi(ip string) []byte {
	query := "http://ip-api.com/json/" + ip
	res, err := http.Get(query)
	check(err)
	defer res.Body.Close()
	data, err := ioutil.ReadAll(res.Body)
	check(err)
	return data
}

// Return a map of strings containing the geolocation info.
func geoLocate(ip string) (geoLocationInfo, error) {
	j := queryIpApi(ip)
	var result geoLocationInfo
	err := json.Unmarshal(j, &result)
	check(err)
	if result["status"] == "fail" {
		return nil, errors.New("Failed to geolocate the ip address.")
	}
	return result, nil
}

// Print geolocation information if the request was successful.
func (i geoLocationInfo) print() {
	if i["status"] == "fail" {
		fmt.Printf("\nno geolocation info available\n")
	} else {
		fmt.Printf("\nGeolocation info: %s, %s\n", i["city"], i["country"])
		fmt.Printf("Organization: %s\n", i["org"])
	}
}

// Print aggregated info on an attacker in the log file.
func (a *attacker) printRecap(verbose bool) {
	fmt.Printf("%s Found %d malicious requests from IP address %s ", Red("[+]"), Bold(a.maliciousRequests), Bold(a.ip))
	fmt.Printf("between %s and %s\n", a.firstRequest, a.lastRequest)
	if verbose {
		fmt.Printf("User agent: %s\n", a.userAgent)
		fmt.Printf("Status codes: ")
		for _, s := range a.statusCodes {
			fmt.Printf("%s ", Bold(s))
		}
		locInfo, _ := geoLocate(a.ip)
		locInfo.print()
	}
	fmt.Printf("Example request: %s\n\n", a.exampleRequest)
}
