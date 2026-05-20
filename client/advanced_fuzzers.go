package client

import (
	"context"
	"log"
	"net/http"
	"strings"
)

// FuzzSubdomains attempts to discover virtual hosts by manipulating the Host header.
func FuzzSubdomains(fc *FuzzClient, targetBase string, words []string, allLinks *[]string, validStatuses []int) {
	log.Printf("[~] Starting Advanced Subdomain Fuzzing (VHost) on %s", targetBase)
	
	for i, word := range words {
		if i > 5 { break } // Stub limit for lab
		host := word + ".example.com"
		
		req, _ := http.NewRequestWithContext(context.Background(), "GET", targetBase, nil)
		req.Host = host
		resp, err := fc.Do(req)
		if err == nil && resp != nil {
			if containsInt(validStatuses, resp.StatusCode) {
				log.Printf("[+] Found Subdomain! %s -> %s (Status: %d, Size: %d)", host, targetBase, resp.StatusCode, resp.ContentLength)
			}
			resp.Body.Close()
		}
	}
	log.Printf("[+] Subdomain Fuzzing Phase Complete.")
}

// FuzzAPI attempts to discover hidden API endpoints by altering Content-Type and appending /api/ paths.
func FuzzAPI(fc *FuzzClient, targetBase string, words []string, allLinks *[]string, validStatuses []int) {
	log.Printf("[~] Starting Advanced API Fuzzing (JSON/REST/GraphQL) on %s", targetBase)
	
	apiPaths := []string{"/api/v1/", "/graphql", "/swagger"}
	for _, p := range apiPaths {
		testURL := strings.TrimRight(targetBase, "/") + p
		req, _ := http.NewRequestWithContext(context.Background(), "POST", testURL, strings.NewReader(`{"test":true}`))
		req.Header.Set("Content-Type", "application/json")
		
		resp, err := fc.Do(req)
		if err == nil && resp != nil {
			if containsInt(validStatuses, resp.StatusCode) {
				log.Printf("[+] Found API! %s (Status: %d, Size: %d)", testURL, resp.StatusCode, resp.ContentLength)
			}
			resp.Body.Close()
		}
	}
	log.Printf("[+] API Fuzzing Phase Complete.")
}

// FuzzParameters attempts to discover hidden query parameters on discovered endpoints.
func FuzzParameters(fc *FuzzClient, targetBase string, words []string, allLinks *[]string, validStatuses []int) {
	log.Printf("[~] Starting Advanced Parameter Fuzzing on %s", targetBase)
	
	for i, word := range words {
		if i > 5 { break } // Stub limit for lab
		testURL := targetBase + "?" + word + "=1"
		req, _ := http.NewRequestWithContext(context.Background(), "GET", testURL, nil)
		resp, err := fc.Do(req)
		if err == nil && resp != nil {
			if containsInt(validStatuses, resp.StatusCode) {
				log.Printf("[+] Found Parameter! %s (Status: %d, Size: %d)", testURL, resp.StatusCode, resp.ContentLength)
			}
			resp.Body.Close()
		}
	}
	
	log.Printf("[+] Parameter Fuzzing Phase Complete.")
}

// FuzzMethods cycles through HTTP methods on endpoints.
func FuzzMethods(fc *FuzzClient, targetBase string, validStatuses []int) {
	log.Printf("[~] Starting Advanced HTTP Method Fuzzing on %s", targetBase)
	methods := []string{"POST", "PUT", "DELETE", "OPTIONS", "TRACE", "PATCH"}
	
	for _, method := range methods {
		req, _ := http.NewRequestWithContext(context.Background(), method, targetBase, nil)
		resp, err := fc.Do(req)
		if err == nil && resp != nil {
			if containsInt(validStatuses, resp.StatusCode) {
				log.Printf("[+] Found Method! [%s] %s (Status: %d, Size: %d)", method, targetBase, resp.StatusCode, resp.ContentLength)
			}
			resp.Body.Close()
		}
	}
	log.Printf("[+] HTTP Method Fuzzing Phase Complete.")
}

// FuzzHeaders injects evasion headers to bypass auth or firewalls.
func FuzzHeaders(fc *FuzzClient, targetBase string, validStatuses []int) {
	log.Printf("[~] Starting Advanced Header/Bypass Fuzzing on %s", targetBase)
	headers := map[string]string{
		"X-Forwarded-For": "127.0.0.1",
		"X-Original-URL":  "/admin",
		"X-Custom-IP-Authorization": "127.0.0.1",
	}
	
	for key, val := range headers {
		req, _ := http.NewRequestWithContext(context.Background(), "GET", targetBase, nil)
		req.Header.Set(key, val)
		resp, err := fc.Do(req)
		if err == nil && resp != nil {
			if containsInt(validStatuses, resp.StatusCode) {
				log.Printf("[+] Found Header Bypass! [%s: %s] %s (Status: %d, Size: %d)", key, val, targetBase, resp.StatusCode, resp.ContentLength)
			}
			resp.Body.Close()
		}
	}
	log.Printf("[+] Header Fuzzing Phase Complete.")
}