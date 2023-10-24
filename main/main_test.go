package main

import (
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestIsRequestFromLocalhost(t *testing.T) {
	tests := []struct {
		addr     string
		expected bool
	}{
		{"127.0.0.1:8080", true},
		{"192.168.1.1:8080", false},
		{"[::1]:8080", false}, // you might need to change this to `true` if you want to support IPv6 localhost
	}

	for _, tt := range tests {
		result := isRequestFromLocalhost(tt.addr)
		if result != tt.expected {
			t.Errorf("isRequestFromLocalhost(%q) = %v; want %v", tt.addr, result, tt.expected)
		}
	}
}

func TestIsValidAuthorization(t *testing.T) {
	authToken = "test-token"
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer test-token")

	if !isValidAuthorization(req) {
		t.Errorf("isValidAuthorization failed for valid token")
	}

	req.Header.Set("Authorization", "Bearer invalid-token")
	if isValidAuthorization(req) {
		t.Errorf("isValidAuthorization passed for invalid token")
	}
}

func TestDecodeRequestBody(t *testing.T) {
	validBase64 := base64.StdEncoding.EncodeToString([]byte("test command"))
	req := httptest.NewRequest("GET", "/", strings.NewReader(validBase64))
	decoded, err := decodeRequestBody(req)

	if err != nil {
		t.Errorf("decodeRequestBody returned unexpected error: %v", err)
	}
	if string(decoded) != "test command" {
		t.Errorf("decodeRequestBody decoded to %q; want %q", decoded, "test command")
	}

	invalidBase64 := "invalid-base64==="
	req = httptest.NewRequest("GET", "/", strings.NewReader(invalidBase64))
	_, err = decodeRequestBody(req)
	if err == nil {
		t.Errorf("decodeRequestBody should return an error for invalid base64")
	}
}

func TestExecuteCommand(t *testing.T) {
	output, err := executeCommand("echo hello")
	if err != nil {
		t.Errorf("executeCommand returned unexpected error: %v", err)
	}
	if strings.TrimSpace(string(output)) != "hello" {
		t.Errorf("executeCommand returned %q; want %q", output, "hello")
	}

	_, err = executeCommand("invalidCommandName")
	if err == nil {
		t.Errorf("executeCommand should return an error for invalid commands")
	}
}
