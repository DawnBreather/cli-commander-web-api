package handlers

import (
	"fmt"
	"github.com/getsentry/sentry-go"
	"net/http"
	. "web_api/helpers"
)

func Handler(w http.ResponseWriter, r *http.Request) {
	if !IsRequestFromLocalhost(r.RemoteAddr) {
		sentry.CaptureException(fmt.Errorf("HTTP handler: {Access denied} replied"))
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	if !IsValidAuthorization(r) {
		sentry.CaptureException(fmt.Errorf("HTTP handler: {Invalid or missing authorization token} replied"))
		http.Error(w, "Invalid or missing authorization token", http.StatusUnauthorized)
		return
	}

	decodedBytes, err := DecodeRequestBody(r)
	if err != nil {
		sentry.CaptureException(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	output, err := ExecuteCommand(string(decodedBytes))
	if err != nil {
		sentry.CaptureException(fmt.Errorf("Command execution failed: %v\n%s", err, output))
		http.Error(w, fmt.Sprintf("Command execution failed: %v\n%s", err, output), http.StatusInternalServerError)
		return
	}

	w.Write(output)
}
