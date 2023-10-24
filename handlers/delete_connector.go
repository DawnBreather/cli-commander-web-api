package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	. "web_api/helpers"
)

type ConnectorDeletionRequest struct {
	ConnectorName  string `json:"connector_name"`
	NamespaceName  string `json:"namespace_name"`
	DelayInSeconds int    `json:"delay_in_seconds"`
}

func DeleteConnectorHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure only POST requests are processed
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var request ConnectorDeletionRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Execute the commands
	commands := []string{
		fmt.Sprintf("pkill -f \"kubectl --namespace %s port-forward service/%s\"\n", request.NamespaceName, request.ConnectorName),
		fmt.Sprintf("kubectl delete deployments %s --ignore-not-found=true --namespace %s", request.ConnectorName, request.NamespaceName),
		fmt.Sprintf("kubectl delete services %s --ignore-not-found=true --namespace %s", request.ConnectorName, request.NamespaceName),
		fmt.Sprintf("sleep %ds", request.DelayInSeconds),
	}

	var combinedOutput []byte
	for _, cmd := range commands {
		combinedOutput = append(combinedOutput, fmt.Sprintf("Executing: { %s }", cmd)...)
		output, err := ExecuteCommand(cmd)
		if err != nil {
			combinedOutput = append(combinedOutput, fmt.Sprintf("Failed executing command: %s\nError: %s\nOutput: %s\n\n", cmd, err, output)...)
			http.Error(w, fmt.Sprintf("Failed executing command: %s, Error: %s, Output: %s", cmd, err, output), http.StatusInternalServerError)
			return
		}
		combinedOutput = append(combinedOutput, output...)
	}

	w.Write(combinedOutput)
}
