package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	. "web_api/helpers"
)

type ConnectorDeploymentRequest struct {
	ConnectorName               string `json:"connector_name"`
	NamespaceName               string `json:"namespace_name"`
	DelayInSeconds              int    `json:"delay_in_seconds"`
	OpenOn                      int    `json:"open_on"`
	ForwardTo                   int    `json:"forward_to"`
	HelmInstallationName        string `json:"helm_installation_name"`
	HelmChartRepository         string `json:"helm_chart_repository"`
	HelmChartVersion            string `json:"helm_chart_version"`
	HelmChartValuesFileLocation string `json:"helm_chart_values_file_location"`
}

func DeployConnectorHandler(w http.ResponseWriter, r *http.Request) {
	// Ensure only POST requests are processed
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Parse request body
	var request ConnectorDeploymentRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Execute the commands
	commands := []string{
		fmt.Sprintf("helm template %s %s --version %s -f %s > %s.yml", request.HelmInstallationName, request.HelmChartRepository, request.HelmChartVersion, request.HelmChartValuesFileLocation, request.ConnectorName),
		fmt.Sprintf("kubectl apply --namespace %s -f %s.yml", request.NamespaceName, request.ConnectorName),
		fmt.Sprintf("sleep %ds", request.DelayInSeconds),
		fmt.Sprintf("kubectl --namespace %s port-forward service/%s %d:%d &", request.NamespaceName, request.ConnectorName, request.OpenOn, request.ForwardTo),
	}

	var combinedOutput []byte
	for _, cmd := range commands {
		combinedOutput = append(combinedOutput, fmt.Sprintf("Executing: { %s }", cmd)...)
		output, err := ExecuteCommand(cmd)
		if err != nil {
			combinedOutput = append(combinedOutput, fmt.Sprintf("Failed executing command: %s\nError: %s\nOutput: %s\n\n", cmd, err, output)...)
			http.Error(w, string(combinedOutput), http.StatusInternalServerError)
			return
		}
		combinedOutput = append(combinedOutput, output...)
	}

	// Respond to the client with the combined output
	w.Write(combinedOutput)
}
