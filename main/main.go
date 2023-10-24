package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	sentry "github.com/getsentry/sentry-go"
)

var authToken = ""

func isRequestFromLocalhost(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	return err == nil && host == "127.0.0.1"
}

func isValidAuthorization(r *http.Request) bool {
	authHeader := r.Header.Get("Authorization")
	expectedAuthHeader := "Bearer " + authToken
	return authHeader == expectedAuthHeader
}

func decodeRequestBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		sentry.CaptureException(fmt.Errorf("failed reading request body: %w", err))
		return nil, fmt.Errorf("failed reading request body: %w", err)
	}
	defer r.Body.Close()

	return base64.StdEncoding.DecodeString(string(body))
}

//func executeCommand(decodedCmd string) ([]byte, error) {
//	if len(decodedCmd) == 0 {
//		return nil, fmt.Errorf("no command provided")
//	}
//
//	return exec.Command("sh", "-c", decodedCmd).CombinedOutput()
// }

func executeCommand(decodedCmd string) ([]byte, error) {
	if len(decodedCmd) == 0 {
		sentry.CaptureException(fmt.Errorf("no command provided"))
		return nil, fmt.Errorf("no command provided")
	}

	runInBackground := false
	if strings.HasSuffix(decodedCmd, "&") {
		runInBackground = true
		decodedCmd = strings.TrimSpace(strings.TrimSuffix(decodedCmd, "&"))
	}

	cmdParts := strings.Fields(decodedCmd)
	if len(cmdParts) == 0 {
		sentry.CaptureException(fmt.Errorf("no command provided"))
		return nil, fmt.Errorf("no command provided")
	}

	//cmd := cmdParts[0]
	//args := cmdParts[1:]
	//
	//execCmd := exec.Command(cmd, args...)

	execCmd := exec.Command("sh", "-c", decodedCmd)

	if runInBackground {
		execCmd.Stdout = nil
		execCmd.Stderr = nil

		err := execCmd.Start()
		if err != nil {
			return nil, err
		}

		// If running in the background, return the PID of the started process
		return []byte(fmt.Sprintf("Command started with PID: %d", execCmd.Process.Pid)), nil
	}

	// If not a background command, just run and wait for the command to finish
	output, err := execCmd.CombinedOutput()
	if err != nil {
		sentry.CaptureException(fmt.Errorf("Command execution failed: %w", err))
		return output, fmt.Errorf("Command execution failed: %w", err)
	}

	return output, nil
}

func handler(w http.ResponseWriter, r *http.Request) {
	if !isRequestFromLocalhost(r.RemoteAddr) {
		sentry.CaptureException(fmt.Errorf("HTTP handler: {Access denied} replied"))
		http.Error(w, "Access denied", http.StatusForbidden)
		return
	}

	if !isValidAuthorization(r) {
		sentry.CaptureException(fmt.Errorf("HTTP handler: {Invalid or missing authorization token} replied"))
		http.Error(w, "Invalid or missing authorization token", http.StatusUnauthorized)
		return
	}

	decodedBytes, err := decodeRequestBody(r)
	if err != nil {
		sentry.CaptureException(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	output, err := executeCommand(string(decodedBytes))
	if err != nil {
		sentry.CaptureException(fmt.Errorf("Command execution failed: %v\n%s", err, output))
		http.Error(w, fmt.Sprintf("Command execution failed: %v\n%s", err, output), http.StatusInternalServerError)
		return
	}

	w.Write(output)
}

// Configuration structure
type Config struct {
	SocketAddr string
	AuthToken  string
}

// Load default configurations from environment variables
func loadConfigFromEnv() Config {
	return Config{
		SocketAddr: getEnv("CLI_COMMANDER_SOCKET", "127.0.0.1:8080"),
		AuthToken:  getEnv("CLI_COMMANDER_AUTH_TOKEN", ""),
	}
}

// Get an environment variable; if not found, return a default value
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// Parse and override configurations with CLI flags
func parseFlags(cfg *Config) {
	flag.StringVar(&cfg.SocketAddr, "socket", cfg.SocketAddr, "The address and port to listen on")
	flag.StringVar(&cfg.AuthToken, "auth-token", cfg.AuthToken, "The authorization token required to use the server")

	flag.Parse()
}

// Validate the configuration; ensure required values are set
func validateConfig(cfg Config) {
	if cfg.AuthToken == "" {
		log.Fatalf("Please provide a valid authorization token using --auth-token or through the CLI_COMMANDER_AUTH_TOKEN environment variable")
	}
}

func main() {

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              os.Getenv("SENTRY_DSN"),
		TracesSampleRate: 1.0,
	})
	if err != nil {
		log.Fatalf("sentry.Init: %s", err)
	}
	// Ensures Sentry-go SDK flushes all the buffered events before the program ends.
	defer sentry.Flush(2 * time.Second)

	// Load configurations
	config := loadConfigFromEnv()

	// Override with CLI flags if provided
	parseFlags(&config)

	// Validate configurations
	validateConfig(config)

	authToken = config.AuthToken

	http.HandleFunc("/execute", handler)
	sentry.CaptureMessage("CLI Commander Web API started")
	log.Fatal(http.ListenAndServe(config.SocketAddr, nil))
	defer sentry.CaptureMessage("CLI Commander Web API terminated")

}
