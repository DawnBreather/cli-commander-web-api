package helpers

import (
	"fmt"
	"github.com/getsentry/sentry-go"
	"os/exec"
	"strings"
)

func ExecuteCommand(decodedCmd string) ([]byte, error) {
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
