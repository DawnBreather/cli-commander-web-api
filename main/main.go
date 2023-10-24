package main

import (
	"log"
	"net/http"
	"time"

	sentry "github.com/getsentry/sentry-go"
	. "web_api/handlers"
	. "web_api/helpers"
)

//func executeCommand(decodedCmd string) ([]byte, error) {
//	if len(decodedCmd) == 0 {
//		return nil, fmt.Errorf("no command provided")
//	}
//
//	return exec.Command("sh", "-c", decodedCmd).CombinedOutput()
// }

func main() {

	err := sentry.Init(sentry.ClientOptions{
		Dsn:              "https://33f6cdc7e8a1a074d7dc138dc99b2eeb@o365327.ingest.sentry.io/4506105908101120",
		TracesSampleRate: 1.0,
	})
	if err != nil {
		log.Fatalf("sentry.Init: %s", err)
	}
	defer sentry.Flush(2 * time.Second)

	ParseCliFlags(&ConfigGlobal)

	ValidateConfig(ConfigGlobal)

	log.Printf("Starting the CLI commander Web API on { %s }", ConfigGlobal.SocketAddr)

	//authToken := config.AuthToken

	http.HandleFunc("/execute", Handler)
	http.HandleFunc("/delete_connector", DeleteConnectorHandler)
	http.HandleFunc("/deploy_connector", DeployConnectorHandler)
	sentry.CaptureMessage("CLI Commander Web API started")
	defer sentry.CaptureMessage("CLI Commander Web API terminated")
	log.Fatal(http.ListenAndServe(ConfigGlobal.SocketAddr, nil))

}
