package helpers

import (
	"encoding/base64"
	"fmt"
	"github.com/getsentry/sentry-go"
	"io"
	"net"
	"net/http"
)

func IsRequestFromLocalhost(remoteAddr string) bool {
  host, _, err := net.SplitHostPort(remoteAddr)
  return err == nil && host == "127.0.0.1"
}

func IsValidAuthorization(r *http.Request) bool {
  authHeader := r.Header.Get("Authorization")
  expectedAuthHeader := "Bearer " + ConfigGlobal.AuthToken
  return authHeader == expectedAuthHeader
}

func DecodeRequestBody(r *http.Request) ([]byte, error) {
  body, err := io.ReadAll(r.Body)
  if err != nil {
    sentry.CaptureException(fmt.Errorf("failed reading request body: %w", err))
    return nil, fmt.Errorf("failed reading request body: %w", err)
  }
  defer r.Body.Close()

  return base64.StdEncoding.DecodeString(string(body))
}
