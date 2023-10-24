package helpers

import (
	"flag"
	"log"
	"os"
)

var ConfigGlobal = LoadConfigFromEnv()

type Config struct {
	SocketAddr string
	AuthToken  string
}

func LoadConfigFromEnv() Config {
	return Config{
		SocketAddr: getEnv("CLI_COMMANDER_SOCKET", "127.0.0.1:8080"),
		AuthToken:  getEnv("CLI_COMMANDER_AUTH_TOKEN", ""),
	}
}

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

func ParseCliFlags(cfg *Config) {
	flag.StringVar(&cfg.SocketAddr, "socket", cfg.SocketAddr, "The address and port to listen on")
	flag.StringVar(&cfg.AuthToken, "auth-token", cfg.AuthToken, "The authorization token required to use the server")

	flag.Parse()
}

func ValidateConfig(cfg Config) {
	if cfg.AuthToken == "" {
		log.Fatalf("Please provide a valid authorization token using --auth-token or through the CLI_COMMANDER_AUTH_TOKEN environment variable")
	}
}
