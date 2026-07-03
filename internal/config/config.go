package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr             string
	AllowedOrigins   []string
	InternalAPIKey   string
	MasterKey        string
	MemgraphURI      string
	MemgraphUser     string
	MemgraphPassword string
	RequestTimeout   time.Duration
	ShutdownTimeout  time.Duration
}

func Load() (Config, error) {
	loadDotEnv(".env.gmr-vault", "../.env.gmr-vault")

	cfg := Config{
		Addr:             env("GMR_VAULT_ADDR", ":8091"),
		AllowedOrigins:   splitCSV(env("GMR_VAULT_ALLOWED_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000,http://localhost:3001,http://127.0.0.1:3001,http://localhost:3002,http://127.0.0.1:3002")),
		InternalAPIKey:   os.Getenv("GMR_VAULT_INTERNAL_API_KEY"),
		MasterKey:        os.Getenv("GMR_VAULT_MASTER_KEY"),
		MemgraphURI:      env("GMR_VAULT_MEMGRAPH_URI", "bolt://localhost:7690"),
		MemgraphUser:     env("GMR_VAULT_MEMGRAPH_USER", ""),
		MemgraphPassword: env("GMR_VAULT_MEMGRAPH_PASSWORD", ""),
		RequestTimeout:   time.Duration(envInt("GMR_VAULT_REQUEST_TIMEOUT_SECONDS", 20)) * time.Second,
		ShutdownTimeout:  time.Duration(envInt("GMR_VAULT_SHUTDOWN_TIMEOUT_SECONDS", 5)) * time.Second,
	}

	if len(cfg.InternalAPIKey) < 32 {
		return Config{}, errors.New("GMR_VAULT_INTERNAL_API_KEY must be at least 32 characters")
	}
	if len(cfg.MasterKey) < 32 {
		return Config{}, errors.New("GMR_VAULT_MASTER_KEY must be at least 32 characters")
	}
	return cfg, nil
}

func env(key string, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
