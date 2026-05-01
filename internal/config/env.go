package config

import (
	"bufio"
	"log"
	"os"
	"strings"
	"sync"
)

// IsProduction reports whether VP_ENV is set to "production".
func IsProduction() bool {
	return os.Getenv("VP_ENV") == "production"
}

var envOnce sync.Once

// loadEnvDev loads .env.dev in development mode, setting only vars that
// aren't already in the environment. This keeps dev credentials out of
// Go source while still providing a zero-config local dev experience.
func loadEnvDev() {
	envOnce.Do(func() {
		if IsProduction() {
			return
		}
		f, err := os.Open(".env.dev")
		if err != nil {
			return // file not found — fine, use env vars or empty defaults
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			// Only set if not already in environment (explicit env takes precedence).
			if os.Getenv(k) == "" {
				os.Setenv(k, v)
			}
		}
	})
}

// Require returns the value of the named environment variable.
// In development, loads .env.dev first for local defaults.
// If empty and VP_ENV=production, it calls log.Fatal.
func Require(key, devDefault string) string {
	loadEnvDev()
	if v := os.Getenv(key); v != "" {
		return v
	}
	if IsProduction() {
		log.Fatalf("%s must be set in production", key)
	}
	return devDefault
}

// Optional returns the value of the named environment variable, or empty string
// if not set. In development, loads .env.dev first for local defaults.
func Optional(key string) string {
	loadEnvDev()
	return os.Getenv(key)
}

// RequireInProduction returns the value of the named environment variable.
// In production (VP_ENV=production), it calls log.Fatal if the variable is empty.
// In development, returns empty string without error (F-13 fix).
func RequireInProduction(key string) string {
	loadEnvDev()
	v := os.Getenv(key)
	if v == "" && IsProduction() {
		log.Fatalf("SECURITY: %s must be set in production", key)
	}
	return v
}
