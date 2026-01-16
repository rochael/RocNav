package config

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr           string
	DBPath         string
	JWTSecret      []byte
	JWTIssuer      string
	JWTTTL         time.Duration
	CookieDomain   string
	CookieSecure   bool
	FrontendOrigin string
	GitHubClientID string
	GitHubSecret   string
	GitHubRedirect string
	AdminEmail     string
	AdminPassword  string
	AllowRegister  bool
}

func Load() *Config {
	loadDotEnv()
	cfg := &Config{
		Addr:           getenv("ADDR", ":8080"),
		DBPath:         getenv("SQLITE_PATH", "data/nav.db"),
		JWTSecret:      []byte(getenv("JWT_SECRET", "dev-secret-change")),
		JWTIssuer:      getenv("JWT_ISSUER", "mynav"),
		JWTTTL:         durationEnv("JWT_TTL", 72*time.Hour),
		CookieDomain:   os.Getenv("COOKIE_DOMAIN"),
		CookieSecure:   boolEnv("COOKIE_SECURE", false),
		FrontendOrigin: getenv("FRONTEND_ORIGIN", "http://localhost:5173"),
		GitHubClientID: os.Getenv("GITHUB_CLIENT_ID"),
		GitHubSecret:   os.Getenv("GITHUB_CLIENT_SECRET"),
		GitHubRedirect: getenv("GITHUB_REDIRECT", "http://localhost:8080/api/auth/github/callback"),
		AdminEmail:     os.Getenv("ADMIN_EMAIL"),
		AdminPassword:  os.Getenv("ADMIN_PASSWORD"),
		AllowRegister:  boolEnv("ALLOW_REGISTER", true),
	}

	if len(cfg.JWTSecret) < 16 {
		log.Println("warning: JWT_SECRET is weak or not set; use a stronger secret in production")
	}
	return cfg
}

// Minimal .env loader (no external dependency). Supports KEY=VALUE, ignores empty lines and lines starting with '#'.
func loadDotEnv() {
	f, err := os.Open(".env")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		// preserve existing env if already set
		if os.Getenv(k) == "" {
			_ = os.Setenv(k, v)
		}
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func boolEnv(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

func durationEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err == nil {
			return d
		}
	}
	return def
}
