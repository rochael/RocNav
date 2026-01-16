package version

import (
	"os"
	"path/filepath"
	"strings"
)

// buildVersion can be set via -ldflags "-X github.com/rochael/RocNav/internal/version.buildVersion=1.2.3"
var buildVersion string

const (
	defaultVersion = "dev"
	versionFile    = "VERSION"
)

// Version returns the current application version.
// Priority: ldflags override -> VERSION file (if present) -> defaultVersion.
func Version() string {
	if v := strings.TrimSpace(buildVersion); v != "" {
		return v
	}
	if v := fromFile(filepath.Join(exeDir(), versionFile)); v != "" {
		return v
	}
	if v := fromFile(versionFile); v != "" {
		return v
	}
	return defaultVersion
}

func exeDir() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return "."
}

func fromFile(path string) string {
	if data, err := os.ReadFile(path); err == nil {
		if v := strings.TrimSpace(string(data)); v != "" {
			return v
		}
	}
	return ""
}
