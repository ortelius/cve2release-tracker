// Package util provides utility functions for import/export operations in the Ortelius CLI.
package util

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/package-url/packageurl-go"
	"gopkg.in/yaml.v2"
)

// GetEnvDefault is a convenience function for handling env vars
func GetEnvDefault(key, defVal string) string {
	val, ex := os.LookupEnv(key) // get the env var
	if !ex {                     // not found return default
		return defVal
	}
	return val // return value for env var
}

// IsEmpty checks if a string is empty or contains only whitespace
func IsEmpty(s string) bool {
	return len(strings.TrimSpace(s)) == 0
}

// IsNotEmpty checks if a string is not empty
func IsNotEmpty(s string) bool {
	return !IsEmpty(s)
}

// FileExists checks if a file exists
func FileExists(filename string) bool {
	_, err := os.Stat(filename)
	return err == nil
}

// CleanName removes periods and dashes from the name, replacing with underscores
func CleanName(name string) string {
	if name == "" {
		return name
	}
	name = strings.ReplaceAll(name, ".", "_")
	name = strings.ReplaceAll(name, "-", "_")
	return name
}

// GetEnvOrDefault returns environment variable value or default
func GetEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// Contains checks if a string slice contains an item
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// FindChartPath finds a Helm chart file
func FindChartPath(shortname string) string {
	paths := []string{
		filepath.Join("helm", shortname, "Chart.yaml"),
		filepath.Join("helm", shortname, "Chart.yml"),
		filepath.Join("chart", shortname, "Chart.yaml"),
		filepath.Join("chart", shortname, "Chart.yml"),
		filepath.Join("charts", shortname, "Chart.yaml"),
		filepath.Join("charts", shortname, "Chart.yml"),
	}

	for _, path := range paths {
		if FileExists(path) {
			return path
		}
	}
	return ""
}

// ExtractChartVersion extracts version from a Helm chart file
func ExtractChartVersion(chartPath string) string {
	content, err := os.ReadFile(chartPath)
	if err != nil {
		return ""
	}

	var chart map[string]any
	if err := yaml.Unmarshal(content, &chart); err != nil {
		return ""
	}

	if version, ok := chart["version"].(string); ok {
		return version
	}
	return ""
}

// FindFile finds the first existing file from a list of candidates
func FindFile(candidates []string) string {
	for _, candidate := range candidates {
		if FileExists(candidate) {
			return candidate
		}
	}
	return ""
}

// RunCmd executes a shell command and returns the trimmed output
func RunCmd(cmd string) string {
	if strings.Contains(cmd, "git") {
		if _, err := os.Stat(".git"); os.IsNotExist(err) {
			return ""
		}
	}

	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return ""
	}

	var cmdExec *exec.Cmd
	if len(parts) == 1 {
		cmdExec = exec.Command(parts[0])
	} else {
		// For complex shell commands, use sh -c
		if strings.Contains(cmd, "|") || strings.Contains(cmd, "&&") || strings.Contains(cmd, "||") || strings.Contains(cmd, ";") {
			cmdExec = exec.Command("sh", "-c", cmd)
		} else {
			cmdExec = exec.Command(parts[0], parts[1:]...)
		}
	}

	output, err := cmdExec.Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(output))
}

// GetStringOrDefault returns value or default if empty
func GetStringOrDefault(value, defaultValue string) string {
	if value == "" {
		return defaultValue
	}
	return value
}

// CleanPURL removes qualifiers (after ?) and subpath (after #) to create canonical PURL
func CleanPURL(purlStr string) (string, error) {
	parsed, err := packageurl.FromString(purlStr)
	if err != nil {
		return "", err
	}

	// Create new PURL without qualifiers and subpath
	cleaned := packageurl.PackageURL{
		Type:      parsed.Type,
		Namespace: parsed.Namespace,
		Name:      parsed.Name,
		Version:   parsed.Version,
		// Qualifiers and Subpath are intentionally omitted
	}

	return strings.ToLower(cleaned.ToString()), nil
}

// GetBasePURL removes the version component from a PURL to create a base package identifier
// This is used for matching CVE PURLs (which lack versions) with SBOM component PURLs (which include versions)
// Example: pkg:npm/lodash@4.17.20 -> pkg:npm/lodash
func GetBasePURL(purlStr string) (string, error) {
	parsed, err := packageurl.FromString(purlStr)
	if err != nil {
		return "", err
	}

	// Create new PURL without version, qualifiers, and subpath
	base := packageurl.PackageURL{
		Type:      parsed.Type,
		Namespace: parsed.Namespace,
		Name:      parsed.Name,
		// Version, Qualifiers and Subpath are intentionally omitted
	}

	return strings.ToLower(base.ToString()), nil
}

// ParsePURL parses a PURL string and returns the parsed PackageURL
func ParsePURL(purlStr string) (*packageurl.PackageURL, error) {
	parsed, err := packageurl.FromString(purlStr)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

// EcosystemToPurlType converts OSV ecosystem to PURL type
func EcosystemToPurlType(ecosystem string) string {
	mapping := map[string]string{
		"npm":       "npm",
		"PyPI":      "pypi",
		"Maven":     "maven",
		"Go":        "golang",
		"NuGet":     "nuget",
		"RubyGems":  "gem",
		"crates.io": "cargo",
		"Packagist": "composer",
		"Pub":       "pub",
		"CocoaPods": "cocoapods",
		"Hex":       "hex",
		"Alpine":    "alpine",
		"Debian":    "deb",
		"Ubuntu":    "deb",
	}
	return mapping[ecosystem]
}

// IsVersionAffected checks if a version is affected by OSV ranges
func IsVersionAffected(version string, affected models.Affected) bool {
	// Check specific versions list
	if len(affected.Versions) > 0 {
		for _, v := range affected.Versions {
			if version == v {
				return true
			}
		}
	}

	// Check version ranges
	if len(affected.Ranges) > 0 {
		for _, vrange := range affected.Ranges {
			// Only handle SEMVER and ECOSYSTEM types
			if vrange.Type != models.RangeEcosystem && vrange.Type != models.RangeSemVer {
				continue
			}

			if isVersionInRange(version, vrange) {
				return true
			}
		}
	}

	return false
}

// isVersionInRange checks if a version falls within an OSV range
func isVersionInRange(version string, vrange models.Range) bool {
	v, err := semver.NewVersion(version)
	if err != nil {
		// If not valid semver, fall back to string comparison
		return isVersionInRangeString(version, vrange)
	}

	var introduced, fixed, lastAffected *semver.Version

	for _, event := range vrange.Events {
		if event.Introduced != "" {
			introduced, _ = semver.NewVersion(event.Introduced)
		}
		if event.Fixed != "" {
			fixed, _ = semver.NewVersion(event.Fixed)
		}
		if event.LastAffected != "" {
			lastAffected, _ = semver.NewVersion(event.LastAffected)
		}
	}

	// Check if version is >= introduced
	if introduced != nil && v.LessThan(introduced) {
		return false
	}

	// Check if version is < fixed
	if fixed != nil && !v.LessThan(fixed) {
		return false
	}

	// Check if version is <= last_affected
	if lastAffected != nil && v.GreaterThan(lastAffected) {
		return false
	}

	// If we get here and there's an introduced/fixed/last_affected, it's affected
	return introduced != nil || fixed != nil || lastAffected != nil
}

// isVersionInRangeString performs string-based comparison as fallback
func isVersionInRangeString(version string, vrange models.Range) bool {
	for _, event := range vrange.Events {
		// Simple string comparison for non-semver versions
		if event.Introduced != "" {
			if version < event.Introduced {
				return false
			}
		}
		if event.Fixed != "" {
			if version >= event.Fixed {
				return false
			}
		}
		if event.LastAffected != "" {
			if version > event.LastAffected {
				return false
			}
		}
	}
	return true
}
