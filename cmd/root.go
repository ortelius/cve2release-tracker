// Package cmd implements the command line interface (CLI) commands
// for interacting with the CVE2Release-Tracker API, including uploading releases,
// generating SBOMs using Syft, and fetching release details.
package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/ortelius/cve2release-tracker/model"
	"github.com/ortelius/cve2release-tracker/util"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	// Import SQLite driver for Syft's RPM database scanning
	_ "github.com/glebarez/go-sqlite"
)

var (
	serverURL   string
	sbomFile    string
	projectType string
	processFile string
	verbose     bool
	outputFile  string
	sbomOnly    bool
)

// -------------------- CLI COMMANDS --------------------

var rootCmd = &cobra.Command{
	Use:   "cve2release-cli",
	Short: "CVE2Release‑Tracker CLI for managing releases and SBOMs",
}

var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload a release with SBOM",
	RunE:  runUpload,
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all releases",
	RunE:  runList,
}

var getCmd = &cobra.Command{
	Use:   "get [name] [version]",
	Short: "Get a specific release by name and version",
	Args:  cobra.ExactArgs(2),
	RunE:  runGet,
}

// ProcessConfig defines the structure for the optional process.yaml file,
// listing repositories and their corresponding release branches to process.
type ProcessConfig struct {
	Repositories map[string]string `yaml:"repositories"`
}

func init() {
	rootCmd.AddCommand(uploadCmd, listCmd, getCmd)

	rootCmd.PersistentFlags().StringVar(&serverURL, "server", "http://localhost:3000", "CVE2Release‑Tracker API server URL")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	uploadCmd.Flags().StringVarP(&sbomFile, "sbom", "s", "", "Path to SBOM file (optional)")
	uploadCmd.Flags().StringVarP(&projectType, "type", "t", "application", "Project type (application, library, docker, etc.)")
	uploadCmd.Flags().StringVarP(&processFile, "process", "p", "", "Optional process.yaml file listing repositories and releases")

	getCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write SBOM to file (optional)")
	getCmd.Flags().BoolVar(&sbomOnly, "sbom-only", false, "Output only SBOM content")
}

// Execute adds all child commands to the root command and sets flags appropriately.
// It is the primary entry point for the CLI application.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// -------------------- UPLOAD LOGIC --------------------

func runUpload(_ *cobra.Command, _ []string) error {
	if processFile != "" {
		cfg, err := loadProcessFile(processFile)
		if err != nil {
			return err
		}
		for repo, releaseBranch := range cfg.Repositories {
			fmt.Printf("Processing repo %s for release %s\n", repo, releaseBranch)
			tempDir, err := os.MkdirTemp("", "repo-*")
			if err != nil {
				return fmt.Errorf("failed to create temp dir: %w", err)
			}
			defer os.RemoveAll(tempDir)

			if err := gitCloneCheckout(repo, releaseBranch, tempDir); err != nil {
				return fmt.Errorf("failed to clone and checkout: %w", err)
			}
			if verbose {
				fmt.Printf("Cloned repo into %s\n", tempDir)
			}

			if err := processDirectory(tempDir); err != nil {
				return fmt.Errorf("failed to process repo %s: %w", repo, err)
			}
		}
		return nil
	}

	// No process.yaml: use current directory
	return processDirectory(".")
}

func loadProcessFile(path string) (*ProcessConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read process file: %w", err)
	}
	var cfg ProcessConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse process.yaml: %w", err)
	}
	if len(cfg.Repositories) == 0 {
		return nil, fmt.Errorf("no repositories defined in process.yaml")
	}
	return &cfg, nil
}

func gitCloneCheckout(repoURL, releaseBranch, dest string) error {
	cmd := exec.Command("git", "clone", "--depth", "1", "--branch", releaseBranch, repoURL, dest)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func processDirectory(dir string) error {
	var sbomContent []byte
	var err error

	if sbomFile != "" {
		sbomContent, err = os.ReadFile(sbomFile)
		if err != nil {
			return fmt.Errorf("failed to read SBOM file: %w", err)
		}
	} else {
		if verbose {
			fmt.Printf("Generating SBOM from %s using Syft...\n", dir)
		}
		sbomContent, err = generateSBOM(dir)
		if err != nil {
			return fmt.Errorf("failed to generate SBOM: %w", err)
		}
		if verbose {
			fmt.Printf("Generated SBOM for directory %s\n", dir)
		}
	}

	var sbomJSON map[string]interface{}
	if err := json.Unmarshal(sbomContent, &sbomJSON); err != nil {
		return fmt.Errorf("SBOM is not valid JSON: %w", err)
	}
	if bomFormat, ok := sbomJSON["bomFormat"].(string); !ok || bomFormat != "CycloneDX" {
		return fmt.Errorf("SBOM must be in CycloneDX format (bomFormat field missing or incorrect)")
	}

	mapping := util.GetDerivedEnvMapping(make(map[string]string))
	if processFile == "" {
		if verbose {
			fmt.Println("No process.yaml provided: deriving release version from git tag")
		}
		tag, err := getLatestGitTag(dir)
		if err != nil {
			return fmt.Errorf("failed to get latest git tag: %w", err)
		}
		mapping["GitTag"] = tag
		if verbose {
			fmt.Printf("Derived release version: %s\n", tag)
		}
	}

	release := buildRelease(mapping, projectType)

	// Fetch OpenSSF Scorecard data if git repository information is available
	if release.GitURL != "" && release.GitCommit != "" {
		if verbose {
			fmt.Printf("Fetching OpenSSF Scorecard data for %s @ %s...\n", release.GitURL, release.GitCommit)
		}
		scorecardResult, aggregateScore, err := fetchOpenSSFScorecard(release.GitURL, release.GitCommit)
		if err != nil {
			if verbose {
				fmt.Printf("Warning: Failed to fetch OpenSSF Scorecard data: %v\n", err)
			}
			// Don't fail the upload if scorecard fetch fails, just continue without it
		} else {
			release.ScorecardResult = scorecardResult
			release.OpenSSFScorecardScore = aggregateScore
			if verbose {
				fmt.Printf("OpenSSF Scorecard score: %.2f/10\n", release.OpenSSFScorecardScore)
			}
		}
	}

	sbomObj := model.NewSBOM()
	sbomObj.Content = json.RawMessage(sbomContent)

	request := model.ReleaseWithSBOM{
		ProjectRelease: *release,
		SBOM:           *sbomObj,
	}

	if verbose {
		fmt.Printf("Uploading release: %s version %s\n", release.Name, release.Version)
		if release.ContentSha != "" {
			fmt.Printf("ContentSha: %s\n", release.ContentSha)
		}
		if release.OpenSSFScorecardScore >= 0 {
			fmt.Printf("OpenSSF Scorecard Score: %.2f/10\n", release.OpenSSFScorecardScore)
		}
	}

	if err := postRelease(serverURL, request); err != nil {
		return fmt.Errorf("failed to upload release: %w", err)
	}

	fmt.Printf("✓ Successfully uploaded release %s version %s\n", release.Name, release.Version)
	return nil
}

// -------------------- OpenSSF Scorecard API --------------------

// fetchOpenSSFScorecard fetches scorecard data from the OpenSSF Scorecard API
// If the scorecard doesn't exist, it triggers a scan and waits for results
// Returns: ScorecardAPIResponse (matches API structure), aggregate score, error
func fetchOpenSSFScorecard(gitURL, commitSha string) (*model.ScorecardAPIResponse, float64, error) {
	// Parse the Git URL to extract platform, org, and repo
	// Example: https://github.com/ortelius/cve2release-tracker
	platform, org, repo, err := parseGitURL(gitURL)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse git URL: %w", err)
	}

	// Try to fetch existing scorecard first
	result, aggregateScore, err := getScorecardData(platform, org, repo, commitSha)
	if err == nil {
		return result, aggregateScore, nil
	}

	// If scorecard not found, trigger a new scan
	if strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "404") {
		if verbose {
			fmt.Printf("Scorecard not found. Triggering new scan for %s/%s/%s...\n", platform, org, repo)
		}

		// Trigger a new scorecard scan
		if err := triggerScorecardScan(platform, org, repo); err != nil {
			return nil, 0, fmt.Errorf("failed to trigger scorecard scan: %w", err)
		}

		// Wait for the scan to complete and fetch results
		if verbose {
			fmt.Println("Waiting for scorecard scan to complete...")
		}

		// Retry with exponential backoff
		maxRetries := 5
		for i := 0; i < maxRetries; i++ {
			waitTime := time.Duration(5*(i+1)) * time.Second
			if verbose {
				fmt.Printf("Waiting %v before retry %d/%d...\n", waitTime, i+1, maxRetries)
			}
			time.Sleep(waitTime)

			result, aggregateScore, err := getScorecardData(platform, org, repo, commitSha)
			if err == nil {
				return result, aggregateScore, nil
			}

			if !strings.Contains(err.Error(), "not found") && !strings.Contains(err.Error(), "404") {
				// Different error, not a "not found" error
				return nil, 0, err
			}
		}

		return nil, 0, fmt.Errorf("scorecard scan timed out after %d retries", maxRetries)
	}

	return nil, 0, err
}

// getScorecardData fetches existing scorecard data from the API
// Returns: ScorecardAPIResponse, aggregate score, error
func getScorecardData(platform, org, repo, commitSha string) (*model.ScorecardAPIResponse, float64, error) {
	// OpenSSF Scorecard API endpoint
	// https://api.securityscorecards.dev/projects/{platform}/{org}/{repo}
	apiURL := fmt.Sprintf("https://api.securityscorecards.dev/projects/%s/%s/%s", platform, org, repo)

	if verbose {
		fmt.Printf("Fetching scorecard from: %s\n", apiURL)
	}

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers as recommended by the API
	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, 0, fmt.Errorf("scorecard not found for repository %s/%s/%s", platform, org, repo)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var apiResponse model.ScorecardAPIResponse
	if err := json.Unmarshal(body, &apiResponse); err != nil {
		return nil, 0, fmt.Errorf("failed to parse API response: %w", err)
	}

	// Update the commit SHA to match what was requested (API may return latest)
	apiResponse.Repo.Commit = commitSha

	// Use the aggregate score provided by the API
	aggregateScore := apiResponse.Score

	return &apiResponse, aggregateScore, nil
}

// triggerScorecardScan triggers a new scorecard scan via the API
func triggerScorecardScan(platform, org, repo string) error {
	// The OpenSSF Scorecard API automatically triggers scans for GitHub repos
	// when accessed via their REST API endpoint
	apiURL := fmt.Sprintf("https://api.securityscorecards.dev/projects/%s/%s/%s", platform, org, repo)

	// Make a POST request to trigger the scan
	// Note: Some APIs use POST to trigger, but OpenSSF might auto-trigger on GET
	// We'll try a POST first, and if that fails, rely on auto-triggering
	req, err := http.NewRequest("POST", apiURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create scan request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		if verbose {
			fmt.Printf("POST request failed (expected, will auto-trigger): %v\n", err)
		}
		// POST might not be supported, but GET should auto-trigger
		return nil
	}
	defer resp.Body.Close()

	// Any 2xx or 404 response is acceptable
	// 404 means the endpoint doesn't support POST, but GET should auto-trigger
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if verbose {
			fmt.Println("Scorecard scan triggered successfully")
		}
		return nil
	}

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		if verbose {
			fmt.Println("POST not supported, relying on auto-trigger via GET requests")
		}
		return nil
	}

	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("unexpected response from scan trigger: %d - %s", resp.StatusCode, string(body))
}

// parseGitURL extracts platform, org, and repo from a git URL
func parseGitURL(gitURL string) (platform, org, repo string, err error) {
	// Remove .git suffix if present
	gitURL = strings.TrimSuffix(gitURL, ".git")

	// Remove protocol
	gitURL = strings.TrimPrefix(gitURL, "https://")
	gitURL = strings.TrimPrefix(gitURL, "http://")
	gitURL = strings.TrimPrefix(gitURL, "git@")

	// Replace : with / for SSH URLs
	gitURL = strings.ReplaceAll(gitURL, ":", "/")

	// Split the URL
	parts := strings.Split(gitURL, "/")

	if len(parts) < 3 {
		return "", "", "", fmt.Errorf("invalid git URL format: %s", gitURL)
	}

	platform = parts[0]
	org = parts[1]
	repo = parts[2]

	// Map platform names to expected format
	switch {
	case strings.Contains(platform, "github"):
		platform = "github.com"
	case strings.Contains(platform, "gitlab"):
		platform = "gitlab.com"
	default:
		// Use as-is for other platforms
	}

	return platform, org, repo, nil
}

// -------------------- Syft SBOM GENERATION --------------------

func generateSBOM(dir string) ([]byte, error) {
	ctx := context.Background()

	// Convert to absolute path to avoid Syft misinterpreting relative paths
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to get absolute path: %w", err)
	}

	src, err := syft.GetSource(ctx, absDir, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create source: %w", err)
	}

	sbomResult, err := syft.CreateSBOM(ctx, src, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create SBOM: %w", err)
	}

	// Setup encoder configuration
	cfg := cyclonedxjson.DefaultEncoderConfig()
	cfg.Pretty = true

	enc, err := cyclonedxjson.NewFormatEncoderWithConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create format encoder: %w", err)
	}

	var buf bytes.Buffer
	if err := enc.Encode(&buf, *sbomResult); err != nil {
		return nil, fmt.Errorf("failed to encode SBOM to CycloneDX JSON: %w", err)
	}

	return buf.Bytes(), nil
}

// -------------------- GIT HELPERS --------------------

func getLatestGitTag(dir string) (string, error) {
	cmd := exec.Command("git", "-C", dir, "describe", "--tags", "--abbrev=0")
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git describe failed: %w", err)
	}
	return strings.TrimSpace(string(out)), nil
}

// -------------------- ORIGINAL buildRelease & parseGitDate --------------------

func buildRelease(mapping map[string]string, projectType string) *model.ProjectRelease {
	release := model.NewProjectRelease()
	release.Name = getOrDefault(mapping["CompName"], mapping["GitRepoProject"], "unknown")
	release.Version = getOrDefault(mapping["DockerTag"], mapping["GitTag"], "0.0.0")
	release.ProjectType = projectType

	release.Basename = mapping["BaseName"]
	release.BuildID = mapping["BuildId"]
	release.BuildNum = mapping["BuildNumber"]
	release.BuildURL = mapping["BuildUrl"]
	release.DockerRepo = mapping["DockerRepo"]
	release.DockerSha = mapping["DockerSha"]
	release.DockerTag = mapping["DockerTag"]
	release.GitBranch = mapping["GitBranch"]
	release.GitBranchCreateCommit = mapping["GitBranchCreateCommit"]
	release.GitBranchParent = mapping["GitBranchParent"]
	release.GitCommit = mapping["GitCommit"]
	release.GitCommitAuthors = mapping["GitCommitAuthors"]
	release.GitCommittersCnt = mapping["GitCommittersCnt"]
	release.GitContribPercentage = mapping["GitContribPercentage"]
	release.GitLinesAdded = mapping["GitLinesAdded"]
	release.GitLinesDeleted = mapping["GitLinesDeleted"]
	release.GitLinesTotal = mapping["GitLinesTotal"]
	release.GitOrg = mapping["GitOrg"]
	release.GitPrevCompCommit = mapping["GitPrevCompCommit"]
	release.GitRepo = mapping["GitRepo"]
	release.GitRepoProject = mapping["GitRepoProject"]
	release.GitSignedOffBy = mapping["GitSignedOffBy"]
	release.GitTag = mapping["GitTag"]
	release.GitTotalCommittersCnt = mapping["GitTotalCommittersCnt"]
	release.GitURL = mapping["GitUrl"]
	release.GitVerifyCommit = mapping["GitVerifyCommit"] == "Y"

	if buildDate := mapping["BuildDate"]; buildDate != "" {
		if t, err := time.Parse(time.RFC3339, buildDate); err == nil {
			release.BuildDate = t
		}
	}
	if gitBranchCreateTimestamp := mapping["GitBranchCreateTimestamp"]; gitBranchCreateTimestamp != "" {
		if t, err := parseGitDate(gitBranchCreateTimestamp); err == nil {
			release.GitBranchCreateTimestamp = t
		}
	}
	if gitCommitTimestamp := mapping["GitCommitTimestamp"]; gitCommitTimestamp != "" {
		if t, err := parseGitDate(gitCommitTimestamp); err == nil {
			release.GitCommitTimestamp = t
		}
	}

	populateContentSha(release)
	return release
}

func parseGitDate(dateStr string) (time.Time, error) {
	formats := []string{
		time.RFC3339,
		time.RFC1123Z,
		"Mon Jan 2 15:04:05 2006 -0700",
		"2006-01-02 15:04:05 -0700",
	}
	for _, f := range formats {
		if t, err := time.Parse(f, dateStr); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}

func populateContentSha(release *model.ProjectRelease) {
	if release.ProjectType == "docker" || release.ProjectType == "container" {
		if release.DockerSha != "" {
			release.ContentSha = release.DockerSha
		} else if release.GitCommit != "" {
			release.ContentSha = release.GitCommit
		}
	} else {
		if release.GitCommit != "" {
			release.ContentSha = release.GitCommit
		} else if release.DockerSha != "" {
			release.ContentSha = release.DockerSha
		}
	}
}

// -------------------- HELPERS --------------------

func getOrDefault(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func postRelease(serverURL string, payload interface{}) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	if verbose {
		fmt.Println("Request payload:")
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, jsonData, "", "  "); err == nil {
			fmt.Println(prettyJSON.String())
		}
	}
	url := serverURL + "/api/v1/releases"
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}
	if verbose {
		fmt.Println("Server response:")
		fmt.Println(string(body))
	}
	return nil
}

// -------------------- LIST & GET --------------------

func runList(_ *cobra.Command, _ []string) error {
	url := serverURL + "/api/v1/releases"
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	var result struct {
		Success  bool `json:"success"`
		Count    int  `json:"count"`
		Releases []struct {
			Key     string `json:"_key"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}
	if !result.Success {
		return fmt.Errorf("API returned success=false")
	}

	fmt.Printf("Found %d release(s):\n\n", result.Count)
	fmt.Printf("%-40s %-30s %-20s\n", "KEY", "NAME", "VERSION")
	fmt.Println("─────────────────────────────────────────────────────────────────────────────────────────")
	for _, release := range result.Releases {
		fmt.Printf("%-40s %-30s %-20s\n", release.Key, release.Name, release.Version)
	}
	return nil
}

func runGet(_ *cobra.Command, args []string) error {
	name := args[0]
	version := args[1]

	url := fmt.Sprintf("%s/api/v1/releases/%s/%s", serverURL, name, version)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("release not found: %s version %s", name, version)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
	}

	var result model.ReleaseWithSBOM
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	if sbomOnly {
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, result.SBOM.Content, "", "  "); err != nil {
			return fmt.Errorf("failed to format SBOM: %w", err)
		}
		if outputFile != "" {
			if err := os.WriteFile(outputFile, prettyJSON.Bytes(), 0644); err != nil {
				return fmt.Errorf("failed to write SBOM to file: %w", err)
			}
			fmt.Printf("SBOM written to: %s\n", outputFile)
		} else {
			fmt.Println(prettyJSON.String())
		}
		return nil
	}

	// display release info
	fmt.Printf("Release: %s\nVersion: %s\nType: %s\nContentSha: %s\nGit Commit: %s\nGit Branch: %s\nDocker Repo: %s\nDocker Tag: %s\nDocker SHA: %s\n",
		result.Name, result.Version, result.ProjectType, result.ContentSha,
		result.GitCommit, result.GitBranch, result.DockerRepo, result.DockerTag, result.DockerSha,
	)

	if result.OpenSSFScorecardScore >= 0 {
		fmt.Printf("OpenSSF Scorecard Score: %.2f/10\n", result.OpenSSFScorecardScore)
	}

	return nil
}
