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

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// -------------------- UPLOAD LOGIC --------------------

func runUpload(cmd *cobra.Command, args []string) error {
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
	}

	if err := postRelease(serverURL, request); err != nil {
		return fmt.Errorf("failed to upload release: %w", err)
	}

	fmt.Printf("✓ Successfully uploaded release %s version %s\n", release.Name, release.Version)
	return nil
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

func runList(cmd *cobra.Command, args []string) error {
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

func runGet(cmd *cobra.Command, args []string) error {
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
	return nil
}
