package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/ortelius/scec-db/model"
	"github.com/ortelius/scec-db/util"
	"github.com/spf13/cobra"
)

// ReleaseWithSBOM combines both ProjectRelease and SBOM for API requests/responses
// This matches the server's handler model
type ReleaseWithSBOM struct {
	model.ProjectRelease
	SBOM model.SBOM `json:"sbom"`
}

var (
	serverURL   string
	sbomFile    string
	projectType string
	verbose     bool
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "scec-cli",
	Short: "SCEC Database CLI for managing releases and SBOMs",
	Long: `A CLI tool for interacting with the SCEC Database API.
Collects git metadata from the local repository and posts
releases with their associated SBOMs.`,
}

// uploadCmd represents the upload command
var uploadCmd = &cobra.Command{
	Use:   "upload",
	Short: "Upload a release with SBOM to the SCEC database",
	Long: `Collects git metadata from the current repository and uploads
a release along with its SBOM to the SCEC database.`,
	RunE: runUpload,
}

func init() {
	rootCmd.AddCommand(uploadCmd)

	// Persistent flags available to all commands
	rootCmd.PersistentFlags().StringVar(&serverURL, "server", "http://localhost:3000", "SCEC API server URL")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// Upload command specific flags
	uploadCmd.Flags().StringVarP(&sbomFile, "sbom", "s", "", "Path to SBOM file (required)")
	uploadCmd.Flags().StringVarP(&projectType, "type", "t", "application", "Project type (application, library, etc.)")
	uploadCmd.MarkFlagRequired("sbom")
}

// Execute runs the root command
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runUpload(cmd *cobra.Command, args []string) error {
	// Validate SBOM file exists
	if _, err := os.Stat(sbomFile); os.IsNotExist(err) {
		return fmt.Errorf("SBOM file not found: %s", sbomFile)
	}

	// Read SBOM file
	sbomContent, err := os.ReadFile(sbomFile)
	if err != nil {
		return fmt.Errorf("failed to read SBOM file: %w", err)
	}

	// Validate SBOM is valid JSON
	var sbomJSON map[string]any
	if err := json.Unmarshal(sbomContent, &sbomJSON); err != nil {
		return fmt.Errorf("SBOM file is not valid JSON: %w", err)
	}

	// Validate it's a CycloneDX SBOM
	if bomFormat, ok := sbomJSON["bomFormat"].(string); !ok || bomFormat != "CycloneDX" {
		return fmt.Errorf("SBOM must be in CycloneDX format (bomFormat field missing or incorrect)")
	}

	if verbose {
		fmt.Printf("Loaded CycloneDX SBOM from: %s\n", sbomFile)
		if specVersion, ok := sbomJSON["specVersion"].(string); ok {
			fmt.Printf("CycloneDX Spec Version: %s\n", specVersion)
		}
		if components, ok := sbomJSON["components"].([]interface{}); ok {
			fmt.Printf("Number of components: %d\n", len(components))
		}
	}

	if verbose {
		fmt.Println("Collecting git metadata...")
	}

	// Collect git metadata using the utility function
	mapping := make(map[string]string)
	mapping = util.GetDerivedEnvMapping(mapping)

	// Build the release object
	release := buildRelease(mapping, projectType)

	// Build the SBOM object - store the raw CycloneDX JSON
	sbom := model.NewSBOM()
	sbom.Content = json.RawMessage(sbomContent)

	// Create the combined request using ReleaseWithSBOM structure
	request := ReleaseWithSBOM{
		ProjectRelease: *release,
		SBOM:           *sbom,
	}

	if verbose {
		fmt.Printf("Uploading release: %s version %s\n", release.Name, release.Version)
	}

	// Send POST request
	if err := postRelease(serverURL, request); err != nil {
		return fmt.Errorf("failed to upload release: %w", err)
	}

	fmt.Printf("✓ Successfully uploaded release %s version %s\n", release.Name, release.Version)
	return nil
}

func buildRelease(mapping map[string]string, projectType string) *model.ProjectRelease {
	release := model.NewProjectRelease()

	// Required fields
	release.Name = getOrDefault(mapping["CompName"], mapping["GitRepoProject"], "unknown")
	release.Version = getOrDefault(mapping["DockerTag"], mapping["GitCommit"], "0.0.0")
	release.ProjectType = projectType

	// Optional fields from mapping
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

	// Parse timestamps
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

	return release
}

func parseGitDate(dateStr string) (time.Time, error) {
	// Try common git date formats
	formats := []string{
		time.RFC3339,
		time.RFC1123Z,
		"Mon Jan 2 15:04:05 2006 -0700",
		"2006-01-02 15:04:05 -0700",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("unable to parse date: %s", dateStr)
}

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

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all releases in the database",
	Long:  `Retrieves and displays all releases with their key, name, and version.`,
	RunE:  runList,
}

func init() {
	rootCmd.AddCommand(listCmd)
}

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

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned status %d: %s", resp.StatusCode, string(body))
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

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get [name] [version]",
	Short: "Get a specific release by name and version",
	Long:  `Retrieves and displays a specific release with its SBOM by name and version.`,
	Args:  cobra.ExactArgs(2),
	RunE:  runGet,
}

var (
	outputFile string
	sbomOnly   bool
)

func init() {
	rootCmd.AddCommand(getCmd)
	getCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Write SBOM to file (optional)")
	getCmd.Flags().BoolVar(&sbomOnly, "sbom-only", false, "Output only SBOM content")
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

	var result ReleaseWithSBOM

	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// If sbom-only flag is set, only output SBOM
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

	// Display full release information
	fmt.Printf("Release: %s\n", result.Name)
	fmt.Printf("Version: %s\n", result.Version)
	fmt.Printf("Type: %s\n", result.ProjectType)
	fmt.Printf("Git Commit: %s\n", result.GitCommit)
	fmt.Printf("Git Branch: %s\n", result.GitBranch)
	fmt.Printf("Docker Repo: %s\n", result.DockerRepo)
	fmt.Printf("Docker Tag: %s\n", result.DockerTag)
	fmt.Println()

	// Handle SBOM output
	if outputFile != "" {
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, result.SBOM.Content, "", "  "); err != nil {
			return fmt.Errorf("failed to format SBOM: %w", err)
		}

		if err := os.WriteFile(outputFile, prettyJSON.Bytes(), 0644); err != nil {
			return fmt.Errorf("failed to write SBOM to file: %w", err)
		}
		fmt.Printf("SBOM written to: %s\n", outputFile)
	} else if verbose {
		fmt.Println("SBOM Content:")
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, result.SBOM.Content, "", "  "); err == nil {
			fmt.Println(prettyJSON.String())
		}
	}

	return nil
}
