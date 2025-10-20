// Package model - API types for combining models in API requests/responses
package model

import "time"

// ReleaseWithSBOM combines ProjectRelease and SBOM for API communication
type ReleaseWithSBOM struct {
	ProjectRelease
	SBOM SBOM `json:"sbom"`
}

// Sync represents the association between a release and an endpoint (deployment)
type Sync struct {
	Key            string    `json:"_key,omitempty"`
	ReleaseName    string    `json:"release_name"`
	ReleaseVersion string    `json:"release_version"`
	EndpointName   string    `json:"endpoint_name"`
	SyncedAt       time.Time `json:"synced_at"`
	ObjType        string    `json:"objtype,omitempty"`
}

// NewSync creates a new Sync instance with default values
func NewSync() *Sync {
	return &Sync{
		ObjType:  "Sync",
		SyncedAt: time.Now(),
	}
}

// AffectedRelease represents a release that is affected by a CVE
type AffectedRelease struct {
	CveID           string   `json:"cve_id"`
	Summary         string   `json:"summary"`
	Details         string   `json:"details"`
	Severity        string   `json:"severity"`
	Published       string   `json:"published"`
	Modified        string   `json:"modified"`
	Aliases         []string `json:"aliases"`
	Package         string   `json:"package"`
	AffectedVersion string   `json:"affected_version"`
	FullPurl        string   `json:"full_purl"`
	ReleaseName     string   `json:"release_name"`
	ReleaseVersion  string   `json:"release_version"`
	ContentSha      string   `json:"content_sha"`
	ProjectType     string   `json:"project_type"`
}

// AffectedEndpoint represents an endpoint that is affected by a CVE
type AffectedEndpoint struct {
	CveID           string    `json:"cve_id"`
	Summary         string    `json:"summary"`
	Details         string    `json:"details"`
	Severity        string    `json:"severity"`
	Published       string    `json:"published"`
	Modified        string    `json:"modified"`
	Aliases         []string  `json:"aliases"`
	Package         string    `json:"package"`
	AffectedVersion string    `json:"affected_version"`
	FullPurl        string    `json:"full_purl"`
	ReleaseName     string    `json:"release_name"`
	ReleaseVersion  string    `json:"release_version"`
	ContentSha      string    `json:"content_sha"`
	ProjectType     string    `json:"project_type"`
	EndpointName    string    `json:"endpoint_name"`
	EndpointType    string    `json:"endpoint_type"`
	Environment     string    `json:"environment"`
	SyncedAt        time.Time `json:"synced_at"`
}
