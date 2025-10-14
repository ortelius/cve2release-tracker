// Package model - API types for combining models in API requests/responses
package model

// ReleaseWithSBOM combines ProjectRelease and SBOM for API communication
type ReleaseWithSBOM struct {
	ProjectRelease
	SBOM SBOM `json:"sbom"`
}
