package graphql

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/graphql-go/graphql"
	"github.com/ortelius/cve2release-tracker/database"
	"github.com/ortelius/cve2release-tracker/model"
	"github.com/ortelius/cve2release-tracker/util"
)

var db database.DBConnection

// InitDB sets the database connection for GraphQL resolvers
func InitDB(dbConn database.DBConnection) {
	db = dbConn
}

// SeverityType represents the severity enum
var SeverityType = graphql.NewEnum(graphql.EnumConfig{
	Name: "Severity",
	Values: graphql.EnumValueConfigMap{
		"CRITICAL": &graphql.EnumValueConfig{Value: "critical"},
		"HIGH":     &graphql.EnumValueConfig{Value: "high"},
		"MEDIUM":   &graphql.EnumValueConfig{Value: "medium"},
		"LOW":      &graphql.EnumValueConfig{Value: "low"},
		"NONE":     &graphql.EnumValueConfig{Value: "none"},
	},
})

// VulnerabilityType represents a vulnerability in GraphQL
var VulnerabilityType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Vulnerability",
	Fields: graphql.Fields{
		"cve_id": &graphql.Field{
			Type: graphql.String,
		},
		"summary": &graphql.Field{
			Type: graphql.String,
		},
		"details": &graphql.Field{
			Type: graphql.String,
		},
		"severity_score": &graphql.Field{
			Type: graphql.Float,
		},
		"severity_rating": &graphql.Field{
			Type: graphql.String,
		},
		"cvss_v3_score": &graphql.Field{
			Type: graphql.String,
		},
		"published": &graphql.Field{
			Type: graphql.String,
		},
		"modified": &graphql.Field{
			Type: graphql.String,
		},
		"aliases": &graphql.Field{
			Type: graphql.NewList(graphql.String),
		},
		"package": &graphql.Field{
			Type: graphql.String,
		},
		"affected_version": &graphql.Field{
			Type: graphql.String,
		},
		"full_purl": &graphql.Field{
			Type: graphql.String,
		},
		"fixed_in": &graphql.Field{
			Type: graphql.NewList(graphql.String),
		},
	},
})

// SBOMType represents an SBOM in GraphQL
var SBOMType = graphql.NewObject(graphql.ObjectConfig{
	Name: "SBOM",
	Fields: graphql.Fields{
		"key": &graphql.Field{
			Type: graphql.String,
		},
		"contentsha": &graphql.Field{
			Type: graphql.String,
		},
		"objtype": &graphql.Field{
			Type: graphql.String,
		},
		"content": &graphql.Field{
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if sbom, ok := p.Source.(model.SBOM); ok {
					return string(sbom.Content), nil
				}
				return nil, nil
			},
		},
		"dependency_count": &graphql.Field{
			Type: graphql.Int,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				sbom, ok := p.Source.(model.SBOM)
				if !ok {
					return 0, nil
				}

				// Use AQL to get the length of components array
				ctx := context.Background()
				query := `
					LET sbom = DOCUMENT(@sbomKey)
					RETURN sbom.content.components != null ? LENGTH(sbom.content.components) : 0
				`

				cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
					BindVars: map[string]interface{}{
						"sbomKey": sbom.Key,
					},
				})
				if err != nil {
					log.Printf("Error querying dependency_count: %v", err)
					return 0, nil
				}
				defer cursor.Close()

				var count int
				if cursor.HasMore() {
					_, err = cursor.ReadDocument(ctx, &count)
					if err != nil {
						log.Printf("Error reading dependency_count: %v", err)
						return 0, nil
					}
					return count, nil
				}

				return 0, nil
			},
		},
	},
})

// ReleaseType represents a release in GraphQL
var ReleaseType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Release",
	Fields: graphql.Fields{
		"key": &graphql.Field{
			Type: graphql.String,
		},
		"name": &graphql.Field{
			Type: graphql.String,
		},
		"version": &graphql.Field{
			Type: graphql.String,
		},
		"project_type": &graphql.Field{
			Type: graphql.String,
		},
		"content_sha": &graphql.Field{
			Type: graphql.String,
		},
		"git_commit": &graphql.Field{
			Type: graphql.String,
		},
		"git_branch": &graphql.Field{
			Type: graphql.String,
		},
		"docker_repo": &graphql.Field{
			Type: graphql.String,
		},
		"docker_tag": &graphql.Field{
			Type: graphql.String,
		},
		"docker_sha": &graphql.Field{
			Type: graphql.String,
		},
		"openssf_score": &graphql.Field{
			Type: graphql.Float,
		},
		"sbom": &graphql.Field{
			Type: SBOMType,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				release, ok := p.Source.(model.ProjectRelease)
				if !ok {
					return nil, nil
				}

				ctx := context.Background()
				sbomQuery := `
					FOR r IN release
						FILTER r.name == @name && r.version == @version
						FOR v IN 1..1 OUTBOUND r release2sbom
							RETURN v
				`

				cursor, err := db.Database.Query(ctx, sbomQuery, &arangodb.QueryOptions{
					BindVars: map[string]interface{}{
						"name":    release.Name,
						"version": release.Version,
					},
				})
				if err != nil {
					return nil, err
				}
				defer cursor.Close()

				var sbom model.SBOM
				if cursor.HasMore() {
					_, err = cursor.ReadDocument(ctx, &sbom)
					if err != nil {
						return nil, err
					}
					return sbom, nil
				}

				return nil, nil
			},
		},
		"vulnerabilities": &graphql.Field{
			Type: graphql.NewList(VulnerabilityType),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				release, ok := p.Source.(model.ProjectRelease)
				if !ok {
					return nil, nil
				}
				return resolveReleaseVulnerabilities(release.Name, release.Version)
			},
		},
		"dependency_count": &graphql.Field{
			Type: graphql.Int,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				release, ok := p.Source.(model.ProjectRelease)
				if !ok {
					return 0, nil
				}

				ctx := context.Background()
				query := `
					FOR r IN release
						FILTER r.name == @name && r.version == @version
						FOR sbom IN 1..1 OUTBOUND r release2sbom
							RETURN sbom.content.components != null ? LENGTH(sbom.content.components) : 0
				`

				cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
					BindVars: map[string]interface{}{
						"name":    release.Name,
						"version": release.Version,
					},
				})
				if err != nil {
					log.Printf("Error querying dependency_count: %v", err)
					return 0, nil
				}
				defer cursor.Close()

				var count int
				if cursor.HasMore() {
					_, err = cursor.ReadDocument(ctx, &count)
					if err != nil {
						log.Printf("Error reading dependency_count: %v", err)
						return 0, nil
					}
					return count, nil
				}

				return 0, nil
			},
		},
	},
})

// AffectedReleaseType represents an affected release
var AffectedReleaseType = graphql.NewObject(graphql.ObjectConfig{
	Name: "AffectedRelease",
	Fields: graphql.Fields{
		"cve_id": &graphql.Field{
			Type: graphql.String,
		},
		"summary": &graphql.Field{
			Type: graphql.String,
		},
		"details": &graphql.Field{
			Type: graphql.String,
		},
		"severity_score": &graphql.Field{
			Type: graphql.Float,
		},
		"severity_rating": &graphql.Field{
			Type: graphql.String,
		},
		"published": &graphql.Field{
			Type: graphql.String,
		},
		"modified": &graphql.Field{
			Type: graphql.String,
		},
		"aliases": &graphql.Field{
			Type: graphql.NewList(graphql.String),
		},
		"package": &graphql.Field{
			Type: graphql.String,
		},
		"affected_version": &graphql.Field{
			Type: graphql.String,
		},
		"full_purl": &graphql.Field{
			Type: graphql.String,
		},
		"fixed_in": &graphql.Field{
			Type: graphql.NewList(graphql.String),
		},
		"release_name": &graphql.Field{
			Type: graphql.String,
		},
		"release_version": &graphql.Field{
			Type: graphql.String,
		},
		"content_sha": &graphql.Field{
			Type: graphql.String,
		},
		"project_type": &graphql.Field{
			Type: graphql.String,
		},
		"openssf_scorecard_score": &graphql.Field{
			Type: graphql.Float,
		},
		"dependency_count": &graphql.Field{
			Type: graphql.Int,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				source, ok := p.Source.(map[string]interface{})
				if !ok {
					return 0, nil
				}

				releaseName, _ := source["release_name"].(string)
				releaseVersion, _ := source["release_version"].(string)

				if releaseName == "" || releaseVersion == "" {
					return 0, nil
				}

				ctx := context.Background()
				query := `
					FOR r IN release
						FILTER r.name == @name && r.version == @version
						FOR sbom IN 1..1 OUTBOUND r release2sbom
							RETURN sbom.content.components != null ? LENGTH(sbom.content.components) : 0
				`

				cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
					BindVars: map[string]interface{}{
						"name":    releaseName,
						"version": releaseVersion,
					},
				})
				if err != nil {
					log.Printf("Error querying dependency_count: %v", err)
					return 0, nil
				}
				defer cursor.Close()

				var count int
				if cursor.HasMore() {
					_, err = cursor.ReadDocument(ctx, &count)
					if err != nil {
						log.Printf("Error reading dependency_count: %v", err)
						return 0, nil
					}
					return count, nil
				}

				return 0, nil
			},
		},
	},
})

// AffectedEndpointType represents an affected endpoint
var AffectedEndpointType = graphql.NewObject(graphql.ObjectConfig{
	Name: "AffectedEndpoint",
	Fields: graphql.Fields{
		"cve_id": &graphql.Field{
			Type: graphql.String,
		},
		"summary": &graphql.Field{
			Type: graphql.String,
		},
		"details": &graphql.Field{
			Type: graphql.String,
		},
		"severity_score": &graphql.Field{
			Type: graphql.Float,
		},
		"severity_rating": &graphql.Field{
			Type: graphql.String,
		},
		"published": &graphql.Field{
			Type: graphql.String,
		},
		"modified": &graphql.Field{
			Type: graphql.String,
		},
		"aliases": &graphql.Field{
			Type: graphql.NewList(graphql.String),
		},
		"package": &graphql.Field{
			Type: graphql.String,
		},
		"affected_version": &graphql.Field{
			Type: graphql.String,
		},
		"full_purl": &graphql.Field{
			Type: graphql.String,
		},
		"fixed_in": &graphql.Field{
			Type: graphql.NewList(graphql.String),
		},
		"release_name": &graphql.Field{
			Type: graphql.String,
		},
		"release_version": &graphql.Field{
			Type: graphql.String,
		},
		"content_sha": &graphql.Field{
			Type: graphql.String,
		},
		"project_type": &graphql.Field{
			Type: graphql.String,
		},
		"endpoint_name": &graphql.Field{
			Type: graphql.String,
		},
		"endpoint_type": &graphql.Field{
			Type: graphql.String,
		},
		"environment": &graphql.Field{
			Type: graphql.String,
		},
		"synced_at": &graphql.Field{
			Type: graphql.String,
		},
		"openssf_scorecard_score": &graphql.Field{
			Type: graphql.Float,
		},
		"dependency_count": &graphql.Field{
			Type: graphql.Int,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				source, ok := p.Source.(map[string]interface{})
				if !ok {
					return 0, nil
				}

				releaseName, _ := source["release_name"].(string)
				releaseVersion, _ := source["release_version"].(string)

				if releaseName == "" || releaseVersion == "" {
					return 0, nil
				}

				ctx := context.Background()
				query := `
					FOR r IN release
						FILTER r.name == @name && r.version == @version
						FOR sbom IN 1..1 OUTBOUND r release2sbom
							RETURN sbom.content.components != null ? LENGTH(sbom.content.components) : 0
				`

				cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
					BindVars: map[string]interface{}{
						"name":    releaseName,
						"version": releaseVersion,
					},
				})
				if err != nil {
					log.Printf("Error querying dependency_count: %v", err)
					return 0, nil
				}
				defer cursor.Close()

				var count int
				if cursor.HasMore() {
					_, err = cursor.ReadDocument(ctx, &count)
					if err != nil {
						log.Printf("Error reading dependency_count: %v", err)
						return 0, nil
					}
					return count, nil
				}

				return 0, nil
			},
		},
	},
})

// Helper function to extract fixed versions
func extractFixedVersions(affected models.Affected) []string {
	var fixedVersions []string
	seen := make(map[string]bool)

	for _, vrange := range affected.Ranges {
		for _, event := range vrange.Events {
			if event.Fixed != "" && !seen[event.Fixed] {
				fixedVersions = append(fixedVersions, event.Fixed)
				seen[event.Fixed] = true
			}
		}
	}

	return fixedVersions
}

// Resolver functions
func resolveReleaseVulnerabilities(name, version string) ([]map[string]interface{}, error) {
	ctx := context.Background()

	log.Printf("Fetching vulnerabilities for release %s:%s", name, version)

	query := `
		FOR release IN release
			FILTER release.name == @name AND release.version == @version
			
			FOR sbom IN 1..1 OUTBOUND release release2sbom
				
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbom._id
					
					LET purl = DOCUMENT(sbomEdge._to)
					LET packageVersion = sbomEdge.version
					LET packageFullPurl = sbomEdge.full_purl
					
					FOR cve IN 1..1 INBOUND purl cve2purl
						
						FOR affected IN cve.affected
							
							LET cveBasePurl = affected.package.purl != null ? 
								affected.package.purl : 
								CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
							
							FILTER cveBasePurl == purl.purl

							RETURN {
								cve_id: cve.id,
								summary: cve.summary,
								details: cve.details,
								severity: cve.severity,
								severity_score: cve.database_specific.cvss_base_score,
								severity_rating: cve.database_specific.severity_rating,
								published: cve.published,
								modified: cve.modified,
								aliases: cve.aliases,
								package: purl.purl,
								package_version: packageVersion,
								full_purl: packageFullPurl,
								affected_data: affected
							}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name":    name,
			"version": version,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	type CVEResult struct {
		CveID          string            `json:"cve_id"`
		Summary        string            `json:"summary"`
		Details        string            `json:"details"`
		Severity       []models.Severity `json:"severity"`
		SeverityScore  float64           `json:"severity_score"`
		SeverityRating string            `json:"severity_rating"`
		Published      string            `json:"published"`
		Modified       string            `json:"modified"`
		Aliases        []string          `json:"aliases"`
		Package        string            `json:"package"`
		PackageVersion string            `json:"package_version"`
		FullPurl       string            `json:"full_purl"`
		AffectedData   models.Affected   `json:"affected_data"`
	}

	var vulnerabilities []map[string]interface{}
	seen := make(map[string]bool)

	for cursor.HasMore() {
		var result CVEResult
		_, err := cursor.ReadDocument(ctx, &result)
		if err != nil {
			continue
		}

		if !util.IsVersionAffected(result.PackageVersion, result.AffectedData) {
			continue
		}

		key := result.CveID + ":" + result.Package + ":" + result.PackageVersion
		if seen[key] {
			continue
		}
		seen[key] = true

		var cvssScore string
		for _, sev := range result.Severity {
			if sev.Type == "CVSS_V3" {
				cvssScore = sev.Score
				break
			}
		}

		fixedVersions := extractFixedVersions(result.AffectedData)

		vulnerabilities = append(vulnerabilities, map[string]interface{}{
			"cve_id":           result.CveID,
			"summary":          result.Summary,
			"details":          result.Details,
			"severity_score":   result.SeverityScore,
			"severity_rating":  result.SeverityRating,
			"cvss_v3_score":    cvssScore,
			"published":        result.Published,
			"modified":         result.Modified,
			"aliases":          result.Aliases,
			"package":          result.Package,
			"affected_version": result.PackageVersion,
			"full_purl":        result.FullPurl,
			"fixed_in":         fixedVersions,
		})
	}

	return vulnerabilities, nil
}

func resolveAffectedReleases(severity string) ([]map[string]interface{}, error) {
	ctx := context.Background()

	severityScore := util.GetSeverityScore(severity)

	log.Printf("Querying releases affected by %s severity", severity)

	var query string
	
	// Use separate AQL statements based on severity
	if severityScore == 0.0 {
		// Query without severity filter for NONE
		query = `
			FOR release IN release
				
				FOR sbom IN 1..1 OUTBOUND release release2sbom
					
					FOR sbomEdge IN sbom2purl
						FILTER sbomEdge._from == sbom._id
						
						LET purl = DOCUMENT(sbomEdge._to)
						FILTER purl != null
						
						LET packageVersion = sbomEdge.version
						LET packageFullPurl = sbomEdge.full_purl
						
						// Left outer join with CVEs - include packages even without CVEs
						LET cveMatches = (
							FOR cveEdge IN cve2purl
								FILTER cveEdge._to == purl._id
								
								LET cve = DOCUMENT(cveEdge._from)
								FILTER cve != null
								FILTER cve.affected != null
								
								FOR affected IN cve.affected
									
									LET cveBasePurl = affected.package.purl != null ? 
										affected.package.purl : 
										CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
									
									FILTER cveBasePurl == purl.purl
									
									RETURN {
										cve_id: cve.id,
										cve_summary: cve.summary,
										cve_details: cve.details,
										cve_severity_score: cve.database_specific.cvss_base_score,
										cve_severity_rating: cve.database_specific.severity_rating,
										cve_published: cve.published,
										cve_modified: cve.modified,
										cve_aliases: cve.aliases,
										affected_data: affected
									}
						)
						
						// Return one result per CVE match, or one result with null CVE data if no matches
						FOR cveMatch IN LENGTH(cveMatches) > 0 ? cveMatches : [null]
							LET result = {
								cve_id: cveMatch != null ? cveMatch.cve_id : null,
								cve_summary: cveMatch != null ? cveMatch.cve_summary : null,
								cve_details: cveMatch != null ? cveMatch.cve_details : null,
								cve_severity_score: cveMatch != null ? cveMatch.cve_severity_score : null,
								cve_severity_rating: cveMatch != null ? cveMatch.cve_severity_rating : null,
								cve_published: cveMatch != null ? cveMatch.cve_published : null,
								cve_modified: cveMatch != null ? cveMatch.cve_modified : null,
								cve_aliases: cveMatch != null ? cveMatch.cve_aliases : null,
								affected_data: cveMatch != null ? cveMatch.affected_data : null,
								package: purl.purl,
								version: packageVersion,
								full_purl: packageFullPurl,
								release_name: release.name,
								release_version: release.version,
								content_sha: release.contentsha,
								project_type: release.projecttype,
								openssf_scorecard_score: release.openssf_scorecard_score
							}
							SORT result.cve_severity_score DESC
							RETURN result
		`
	} else {
		// Query with severity filter for LOW, MEDIUM, HIGH, CRITICAL
		query = `
			FOR release IN release
				
				FOR sbom IN 1..1 OUTBOUND release release2sbom
					
					FOR sbomEdge IN sbom2purl
						FILTER sbomEdge._from == sbom._id
						
						LET purl = DOCUMENT(sbomEdge._to)
						FILTER purl != null
						
						LET packageVersion = sbomEdge.version
						LET packageFullPurl = sbomEdge.full_purl
						
						FOR cveEdge IN cve2purl
							FILTER cveEdge._to == purl._id
							
							LET cve = DOCUMENT(cveEdge._from)
							FILTER cve != null
							FILTER cve.database_specific.cvss_base_score >= @severityScore
						
						FILTER cve.affected != null
						FOR affected IN cve.affected
							
							LET cveBasePurl = affected.package.purl != null ? 
								affected.package.purl : 
								CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
							
							FILTER cveBasePurl == purl.purl
							
							LET result = {
								cve_id: cve.id,
								cve_summary: cve.summary,
								cve_details: cve.details,
								cve_severity_score: cve.database_specific.cvss_base_score,
								cve_severity_rating: cve.database_specific.severity_rating,
								cve_published: cve.published,
								cve_modified: cve.modified,
								cve_aliases: cve.aliases,
								affected_data: affected,
								package: purl.purl,
								version: packageVersion,
								full_purl: packageFullPurl,
								release_name: release.name,
								release_version: release.version,
								content_sha: release.contentsha,
								project_type: release.projecttype,
								openssf_scorecard_score: release.openssf_scorecard_score
							}
							SORT result.cve_severity_score DESC
							RETURN result
		`
	}

	var cursor arangodb.Cursor
	var err error
	
	if severityScore == 0.0 {
		// No bind variables needed for NONE severity
		cursor, err = db.Database.Query(ctx, query, nil)
	} else {
		// Bind severity score for other severities
		cursor, err = db.Database.Query(ctx, query, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"severityScore": severityScore,
			},
		})
	}
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	type Candidate struct {
		CveID             *string          `json:"cve_id"`
		CveSummary        *string          `json:"cve_summary"`
		CveDetails        *string          `json:"cve_details"`
		CveSeverityScore  *float64         `json:"cve_severity_score"`
		CveSeverityRating *string          `json:"cve_severity_rating"`
		CvePublished      *string          `json:"cve_published"`
		CveModified       *string          `json:"cve_modified"`
		CveAliases        []string         `json:"cve_aliases"`
		AffectedData      *models.Affected `json:"affected_data"`
		Package           string           `json:"package"`
		Version           string           `json:"version"`
		FullPurl          string           `json:"full_purl"`
		ReleaseName       string           `json:"release_name"`
		ReleaseVersion    string           `json:"release_version"`
		ContentSha             string           `json:"content_sha"`
		ProjectType            string           `json:"project_type"`
		OpenssfScorecardScore  *float64         `json:"openssf_scorecard_score"`
	}

	var affectedReleases []map[string]interface{}
	seen := make(map[string]bool)

	for cursor.HasMore() {
		var candidate Candidate
		_, err := cursor.ReadDocument(ctx, &candidate)
		if err != nil {
			continue
		}

		// Skip version check if there's no CVE data (releases without vulnerabilities)
		if candidate.AffectedData != nil && !util.IsVersionAffected(candidate.Version, *candidate.AffectedData) {
			continue
		}

		// Build key - use empty string for CveID if no CVE
		cveID := ""
		if candidate.CveID != nil {
			cveID = *candidate.CveID
		}
		key := candidate.ReleaseName + ":" + candidate.ReleaseVersion + ":" + candidate.Package + ":" + candidate.Version + ":" + cveID
		if seen[key] {
			continue
		}
		seen[key] = true

		var fixedVersions []string
		if candidate.AffectedData != nil {
			fixedVersions = extractFixedVersions(*candidate.AffectedData)
		}

		affectedReleases = append(affectedReleases, map[string]interface{}{
			"cve_id":           candidate.CveID,
			"summary":          candidate.CveSummary,
			"details":          candidate.CveDetails,
			"severity_score":   candidate.CveSeverityScore,
			"severity_rating":  candidate.CveSeverityRating,
			"published":        candidate.CvePublished,
			"modified":         candidate.CveModified,
			"aliases":          candidate.CveAliases,
			"package":          candidate.Package,
			"affected_version": candidate.Version,
			"full_purl":        candidate.FullPurl,
			"fixed_in":         fixedVersions,
			"release_name":     candidate.ReleaseName,
			"release_version":         candidate.ReleaseVersion,
			"content_sha":             candidate.ContentSha,
			"project_type":            candidate.ProjectType,
			"openssf_scorecard_score": candidate.OpenssfScorecardScore,
		})
	}

	return affectedReleases, nil
}

func resolveAffectedEndpoints(severity string) ([]map[string]interface{}, error) {
	ctx := context.Background()

	severityScore := util.GetSeverityScore(severity)

	log.Printf("Querying endpoints affected by %s severity", severity)

	var query string
	
	// Use separate AQL statements based on severity
	if severityScore == 0.0 {
		// Query without severity filter for NONE
		query = `
			FOR release IN release
				
				FOR sbom IN 1..1 OUTBOUND release release2sbom
					
					FOR sbomEdge IN sbom2purl
						FILTER sbomEdge._from == sbom._id
						
						LET purl = DOCUMENT(sbomEdge._to)
						FILTER purl != null
						
						LET packageVersion = sbomEdge.version
						LET packageFullPurl = sbomEdge.full_purl
						
						// Left outer join with CVEs - include packages even without CVEs
						LET cveMatches = (
							FOR cveEdge IN cve2purl
								FILTER cveEdge._to == purl._id
								
								LET cve = DOCUMENT(cveEdge._from)
								FILTER cve != null
								FILTER cve.affected != null
								
								FOR affected IN cve.affected
									
									LET cveBasePurl = affected.package.purl != null ? 
										affected.package.purl : 
										CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
									
									FILTER cveBasePurl == purl.purl
									
									RETURN {
										cve_id: cve.id,
										cve_summary: cve.summary,
										cve_details: cve.details,
										cve_severity_score: cve.database_specific.cvss_base_score,
										cve_severity_rating: cve.database_specific.severity_rating,
										cve_published: cve.published,
										cve_modified: cve.modified,
										cve_aliases: cve.aliases,
										affected_data: affected
									}
						)
						
						// Return one result per CVE match, or one result with null CVE data if no matches
						FOR cveMatch IN LENGTH(cveMatches) > 0 ? cveMatches : [null]
							
							FOR sync IN sync
								FILTER sync.release_name == release.name 
								   AND sync.release_version == release.version
								
								FOR endpoint IN endpoint
									FILTER endpoint.name == sync.endpoint_name
									
									LET result = {
										cve_id: cveMatch != null ? cveMatch.cve_id : null,
										cve_summary: cveMatch != null ? cveMatch.cve_summary : null,
										cve_details: cveMatch != null ? cveMatch.cve_details : null,
										cve_severity_score: cveMatch != null ? cveMatch.cve_severity_score : null,
										cve_severity_rating: cveMatch != null ? cveMatch.cve_severity_rating : null,
										cve_published: cveMatch != null ? cveMatch.cve_published : null,
										cve_modified: cveMatch != null ? cveMatch.cve_modified : null,
										cve_aliases: cveMatch != null ? cveMatch.cve_aliases : null,
										affected_data: cveMatch != null ? cveMatch.affected_data : null,
										package: purl.purl,
										version: packageVersion,
										full_purl: packageFullPurl,
										release_name: release.name,
										release_version: release.version,
										content_sha: release.contentsha,
										project_type: release.projecttype,
										openssf_scorecard_score: release.openssf_scorecard_score,
										endpoint_name: endpoint.name,
										endpoint_type: endpoint.endpoint_type,
										environment: endpoint.environment,
										synced_at: sync.synced_at,
										openssf_scorecard_score: release.openssf_scorecard_score
									}
									SORT result.cve_severity_score DESC
									RETURN result
		`
	} else {
		// Query with severity filter for LOW, MEDIUM, HIGH, CRITICAL
		query = `
			FOR release IN release
				
				FOR sbom IN 1..1 OUTBOUND release release2sbom
					
					FOR sbomEdge IN sbom2purl
						FILTER sbomEdge._from == sbom._id
						
						LET purl = DOCUMENT(sbomEdge._to)
						FILTER purl != null
						
						LET packageVersion = sbomEdge.version
						LET packageFullPurl = sbomEdge.full_purl
						
						FOR cveEdge IN cve2purl
							FILTER cveEdge._to == purl._id
							
							LET cve = DOCUMENT(cveEdge._from)
							FILTER cve != null
							FILTER cve.database_specific.cvss_base_score >= @severityScore
						
						FILTER cve.affected != null
						FOR affected IN cve.affected
							
							LET cveBasePurl = affected.package.purl != null ? 
								affected.package.purl : 
								CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
							
							FILTER cveBasePurl == purl.purl
							
							FOR sync IN sync
								FILTER sync.release_name == release.name 
								   AND sync.release_version == release.version
								
								FOR endpoint IN endpoint
									FILTER endpoint.name == sync.endpoint_name
									
									LET result = {
										cve_id: cve.id,
										cve_summary: cve.summary,
										cve_details: cve.details,
										cve_severity_score: cve.database_specific.cvss_base_score,
										cve_severity_rating: cve.database_specific.severity_rating,
										cve_published: cve.published,
										cve_modified: cve.modified,
										cve_aliases: cve.aliases,
										affected_data: affected,
										package: purl.purl,
										version: packageVersion,
										full_purl: packageFullPurl,
										release_name: release.name,
										release_version: release.version,
										content_sha: release.contentsha,
										project_type: release.projecttype,
										endpoint_name: endpoint.name,
										endpoint_type: endpoint.endpoint_type,
										environment: endpoint.environment,
										synced_at: sync.synced_at
									}
										SORT result.cve_severity_score DESC
										RETURN result
	`
	}

	var cursor arangodb.Cursor
	var err error
	
	if severityScore == 0.0 {
		// No bind variables needed for NONE severity
		cursor, err = db.Database.Query(ctx, query, nil)
	} else {
		// Bind severity score for other severities
		cursor, err = db.Database.Query(ctx, query, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"severityScore": severityScore,
			},
		})
	}
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	type Candidate struct {
		CveID             *string          `json:"cve_id"`
		CveSummary        *string          `json:"cve_summary"`
		CveDetails        *string          `json:"cve_details"`
		CveSeverityScore  *float64         `json:"cve_severity_score"`
		CveSeverityRating *string          `json:"cve_severity_rating"`
		CvePublished      *string          `json:"cve_published"`
		CveModified       *string          `json:"cve_modified"`
		CveAliases        []string         `json:"cve_aliases"`
		AffectedData      *models.Affected `json:"affected_data"`
		Package           string           `json:"package"`
		Version           string           `json:"version"`
		FullPurl          string           `json:"full_purl"`
		ReleaseName       string           `json:"release_name"`
		ReleaseVersion    string           `json:"release_version"`
		ContentSha        string           `json:"content_sha"`
		ProjectType            string           `json:"project_type"`
		EndpointName           string           `json:"endpoint_name"`
		EndpointType           string           `json:"endpoint_type"`
		Environment            string           `json:"environment"`
		SyncedAt               time.Time        `json:"synced_at"`
		OpenssfScorecardScore  *float64         `json:"openssf_scorecard_score"`
	}

	var affectedEndpoints []map[string]interface{}
	seen := make(map[string]bool)

	for cursor.HasMore() {
		var candidate Candidate
		_, err := cursor.ReadDocument(ctx, &candidate)
		if err != nil {
			continue
		}

		// Skip version check if there's no CVE data (releases without vulnerabilities)
		if candidate.AffectedData != nil && !util.IsVersionAffected(candidate.Version, *candidate.AffectedData) {
			continue
		}

		// Build key - use empty string for CveID if no CVE
		cveID := ""
		if candidate.CveID != nil {
			cveID = *candidate.CveID
		}
		key := candidate.EndpointName + ":" + candidate.ReleaseName + ":" + candidate.ReleaseVersion + ":" + candidate.Package + ":" + candidate.Version + ":" + cveID
		if seen[key] {
			continue
		}
		seen[key] = true

		var fixedVersions []string
		if candidate.AffectedData != nil {
			fixedVersions = extractFixedVersions(*candidate.AffectedData)
		}

		affectedEndpoints = append(affectedEndpoints, map[string]interface{}{
			"cve_id":           candidate.CveID,
			"summary":          candidate.CveSummary,
			"details":          candidate.CveDetails,
			"severity_score":   candidate.CveSeverityScore,
			"severity_rating":  candidate.CveSeverityRating,
			"published":        candidate.CvePublished,
			"modified":         candidate.CveModified,
			"aliases":          candidate.CveAliases,
			"package":          candidate.Package,
			"affected_version": candidate.Version,
			"full_purl":        candidate.FullPurl,
			"fixed_in":         fixedVersions,
			"release_name":     candidate.ReleaseName,
			"release_version":  candidate.ReleaseVersion,
			"content_sha":      candidate.ContentSha,
			"project_type":     candidate.ProjectType,
			"endpoint_name":           candidate.EndpointName,
			"endpoint_type":           candidate.EndpointType,
			"environment":             candidate.Environment,
			"synced_at":               candidate.SyncedAt.Format(time.RFC3339),
			"openssf_scorecard_score": candidate.OpenssfScorecardScore,
		})
	}

	return affectedEndpoints, nil
}

// CreateSchema creates the GraphQL schema
func CreateSchema() (graphql.Schema, error) {
	rootQuery := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			// Get a single release with SBOM and vulnerabilities
			"release": &graphql.Field{
				Type: ReleaseType,
				Args: graphql.FieldConfigArgument{
					"name": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
					"version": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(graphql.String),
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					name := p.Args["name"].(string)
					version := p.Args["version"].(string)

					ctx := context.Background()

					query := `
						FOR r IN release
							FILTER r.name == @name && r.version == @version
							LIMIT 1
							RETURN r
					`

					cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
						BindVars: map[string]interface{}{
							"name":    name,
							"version": version,
						},
					})
					if err != nil {
						return nil, err
					}
					defer cursor.Close()

					var release model.ProjectRelease
					if !cursor.HasMore() {
						return nil, nil
					}

					_, err = cursor.ReadDocument(ctx, &release)
					if err != nil {
						return nil, err
					}

					return release, nil
				},
			},

			// Get affected releases by severity
			"affectedReleases": &graphql.Field{
				Type: graphql.NewList(AffectedReleaseType),
				Args: graphql.FieldConfigArgument{
					"severity": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(SeverityType),
					},
					"limit": &graphql.ArgumentConfig{
						Type:         graphql.Int,
						DefaultValue: 100,
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					severity := p.Args["severity"].(string)
					// Normalize to lowercase to handle mixed/upper case from clients
					return resolveAffectedReleases(strings.ToLower(severity))
				},
			},

			// Get affected endpoints by severity
			"affectedEndpoints": &graphql.Field{
				Type: graphql.NewList(AffectedEndpointType),
				Args: graphql.FieldConfigArgument{
					"severity": &graphql.ArgumentConfig{
						Type: graphql.NewNonNull(SeverityType),
					},
					"environment": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"endpoint_type": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"limit": &graphql.ArgumentConfig{
						Type:         graphql.Int,
						DefaultValue: 100,
					},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					severity := p.Args["severity"].(string)
					// Normalize to lowercase to handle mixed/upper case from clients
					// TODO: Add filtering by environment and endpoint_type
					return resolveAffectedEndpoints(strings.ToLower(severity))
				},
			},
		},
	})

	return graphql.NewSchema(graphql.SchemaConfig{
		Query: rootQuery,
	})
}
