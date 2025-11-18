// package graphql - UPDATED VERSION

package graphql

import (
	"context"
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

func InitDB(dbConn database.DBConnection) {
	db = dbConn
}

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

var VulnerabilityCountType = graphql.NewObject(graphql.ObjectConfig{
	Name: "VulnerabilityCount",
	Fields: graphql.Fields{
		"critical": &graphql.Field{Type: graphql.Int},
		"high":     &graphql.Field{Type: graphql.Int},
		"medium":   &graphql.Field{Type: graphql.Int},
		"low":      &graphql.Field{Type: graphql.Int},
	},
})

var VulnerabilityType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Vulnerability",
	Fields: graphql.Fields{
		"cve_id":           &graphql.Field{Type: graphql.String},
		"summary":          &graphql.Field{Type: graphql.String},
		"details":          &graphql.Field{Type: graphql.String},
		"severity_score":   &graphql.Field{Type: graphql.Float},
		"severity_rating":  &graphql.Field{Type: graphql.String},
		"cvss_v3_score":    &graphql.Field{Type: graphql.String},
		"published":        &graphql.Field{Type: graphql.String},
		"modified":         &graphql.Field{Type: graphql.String},
		"aliases":          &graphql.Field{Type: graphql.NewList(graphql.String)},
		"package":          &graphql.Field{Type: graphql.String},
		"affected_version": &graphql.Field{Type: graphql.String},
		"full_purl":        &graphql.Field{Type: graphql.String},
		"fixed_in":         &graphql.Field{Type: graphql.NewList(graphql.String)},
	},
})

var SBOMType = graphql.NewObject(graphql.ObjectConfig{
	Name: "SBOM",
	Fields: graphql.Fields{
		"key":        &graphql.Field{Type: graphql.String},
		"contentsha": &graphql.Field{Type: graphql.String},
		"objtype":    &graphql.Field{Type: graphql.String},
		"content": &graphql.Field{
			Type: graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				if sbom, ok := p.Source.(model.SBOM); ok {
					return string(sbom.Content), nil
				}
				return nil, nil
			},
		},
	},
})

// --- Start of OpenSSF Scorecard Types ---

var ScorecardDocumentationType = graphql.NewObject(graphql.ObjectConfig{
	Name: "ScorecardDocumentation",
	Fields: graphql.Fields{
		"Short": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			doc, _ := p.Source.(model.Documentation)
			return doc.Short, nil
		}},
		"URL": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			doc, _ := p.Source.(model.Documentation)
			return doc.URL, nil
		}},
	},
})

var ScorecardCheckType = graphql.NewObject(graphql.ObjectConfig{
	Name: "ScorecardCheck",
	Fields: graphql.Fields{
		"Name": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			check, _ := p.Source.(model.Check)
			return check.Name, nil
		}},
		"Score": &graphql.Field{Type: graphql.Int, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			check, _ := p.Source.(model.Check)
			return check.Score, nil
		}},
		"Reason": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			check, _ := p.Source.(model.Check)
			return check.Reason, nil
		}},
		"Details": &graphql.Field{Type: graphql.NewList(graphql.String), Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			check, _ := p.Source.(model.Check)
			return check.Details, nil
		}},
		"Documentation": &graphql.Field{Type: ScorecardDocumentationType, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			check, _ := p.Source.(model.Check)
			return check.Documentation, nil
		}},
	},
})

var ScorecardRepoType = graphql.NewObject(graphql.ObjectConfig{
	Name: "ScorecardRepo",
	Fields: graphql.Fields{
		"Name": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			repo, _ := p.Source.(model.Repo)
			return repo.Name, nil
		}},
		"Commit": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			repo, _ := p.Source.(model.Repo)
			return repo.Commit, nil
		}},
	},
})

var ScorecardScoresType = graphql.NewObject(graphql.ObjectConfig{
	Name: "ScorecardScores",
	Fields: graphql.Fields{
		"Version": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			scores, _ := p.Source.(model.Scores)
			return scores.Version, nil
		}},
		"Commit": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			scores, _ := p.Source.(model.Scores)
			return scores.Commit, nil
		}},
	},
})

var ScorecardResultType = graphql.NewObject(graphql.ObjectConfig{
	Name: "ScorecardResult",
	Fields: graphql.Fields{
		"Date": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			res, _ := p.Source.(*model.ScorecardAPIResponse)
			return res.Date, nil
		}},
		"Repo": &graphql.Field{Type: ScorecardRepoType, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			res, _ := p.Source.(*model.ScorecardAPIResponse)
			return res.Repo, nil
		}},
		"Scorecard": &graphql.Field{Type: ScorecardScoresType, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			res, _ := p.Source.(*model.ScorecardAPIResponse)
			return res.Scorecard, nil
		}},
		"Score": &graphql.Field{Type: graphql.Float, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			res, _ := p.Source.(*model.ScorecardAPIResponse)
			return res.Score, nil
		}},
		"Checks": &graphql.Field{Type: graphql.NewList(ScorecardCheckType), Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			res, _ := p.Source.(*model.ScorecardAPIResponse)
			return res.Checks, nil
		}},
		"Metadata": &graphql.Field{Type: graphql.NewList(graphql.String), Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			res, _ := p.Source.(*model.ScorecardAPIResponse)
			return res.Metadata, nil
		}},
	},
})

// --- End of OpenSSF Scorecard Types ---

var ReleaseType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Release",
	Fields: graphql.Fields{
		"key":          &graphql.Field{Type: graphql.String},
		"name":         &graphql.Field{Type: graphql.String},
		"version":      &graphql.Field{Type: graphql.String},
		"project_type": &graphql.Field{Type: graphql.String},
		"content_sha":  &graphql.Field{Type: graphql.String},
		"git_commit":   &graphql.Field{Type: graphql.String},
		"git_branch":   &graphql.Field{Type: graphql.String},
		"docker_repo":  &graphql.Field{Type: graphql.String},
		"docker_tag":   &graphql.Field{Type: graphql.String},
		"docker_sha":   &graphql.Field{Type: graphql.String},
		"sbom": &graphql.Field{
			Type: SBOMType,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				release, ok := p.Source.(model.ProjectRelease)
				if !ok {
					return nil, nil
				}
				ctx := context.Background()
				query := `
					FOR r IN release
						FILTER r.name == @name && r.version == @version
						FOR v IN 1..1 OUTBOUND r release2sbom
							RETURN v
				`
				cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
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
		// --- OpenSSF Scorecard Fields Added ---
		"openssf_scorecard_score": &graphql.Field{
			Type: graphql.Float,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				release, _ := p.Source.(model.ProjectRelease)
				return release.OpenSSFScorecardScore, nil
			},
		},
		"scorecard_result": &graphql.Field{
			Type: ScorecardResultType,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				release, _ := p.Source.(model.ProjectRelease)
				// Returning the pointer to the struct as defined in model.ProjectRelease
				return release.ScorecardResult, nil
			},
		},
		// --- End OpenSSF Scorecard Fields Added ---
	},
})

var ReleaseInfoType = graphql.NewObject(graphql.ObjectConfig{
	Name: "ReleaseInfo",
	Fields: graphql.Fields{
		"release_name":    &graphql.Field{Type: graphql.String},
		"release_version": &graphql.Field{Type: graphql.String},
	},
})

var SyncedEndpointType = graphql.NewObject(graphql.ObjectConfig{
	Name: "SyncedEndpoint",
	Fields: graphql.Fields{
		"endpoint_name": &graphql.Field{Type: graphql.String},
		"endpoint_url":  &graphql.Field{Type: graphql.String},
		"endpoint_type": &graphql.Field{Type: graphql.String},
		"environment":   &graphql.Field{Type: graphql.String},
		"status":        &graphql.Field{Type: graphql.String},
		"last_sync":     &graphql.Field{Type: graphql.String},
		"release_count": &graphql.Field{Type: graphql.Int},
		"total_vulnerabilities": &graphql.Field{
			Type: VulnerabilityCountType,
		},
		"releases": &graphql.Field{
			Type: graphql.NewList(ReleaseInfoType),
		},
	},
})

var AffectedEndpointType = graphql.NewObject(graphql.ObjectConfig{
	Name: "AffectedEndpoint",
	Fields: graphql.Fields{
		"endpoint_name": &graphql.Field{Type: graphql.String},
		"endpoint_url":  &graphql.Field{Type: graphql.String},
		"endpoint_type": &graphql.Field{Type: graphql.String},
		"environment":   &graphql.Field{Type: graphql.String},
		"last_sync":     &graphql.Field{Type: graphql.String},
		"status":        &graphql.Field{Type: graphql.String},
	},
})

var AffectedReleaseType = graphql.NewObject(graphql.ObjectConfig{
	Name: "AffectedRelease",
	Fields: graphql.Fields{
		"cve_id":                  &graphql.Field{Type: graphql.String},
		"summary":                 &graphql.Field{Type: graphql.String},
		"details":                 &graphql.Field{Type: graphql.String},
		"severity_score":          &graphql.Field{Type: graphql.Float},
		"severity_rating":         &graphql.Field{Type: graphql.String},
		"published":               &graphql.Field{Type: graphql.String},
		"modified":                &graphql.Field{Type: graphql.String},
		"aliases":                 &graphql.Field{Type: graphql.NewList(graphql.String)},
		"package":                 &graphql.Field{Type: graphql.String},
		"affected_version":        &graphql.Field{Type: graphql.String},
		"full_purl":               &graphql.Field{Type: graphql.String},
		"fixed_in":                &graphql.Field{Type: graphql.NewList(graphql.String)},
		"release_name":            &graphql.Field{Type: graphql.String},
		"release_version":         &graphql.Field{Type: graphql.String},
		"content_sha":             &graphql.Field{Type: graphql.String},
		"project_type":            &graphql.Field{Type: graphql.String},
		"openssf_scorecard_score": &graphql.Field{Type: graphql.Float},
		"dependency_count":        &graphql.Field{Type: graphql.Int},
		"synced_endpoint_count":   &graphql.Field{Type: graphql.Int},
	},
})

var MitigationType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Mitigation",
	Fields: graphql.Fields{
		"cve_id":             &graphql.Field{Type: graphql.String},
		"summary":            &graphql.Field{Type: graphql.String},
		"severity_score":     &graphql.Field{Type: graphql.Float},
		"severity_rating":    &graphql.Field{Type: graphql.String},
		"package":            &graphql.Field{Type: graphql.String},
		"affected_version":   &graphql.Field{Type: graphql.String},
		"full_purl":          &graphql.Field{Type: graphql.String},
		"fixed_in":           &graphql.Field{Type: graphql.NewList(graphql.String)},
		"affected_releases":  &graphql.Field{Type: graphql.Int},
		"affected_endpoints": &graphql.Field{Type: graphql.Int},
	},
})

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

func resolveReleaseVulnerabilities(name, version string) ([]map[string]interface{}, error) {
	ctx := context.Background()
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
			"fixed_in":         extractFixedVersions(result.AffectedData),
		})
	}
	return vulnerabilities, nil
}

func resolveAffectedReleases(severity string) ([]map[string]interface{}, error) {
	ctx := context.Background()
	severityScore := util.GetSeverityScore(severity)

	var query string
	if severityScore == 0.0 {
		query = `
			LET results = (
				FOR release IN release
					FOR sbom IN 1..1 OUTBOUND release release2sbom
						FOR sbomEdge IN sbom2purl
							FILTER sbomEdge._from == sbom._id
							LET purl = DOCUMENT(sbomEdge._to)
							FILTER purl != null
							LET packageVersion = sbomEdge.version
							LET packageFullPurl = sbomEdge.full_purl
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
							FOR cveMatch IN LENGTH(cveMatches) > 0 ? cveMatches : [null]
								LET syncCount = LENGTH(
									FOR sync IN sync
										FILTER sync.release_name == release.name 
										   AND sync.release_version == release.version
										RETURN 1
								)
								LET depCount = (
									FOR s IN 1..1 OUTBOUND release release2sbom
										RETURN s.content.components != null ? LENGTH(s.content.components) : 0
								)[0]
								RETURN {
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
									synced_endpoint_count: syncCount,
									dependency_count: depCount
								}
			)
			FOR result IN results
				SORT result.cve_severity_score DESC
				RETURN result
		`
	} else {
		query = `
			LET results = (
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
								LET syncCount = LENGTH(
									FOR sync IN sync
										FILTER sync.release_name == release.name 
										   AND sync.release_version == release.version
										RETURN 1
								)
								LET depCount = (
									FOR s IN 1..1 OUTBOUND release release2sbom
										RETURN s.content.components != null ? LENGTH(s.content.components) : 0
								)[0]
								RETURN {
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
									openssf_scorecard_score: release.openssf_scorecard_score,
									synced_endpoint_count: syncCount,
									dependency_count: depCount
								}
			)
			FOR result IN results
				SORT result.cve_severity_score DESC
				RETURN result
		`
	}

	var cursor arangodb.Cursor
	var err error
	if severityScore == 0.0 {
		cursor, err = db.Database.Query(ctx, query, nil)
	} else {
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
		CveID                 *string          `json:"cve_id"`
		CveSummary            *string          `json:"cve_summary"`
		CveDetails            *string          `json:"cve_details"`
		CveSeverityScore      *float64         `json:"cve_severity_score"`
		CveSeverityRating     *string          `json:"cve_severity_rating"`
		CvePublished          *string          `json:"cve_published"`
		CveModified           *string          `json:"cve_modified"`
		CveAliases            []string         `json:"cve_aliases"`
		AffectedData          *models.Affected `json:"affected_data"`
		Package               string           `json:"package"`
		Version               string           `json:"version"`
		FullPurl              string           `json:"full_purl"`
		ReleaseName           string           `json:"release_name"`
		ReleaseVersion        string           `json:"release_version"`
		ContentSha            string           `json:"content_sha"`
		ProjectType           string           `json:"project_type"`
		OpenssfScorecardScore *float64         `json:"openssf_scorecard_score"`
		SyncedEndpointCount   int              `json:"synced_endpoint_count"`
		DependencyCount       int              `json:"dependency_count"`
	}

	var affectedReleases []map[string]interface{}
	seen := make(map[string]bool)

	for cursor.HasMore() {
		var candidate Candidate
		_, err := cursor.ReadDocument(ctx, &candidate)
		if err != nil {
			continue
		}
		if candidate.AffectedData != nil && !util.IsVersionAffected(candidate.Version, *candidate.AffectedData) {
			continue
		}
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
			"cve_id":                  candidate.CveID,
			"summary":                 candidate.CveSummary,
			"details":                 candidate.CveDetails,
			"severity_score":          candidate.CveSeverityScore,
			"severity_rating":         candidate.CveSeverityRating,
			"published":               candidate.CvePublished,
			"modified":                candidate.CveModified,
			"aliases":                 candidate.CveAliases,
			"package":                 candidate.Package,
			"affected_version":        candidate.Version,
			"full_purl":               candidate.FullPurl,
			"fixed_in":                fixedVersions,
			"release_name":            candidate.ReleaseName,
			"release_version":         candidate.ReleaseVersion,
			"content_sha":             candidate.ContentSha,
			"project_type":            candidate.ProjectType,
			"openssf_scorecard_score": candidate.OpenssfScorecardScore,
			"synced_endpoint_count":   candidate.SyncedEndpointCount,
			"dependency_count":        candidate.DependencyCount,
		})
	}
	return affectedReleases, nil
}

func resolveSyncedEndpoints(limit int) ([]map[string]interface{}, error) {
	ctx := context.Background()

	// OPTIMIZED: Simplified query with better filtering
	query := `
		FOR endpoint IN endpoint
			LET syncs = (
				FOR sync IN sync
					FILTER sync.endpoint_name == endpoint.name
					RETURN {
						release_name: sync.release_name,
						release_version: sync.release_version,
						synced_at: sync.synced_at
					}
			)
			FILTER LENGTH(syncs) > 0
			
			LET latestSync = MAX(syncs[*].synced_at)
			
			LET vulnCounts = (
				FOR sync IN syncs
					FOR release IN release
						FILTER release.name == sync.release_name AND release.version == sync.release_version
						LIMIT 1
						
						FOR sbomEdge IN 1..1 OUTBOUND release release2sbom
							FOR purlEdge IN sbom2purl
								FILTER purlEdge._from == sbomEdge._id
								LET purl = DOCUMENT(purlEdge._to)
								FILTER purl != null
								
								FOR cveEdge IN cve2purl
									FILTER cveEdge._to == purl._id
									LET cve = DOCUMENT(cveEdge._from)
									FILTER cve != null
									FILTER cve.database_specific != null
									FILTER cve.database_specific.severity_rating != null
									
									FOR affected IN cve.affected != null ? cve.affected : []
										LET cveBasePurl = affected.package.purl != null ? 
											affected.package.purl : 
											CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
										FILTER cveBasePurl == purl.purl
										
										RETURN {
											severity_rating: cve.database_specific.severity_rating,
											package_version: purlEdge.version,
											affected_data: affected
										}
			)
			
			LIMIT @limit
			
			RETURN {
				endpoint_name: endpoint.name,
				endpoint_url: endpoint.name,
				endpoint_type: endpoint.endpoint_type,
				environment: endpoint.environment,
				status: "active",
				last_sync: latestSync != null ? latestSync : DATE_ISO8601(DATE_NOW()),
				release_count: LENGTH(syncs),
				total_vulnerabilities: {
					critical: LENGTH(FOR v IN vulnCounts FILTER LOWER(v.severity_rating) == "critical" RETURN 1),
					high: LENGTH(FOR v IN vulnCounts FILTER LOWER(v.severity_rating) == "high" RETURN 1),
					medium: LENGTH(FOR v IN vulnCounts FILTER LOWER(v.severity_rating) == "medium" RETURN 1),
					low: LENGTH(FOR v IN vulnCounts FILTER LOWER(v.severity_rating) == "low" RETURN 1)
				},
				releases: syncs
			}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"limit": limit,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	type SyncedEndpointResult struct {
		EndpointName         string `json:"endpoint_name"`
		EndpointURL          string `json:"endpoint_url"`
		EndpointType         string `json:"endpoint_type"`
		Environment          string `json:"environment"`
		Status               string `json:"status"`
		LastSync             string `json:"last_sync"`
		ReleaseCount         int    `json:"release_count"`
		TotalVulnerabilities struct {
			Critical int `json:"critical"`
			High     int `json:"high"`
			Medium   int `json:"medium"`
			Low      int `json:"low"`
		} `json:"total_vulnerabilities"`
		Releases []struct {
			ReleaseName    string `json:"release_name"`
			ReleaseVersion string `json:"release_version"`
		} `json:"releases"`
	}

	var endpoints []map[string]interface{}
	for cursor.HasMore() {
		var result SyncedEndpointResult
		_, err := cursor.ReadDocument(ctx, &result)
		if err != nil {
			continue
		}

		releases := make([]map[string]interface{}, len(result.Releases))
		for i, rel := range result.Releases {
			releases[i] = map[string]interface{}{
				"release_name":    rel.ReleaseName,
				"release_version": rel.ReleaseVersion,
			}
		}

		endpoints = append(endpoints, map[string]interface{}{
			"endpoint_name": result.EndpointName,
			"endpoint_url":  result.EndpointURL,
			"endpoint_type": result.EndpointType,
			"environment":   result.Environment,
			"status":        result.Status,
			"last_sync":     result.LastSync,
			"release_count": result.ReleaseCount,
			"total_vulnerabilities": map[string]interface{}{
				"critical": result.TotalVulnerabilities.Critical,
				"high":     result.TotalVulnerabilities.High,
				"medium":   result.TotalVulnerabilities.Medium,
				"low":      result.TotalVulnerabilities.Low,
			},
			"releases": releases,
		})
	}
	return endpoints, nil
}

func resolveAffectedEndpoints(name, version string) ([]map[string]interface{}, error) {
	ctx := context.Background()

	// OPTIMIZED: Direct indexed lookup
	query := `
		FOR sync IN sync
			FILTER sync.release_name == @name AND sync.release_version == @version
			FOR endpoint IN endpoint
				FILTER endpoint.name == sync.endpoint_name
				LIMIT 1
				RETURN {
					endpoint_name: endpoint.name,
					endpoint_url: endpoint.name,
					endpoint_type: endpoint.endpoint_type,
					environment: endpoint.environment,
					last_sync: sync.synced_at,
					status: "active"
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

	type EndpointResult struct {
		EndpointName string    `json:"endpoint_name"`
		EndpointURL  string    `json:"endpoint_url"`
		EndpointType string    `json:"endpoint_type"`
		Environment  string    `json:"environment"`
		LastSync     time.Time `json:"last_sync"`
		Status       string    `json:"status"`
	}

	var endpoints []map[string]interface{}
	for cursor.HasMore() {
		var result EndpointResult
		_, err := cursor.ReadDocument(ctx, &result)
		if err != nil {
			continue
		}

		endpoints = append(endpoints, map[string]interface{}{
			"endpoint_name": result.EndpointName,
			"endpoint_url":  result.EndpointURL,
			"endpoint_type": result.EndpointType,
			"environment":   result.Environment,
			"last_sync":     result.LastSync.Format(time.RFC3339),
			"status":        result.Status,
		})
	}
	return endpoints, nil
}

func resolveVulnerabilities(limit int) ([]map[string]interface{}, error) {
	ctx := context.Background()

	// OPTIMIZED: Start from releases (small dataset), use indexed edge lookups
	// Key fix: COLLECT/SORT/LIMIT must be OUTSIDE the loops
	query := `
		LET vulnData = (
			FOR release IN release
				FOR sbomEdge IN 1..1 OUTBOUND release release2sbom
					FOR purlEdge IN sbom2purl
						FILTER purlEdge._from == sbomEdge._id
						LET purl = DOCUMENT(purlEdge._to)
						FILTER purl != null
						
						FOR cveEdge IN cve2purl
							FILTER cveEdge._to == purl._id
							LET cve = DOCUMENT(cveEdge._from)
							FILTER cve != null
							FILTER cve.database_specific != null
							FILTER cve.database_specific.cvss_base_score != null
							
							LET affectedMatch = FIRST(
								FOR affected IN cve.affected != null ? cve.affected : []
									FILTER affected.package != null
									LET cveBasePurl = affected.package.purl != null ? 
										affected.package.purl : 
										CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
									FILTER cveBasePurl == purl.purl
									LIMIT 1
									RETURN affected
							)
							
							FILTER affectedMatch != null
							
							LET fixedVersions = (
								FOR vrange IN affectedMatch.ranges != null ? affectedMatch.ranges : []
									FOR event IN vrange.events != null ? vrange.events : []
										FILTER event.fixed != null AND event.fixed != ""
										RETURN DISTINCT event.fixed
							)
							
							RETURN {
								cve_id: cve.id,
								package: purl.purl,
								affected_version: purlEdge.version,
								full_purl: purlEdge.full_purl,
								summary: cve.summary,
								severity_score: cve.database_specific.cvss_base_score,
								severity_rating: cve.database_specific.severity_rating,
								fixed_in: fixedVersions,
								release_name: release.name,
								release_version: release.version,
								affected_data: affectedMatch
							}
		)
		
		FOR vuln IN vulnData
			COLLECT 
				cve_id = vuln.cve_id,
				package = vuln.package,
				affected_version = vuln.affected_version
			AGGREGATE 
				summaries = UNIQUE(vuln.summary),
				severity_scores = UNIQUE(vuln.severity_score),
				severity_ratings = UNIQUE(vuln.severity_rating),
				releaseList = UNIQUE(CONCAT(vuln.release_name, ":", vuln.release_version)),
				full_purls = UNIQUE(vuln.full_purl),
				all_fixed_in = UNIQUE(vuln.fixed_in),
				all_affected_data = UNIQUE(vuln.affected_data)
			
			LET endpointCount = LENGTH(
				FOR rel_str IN releaseList
					LET parts = SPLIT(rel_str, ":")
					FOR sync IN sync
						FILTER sync.release_name == parts[0] AND sync.release_version == parts[1]
						LIMIT 1
						RETURN 1
			)
			
			// Use the highest severity score for sorting when there are variations
			LET max_severity_score = MAX(severity_scores)
			
			SORT max_severity_score DESC
			LIMIT @limit
			
			RETURN {
				cve_id: cve_id,
				summary: FIRST(summaries) != null ? FIRST(summaries) : "",
				severity_score: max_severity_score,
				severity_rating: FIRST(severity_ratings) != null ? FIRST(severity_ratings) : "UNKNOWN",
				package: package,
				affected_version: affected_version,
				full_purl: FIRST(full_purls),
				fixed_in: FIRST(all_fixed_in),
				affected_releases: LENGTH(releaseList),
				affected_endpoints: endpointCount,
				affected_data: FIRST(all_affected_data)
			}
	`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"limit": limit,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	type VulnerabilityResult struct {
		CveID             string          `json:"cve_id"`
		Summary           string          `json:"summary"`
		SeverityScore     float64         `json:"severity_score"`
		SeverityRating    string          `json:"severity_rating"`
		Package           string          `json:"package"`
		AffectedVersion   string          `json:"affected_version"`
		FullPurl          string          `json:"full_purl"`
		FixedIn           []string        `json:"fixed_in"`
		AffectedReleases  int             `json:"affected_releases"`
		AffectedEndpoints int             `json:"affected_endpoints"`
		AffectedData      models.Affected `json:"affected_data"` // Need this for version checking
	}

	var vulnerabilities []map[string]interface{}
	seen := make(map[string]bool) // Deduplication

	for cursor.HasMore() {
		var result VulnerabilityResult
		_, err := cursor.ReadDocument(ctx, &result)
		if err != nil {
			continue
		}

		// CRITICAL: Check if version is actually affected
		// The query only matches PURLs, but we need to verify version ranges
		if !util.IsVersionAffected(result.AffectedVersion, result.AffectedData) {
			continue
		}

		// Deduplication check
		key := result.CveID + ":" + result.Package + ":" + result.AffectedVersion
		if seen[key] {
			continue
		}
		seen[key] = true

		vulnerabilities = append(vulnerabilities, map[string]interface{}{
			"cve_id":             result.CveID,
			"summary":            result.Summary,
			"severity_score":     result.SeverityScore,
			"severity_rating":    result.SeverityRating,
			"package":            result.Package,
			"affected_version":   result.AffectedVersion,
			"full_purl":          result.FullPurl,
			"fixed_in":           result.FixedIn,
			"affected_releases":  result.AffectedReleases,
			"affected_endpoints": result.AffectedEndpoints,
		})
	}

	return vulnerabilities, nil
}

func CreateSchema() (graphql.Schema, error) {
	rootQuery := graphql.NewObject(graphql.ObjectConfig{
		Name: "Query",
		Fields: graphql.Fields{
			"release": &graphql.Field{
				Type: ReleaseType,
				Args: graphql.FieldConfigArgument{
					"name":    &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"version": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
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
			"affectedReleases": &graphql.Field{
				Type: graphql.NewList(AffectedReleaseType),
				Args: graphql.FieldConfigArgument{
					"severity": &graphql.ArgumentConfig{Type: graphql.NewNonNull(SeverityType)},
					"limit":    &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 100},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					severity := p.Args["severity"].(string)
					return resolveAffectedReleases(strings.ToLower(severity))
				},
			},
			"syncedEndpoints": &graphql.Field{
				Type: graphql.NewList(SyncedEndpointType),
				Args: graphql.FieldConfigArgument{
					"limit": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 1000},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					limit := p.Args["limit"].(int)
					return resolveSyncedEndpoints(limit)
				},
			},
			"affectedEndpoints": &graphql.Field{
				Type: graphql.NewList(AffectedEndpointType),
				Args: graphql.FieldConfigArgument{
					"name":    &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
					"version": &graphql.ArgumentConfig{Type: graphql.NewNonNull(graphql.String)},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					name := p.Args["name"].(string)
					version := p.Args["version"].(string)
					return resolveAffectedEndpoints(name, version)
				},
			},
			"vulnerabilities": &graphql.Field{
				Type: graphql.NewList(MitigationType),
				Args: graphql.FieldConfigArgument{
					"limit": &graphql.ArgumentConfig{Type: graphql.Int, DefaultValue: 1000},
				},
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					limit := p.Args["limit"].(int)
					return resolveVulnerabilities(limit)
				},
			},
		},
	})

	return graphql.NewSchema(graphql.SchemaConfig{
		Query: rootQuery,
	})
}
