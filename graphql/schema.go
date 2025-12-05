// Package graphql provides the GraphQL schema definition and resolvers
package graphql

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/graphql-go/graphql"
	"github.com/ortelius/pdvd-backend/v12/database"
	"github.com/ortelius/pdvd-backend/v12/model"
	"github.com/ortelius/pdvd-backend/v12/util"
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

var ReleaseType = graphql.NewObject(graphql.ObjectConfig{
	Name: "Release",
	Fields: graphql.Fields{
		"key":          &graphql.Field{Type: graphql.String},
		"name":         &graphql.Field{Type: graphql.String},
		"version":      &graphql.Field{Type: graphql.String},
		"project_type": &graphql.Field{Type: graphql.String},

		"content_sha": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.ContentSha, nil
		}},
		"docker_repo": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.DockerRepo, nil
		}},
		"docker_tag": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.DockerTag, nil
		}},
		"docker_sha": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.DockerSha, nil
		}},
		"basename": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.Basename, nil
		}},

		"git_commit": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitCommit, nil
		}},
		"git_branch": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitBranch, nil
		}},
		"git_tag": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitTag, nil
		}},
		"git_repo": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitRepo, nil
		}},
		"git_org": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitOrg, nil
		}},
		"git_url": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitURL, nil
		}},
		"git_repo_project": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitRepoProject, nil
		}},
		"git_verify_commit": &graphql.Field{Type: graphql.Boolean, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitVerifyCommit, nil
		}},
		"git_signed_off_by": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitSignedOffBy, nil
		}},

		"git_commit_timestamp": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitCommitTimestamp, nil
		}},
		"git_commit_authors": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitCommitAuthors, nil
		}},
		"git_committerscnt": &graphql.Field{Type: graphql.Int, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitCommittersCnt, nil
		}},
		"git_total_committerscnt": &graphql.Field{Type: graphql.Int, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitTotalCommittersCnt, nil
		}},
		"git_contrib_percentage": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitContribPercentage, nil
		}},
		"git_lines_added": &graphql.Field{Type: graphql.Int, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitLinesAdded, nil
		}},
		"git_lines_deleted": &graphql.Field{Type: graphql.Int, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitLinesDeleted, nil
		}},
		"git_lines_total": &graphql.Field{Type: graphql.Int, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitLinesTotal, nil
		}},
		"git_prev_comp_commit": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.GitPrevCompCommit, nil
		}},

		"build_date": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.BuildDate, nil
		}},
		"build_id": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.BuildID, nil
		}},
		"build_num": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.BuildNum, nil
		}},
		"build_url": &graphql.Field{Type: graphql.String, Resolve: func(p graphql.ResolveParams) (interface{}, error) {
			release, _ := p.Source.(model.ProjectRelease)
			return release.BuildURL, nil
		}},

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
					// FIX: Return empty array instead of nil
					return []map[string]interface{}{}, nil
				}
				vulnerabilities, err := resolveReleaseVulnerabilities(release.Name, release.Version)
				if err != nil {
					// FIX: Return empty array on error instead of nil
					return []map[string]interface{}{}, nil
				}
				// FIX: Ensure we always return an array, even if empty
				if vulnerabilities == nil {
					return []map[string]interface{}{}, nil
				}
				return vulnerabilities, nil
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
					FOR release IN release
						FILTER release.name == @name AND release.version == @version
						FOR sbom IN 1..1 OUTBOUND release release2sbom
							LIMIT 1
							LET dependencyCount = (
								FOR edge IN sbom2purl
									FILTER edge._from == sbom._id
									COLLECT fullPurl = edge.full_purl
									RETURN 1
							)
							RETURN LENGTH(dependencyCount)
				`

				cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
					BindVars: map[string]interface{}{
						"name":    release.Name,
						"version": release.Version,
					},
				})
				if err != nil {
					return 0, err
				}
				defer cursor.Close()

				if cursor.HasMore() {
					var count int
					_, err := cursor.ReadDocument(ctx, &count)
					if err != nil {
						return 0, err
					}
					return count, nil
				}

				return 0, nil
			},
		},

		"synced_endpoint_count": &graphql.Field{
			Type: graphql.Int,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				release, ok := p.Source.(model.ProjectRelease)
				if !ok {
					return 0, nil
				}

				endpoints, err := resolveAffectedEndpoints(release.Name, release.Version)
				if err != nil {
					return 0, err
				}

				return len(endpoints), nil
			},
		},
		"synced_endpoints": &graphql.Field{
			Type: graphql.NewList(AffectedEndpointType),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				release, ok := p.Source.(model.ProjectRelease)
				if !ok {
					return []map[string]interface{}{}, nil
				}
				endpoints, err := resolveAffectedEndpoints(release.Name, release.Version)
				if err != nil {
					return []map[string]interface{}{}, nil
				}
				if endpoints == nil {
					return []map[string]interface{}{}, nil
				}
				return endpoints, nil
			},
		},

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
				return release.ScorecardResult, nil
			},
		},
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
		"cve_id":                     &graphql.Field{Type: graphql.String},
		"summary":                    &graphql.Field{Type: graphql.String},
		"details":                    &graphql.Field{Type: graphql.String},
		"severity_score":             &graphql.Field{Type: graphql.Float},
		"severity_rating":            &graphql.Field{Type: graphql.String},
		"published":                  &graphql.Field{Type: graphql.String},
		"modified":                   &graphql.Field{Type: graphql.String},
		"aliases":                    &graphql.Field{Type: graphql.NewList(graphql.String)},
		"package":                    &graphql.Field{Type: graphql.String},
		"affected_version":           &graphql.Field{Type: graphql.String},
		"full_purl":                  &graphql.Field{Type: graphql.String},
		"fixed_in":                   &graphql.Field{Type: graphql.NewList(graphql.String)},
		"release_name":               &graphql.Field{Type: graphql.String},
		"release_version":            &graphql.Field{Type: graphql.String},
		"version_count":              &graphql.Field{Type: graphql.Int},
		"content_sha":                &graphql.Field{Type: graphql.String},
		"project_type":               &graphql.Field{Type: graphql.String},
		"openssf_scorecard_score":    &graphql.Field{Type: graphql.Float},
		"dependency_count":           &graphql.Field{Type: graphql.Int},
		"synced_endpoint_count":      &graphql.Field{Type: graphql.Int},
		"vulnerability_count":        &graphql.Field{Type: graphql.Int},
		"vulnerability_count_delta":  &graphql.Field{Type: graphql.Int},
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

func getStringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func getFloatValue(f *float64) float64 {
	if f == nil {
		return 0.0
	}
	return *f
}

func isVersionAffectedAny(version string, allAffected []models.Affected) bool {
	for _, affected := range allAffected {
		if util.IsVersionAffected(version, affected) {
			return true
		}
	}
	return false
}

func resolveReleaseVulnerabilities(name, version string) ([]map[string]interface{}, error) {
	ctx := context.Background()

	// URL decode the name to handle slashes that may be encoded as %2F
	// Example: "deployhub%2Fms-ui" becomes "deployhub/ms-ui"
	decodedName, err := url.QueryUnescape(name)
	if err != nil {
		// If decoding fails, use the original name
		decodedName = name
	}

	query := `
		FOR release IN release
			FILTER release.name == @name AND release.version == @version
			FOR sbom IN 1..1 OUTBOUND release release2sbom
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbom._id
					LET purl = DOCUMENT(sbomEdge._to)
					FILTER purl != null
					
					FOR cveEdge IN cve2purl
						FILTER cveEdge._to == purl._id
						
						FILTER (
							sbomEdge.version_major != null AND 
							cveEdge.introduced_major != null AND 
							(cveEdge.fixed_major != null OR cveEdge.last_affected_major != null)
						) ? (
							(sbomEdge.version_major > cveEdge.introduced_major OR
							 (sbomEdge.version_major == cveEdge.introduced_major AND 
							  sbomEdge.version_minor > cveEdge.introduced_minor) OR
							 (sbomEdge.version_major == cveEdge.introduced_major AND 
							  sbomEdge.version_minor == cveEdge.introduced_minor AND 
							  sbomEdge.version_patch >= cveEdge.introduced_patch))
							AND
							(cveEdge.fixed_major != null ? (
								sbomEdge.version_major < cveEdge.fixed_major OR
								(sbomEdge.version_major == cveEdge.fixed_major AND 
								 sbomEdge.version_minor < cveEdge.fixed_minor) OR
								(sbomEdge.version_major == cveEdge.fixed_major AND 
								 sbomEdge.version_minor == cveEdge.fixed_minor AND 
								 sbomEdge.version_patch < cveEdge.fixed_patch)
							) : (
								sbomEdge.version_major < cveEdge.last_affected_major OR
								(sbomEdge.version_major == cveEdge.last_affected_major AND 
								 sbomEdge.version_minor < cveEdge.last_affected_minor) OR
								(sbomEdge.version_major == cveEdge.last_affected_major AND 
								 sbomEdge.version_minor == cveEdge.last_affected_minor AND 
								 sbomEdge.version_patch <= cveEdge.last_affected_patch)
							))
						) : true
						
						LET cve = DOCUMENT(cveEdge._from)
						FILTER cve != null
						
						LET matchedAffected = (
							FOR affected IN cve.affected != null ? cve.affected : []
								LET cveBasePurl = affected.package.purl != null ? 
									affected.package.purl : 
									CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
								FILTER cveBasePurl == purl.purl
								RETURN affected
						)
						FILTER LENGTH(matchedAffected) > 0
						
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
							package_version: sbomEdge.version,
							full_purl: sbomEdge.full_purl,
							all_affected: matchedAffected,
							needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
						}
	`
	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name":    decodedName,
			"version": version,
		},
	})
	if err != nil {
		// FIX: Return empty array instead of nil on error
		return []map[string]interface{}{}, err
	}
	defer cursor.Close()

	type CVEResult struct {
		CveID           string            `json:"cve_id"`
		Summary         string            `json:"summary"`
		Details         string            `json:"details"`
		Severity        []models.Severity `json:"severity"`
		SeverityScore   float64           `json:"severity_score"`
		SeverityRating  string            `json:"severity_rating"`
		Published       string            `json:"published"`
		Modified        string            `json:"modified"`
		Aliases         []string          `json:"aliases"`
		Package         string            `json:"package"`
		PackageVersion  string            `json:"package_version"`
		FullPurl        string            `json:"full_purl"`
		AllAffected     []models.Affected `json:"all_affected"`
		NeedsValidation bool              `json:"needs_validation"`
	}

	var vulnerabilities []map[string]interface{}
	seen := make(map[string]bool)

	for cursor.HasMore() {
		var result CVEResult
		_, err := cursor.ReadDocument(ctx, &result)
		if err != nil {
			continue
		}

		if result.NeedsValidation {
			// FIX: Allow UNKNOWN or empty versions to proceed (fail open)
			// Only filter out if we have a valid version string that turns out to be safe.
			if result.PackageVersion == "" {
				result.PackageVersion = "UNKNOWN"
			}

			if result.PackageVersion != "UNKNOWN" {
				if !isVersionAffectedAny(result.PackageVersion, result.AllAffected) {
					continue
				}
			}
		}

		// FIX: Use FullPurl in the unique key to distinguish between the same package
		// appearing in different directories (e.g. one 7.0.2 and one UNKNOWN).
		key := result.CveID + ":" + result.FullPurl
		if result.FullPurl == "" {
			key = result.CveID + ":" + result.Package + ":" + result.PackageVersion
		}

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
			"fixed_in":         util.ExtractApplicableFixedVersion(result.PackageVersion, result.AllAffected),
		})
	}

	// FIX: Always return a non-nil slice
	if vulnerabilities == nil {
		return []map[string]interface{}{}, nil
	}
	return vulnerabilities, nil
}

func resolveAffectedReleases(severity string) ([]interface{}, error) {
	ctx := context.Background()
	severityScore := util.GetSeverityScore(severity)

	query := `
		FOR r IN release
			// 1. Group by name immediately to find the latest version first
			COLLECT name = r.name INTO groupedReleases = r

			// 2. Sort and pick ONLY the latest release per project
			LET latestRelease = (
				FOR release IN groupedReleases
					SORT release.version_major != null ? release.version_major : -1 DESC,
						release.version_minor != null ? release.version_minor : -1 DESC,
						release.version_patch != null ? release.version_patch : -1 DESC,
						release.version_prerelease != null && release.version_prerelease != "" ? 1 : 0 ASC,
						release.version_prerelease ASC,
						release.version DESC
					LIMIT 1
					RETURN release
			)[0]
			
			LET versionCount = LENGTH(groupedReleases)

			// 3. Perform expensive lookups ONLY on the single latest release
			LET sbomData = (
				FOR s IN 1..1 OUTBOUND latestRelease release2sbom
					LIMIT 1
					RETURN { 
						id: s._id
					}
			)[0]

			// 4. Count unique dependencies by full_purl (package + version combination)
			LET dependencyCount = (
				FILTER sbomData != null
				FOR edge IN sbom2purl
					FILTER edge._from == sbomData.id
					COLLECT fullPurl = edge.full_purl
					RETURN 1
			)

			LET syncCount = (
				FOR sync IN sync
					FILTER sync.release_name == latestRelease.name 
					AND sync.release_version == latestRelease.version
					COLLECT WITH COUNT INTO count
					RETURN count
			)[0]

			LET cveMatches = (
				// Optimization: We already found the SBOM ID above, no need to traverse again
				FILTER sbomData != null
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbomData.id
					LET purl = DOCUMENT(sbomEdge._to)
					FILTER purl != null
					
					FOR cveEdge IN cve2purl
						FILTER cveEdge._to == purl._id
						
						// Keep existing complex SemVer logic
						FILTER (
							sbomEdge.version_major != null AND 
							cveEdge.introduced_major != null AND 
							(cveEdge.fixed_major != null OR cveEdge.last_affected_major != null)
						) ? (
							(sbomEdge.version_major > cveEdge.introduced_major OR
							(sbomEdge.version_major == cveEdge.introduced_major AND 
							sbomEdge.version_minor > cveEdge.introduced_minor) OR
							(sbomEdge.version_major == cveEdge.introduced_major AND 
							sbomEdge.version_minor == cveEdge.introduced_minor AND 
							sbomEdge.version_patch >= cveEdge.introduced_patch))
							AND
							(cveEdge.fixed_major != null ? (
								sbomEdge.version_major < cveEdge.fixed_major OR
								(sbomEdge.version_major == cveEdge.fixed_major AND 
								sbomEdge.version_minor < cveEdge.fixed_minor) OR
								(sbomEdge.version_major == cveEdge.fixed_major AND 
								sbomEdge.version_minor == cveEdge.fixed_minor AND 
								sbomEdge.version_patch < cveEdge.fixed_patch)
							) : (
								sbomEdge.version_major < cveEdge.last_affected_major OR
								(sbomEdge.version_major == cveEdge.last_affected_major AND 
								sbomEdge.version_minor < cveEdge.last_affected_minor) OR
								(sbomEdge.version_major == cveEdge.last_affected_major AND 
								sbomEdge.version_minor == cveEdge.last_affected_minor AND 
								sbomEdge.version_patch <= cveEdge.last_affected_patch)
							))
						) : true
						
						LET cve = DOCUMENT(cveEdge._from)
						FILTER cve != null
						FILTER @severityScore == 0.0 OR cve.database_specific.cvss_base_score >= @severityScore
						
						LET matchedAffected = (
							FOR affected IN cve.affected != null ? cve.affected : []
								LET cveBasePurl = affected.package.purl != null ? 
									affected.package.purl : 
									CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
								FILTER cveBasePurl == purl.purl
								RETURN affected
						)
						FILTER LENGTH(matchedAffected) > 0
						
						RETURN {
							cve_id: cve.id,
							cve_summary: cve.summary,
							cve_details: cve.details,
							cve_severity_score: cve.database_specific.cvss_base_score,
							cve_severity_rating: cve.database_specific.severity_rating,
							cve_published: cve.published,
							cve_modified: cve.modified,
							cve_aliases: cve.aliases,
							all_affected: matchedAffected,
							package: purl.purl,
							version: sbomEdge.version,
							full_purl: sbomEdge.full_purl,
							needs_validation: sbomEdge.version_major == null OR cveEdge.introduced_major == null
						}
			)

			FILTER @severityScore == 0.0 OR LENGTH(cveMatches) > 0
			
			LET maxSeverity = LENGTH(cveMatches) > 0 ? MAX(cveMatches[*].cve_severity_score) : 0
			
			// Calculate vulnerability count for this release (unique CVEs)
			LET uniqueCves = (
				FOR match IN cveMatches
					COLLECT cveId = match.cve_id
					RETURN 1
			)
			LET vulnerabilityCount = LENGTH(uniqueCves)
			
			// Get previous version to calculate delta
			LET previousRelease = (
				FOR release IN groupedReleases
					FILTER release._key != latestRelease._key
					SORT release.version_major != null ? release.version_major : -1 DESC,
						release.version_minor != null ? release.version_minor : -1 DESC,
						release.version_patch != null ? release.version_patch : -1 DESC,
						release.version_prerelease != null && release.version_prerelease != "" ? 1 : 0 ASC,
						release.version_prerelease ASC,
						release.version DESC
					LIMIT 1
					RETURN release
			)[0]
			
			// Calculate vulnerability count for previous version
			LET prevVulnCount = previousRelease != null ? (
				LET prevSbomData = (
					FOR s IN 1..1 OUTBOUND previousRelease release2sbom
						LIMIT 1
						RETURN { id: s._id }
				)[0]
				
				FILTER prevSbomData != null
				
				LET prevCveMatches = (
					FOR sbomEdge IN sbom2purl
						FILTER sbomEdge._from == prevSbomData.id
						LET purl = DOCUMENT(sbomEdge._to)
						FILTER purl != null
						
						FOR cveEdge IN cve2purl
							FILTER cveEdge._to == purl._id
							
							FILTER (
								sbomEdge.version_major != null AND 
								cveEdge.introduced_major != null AND 
								(cveEdge.fixed_major != null OR cveEdge.last_affected_major != null)
							) ? (
								(sbomEdge.version_major > cveEdge.introduced_major OR
								(sbomEdge.version_major == cveEdge.introduced_major AND 
								sbomEdge.version_minor > cveEdge.introduced_minor) OR
								(sbomEdge.version_major == cveEdge.introduced_major AND 
								sbomEdge.version_minor == cveEdge.introduced_minor AND 
								sbomEdge.version_patch >= cveEdge.introduced_patch))
								AND
								(cveEdge.fixed_major != null ? (
									sbomEdge.version_major < cveEdge.fixed_major OR
									(sbomEdge.version_major == cveEdge.fixed_major AND 
									sbomEdge.version_minor < cveEdge.fixed_minor) OR
									(sbomEdge.version_major == cveEdge.fixed_major AND 
									sbomEdge.version_minor == cveEdge.fixed_minor AND 
									sbomEdge.version_patch < cveEdge.fixed_patch)
								) : (
									sbomEdge.version_major < cveEdge.last_affected_major OR
									(sbomEdge.version_major == cveEdge.last_affected_major AND 
									sbomEdge.version_minor < cveEdge.last_affected_minor) OR
									(sbomEdge.version_major == cveEdge.last_affected_major AND 
									sbomEdge.version_minor == cveEdge.last_affected_minor AND 
									sbomEdge.version_patch <= cveEdge.last_affected_patch)
								))
							) : true
							
							LET cve = DOCUMENT(cveEdge._from)
							FILTER cve != null
							FILTER @severityScore == 0.0 OR cve.database_specific.cvss_base_score >= @severityScore
							
							LET matchedAffected = (
								FOR affected IN cve.affected != null ? cve.affected : []
									LET cveBasePurl = affected.package.purl != null ? 
										affected.package.purl : 
										CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
									FILTER cveBasePurl == purl.purl
									RETURN affected
							)
							FILTER LENGTH(matchedAffected) > 0
							
							RETURN { cve_id: cve.id }
				)
				
				LET prevUniqueCves = (
					FOR match IN prevCveMatches
						COLLECT cveId = match.cve_id
						RETURN 1
				)
				
				RETURN LENGTH(prevUniqueCves)
			)[0] : null
			
			LET vulnerabilityCountDelta = prevVulnCount != null ? (vulnerabilityCount - prevVulnCount) : null

			RETURN {
				release_name: latestRelease.name,
				latest_version: latestRelease.version,
				version_major: latestRelease.version_major,
				version_minor: latestRelease.version_minor,
				version_patch: latestRelease.version_patch,
				version_prerelease: latestRelease.version_prerelease,
				version_count: versionCount,
				content_sha: latestRelease.contentsha,
				project_type: latestRelease.projecttype,
				openssf_scorecard_score: latestRelease.openssf_scorecard_score,
				synced_endpoint_count: syncCount,
				dependency_count: LENGTH(dependencyCount),
				max_severity: maxSeverity,
				vulnerability_count: vulnerabilityCount,
				vulnerability_count_delta: vulnerabilityCountDelta,
				cve_matches: cveMatches
			}
			`

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"severityScore": severityScore,
		},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	type AggregatedRelease struct {
		ReleaseName              string   `json:"release_name"`
		LatestVersion            string   `json:"latest_version"`
		VersionMajor             *int     `json:"version_major"`
		VersionMinor             *int     `json:"version_minor"`
		VersionPatch             *int     `json:"version_patch"`
		VersionPrerelease        string   `json:"version_prerelease"`
		VersionCount             int      `json:"version_count"`
		ContentSha               string   `json:"content_sha"`
		ProjectType              string   `json:"project_type"`
		OpenSSFScorecardScore    *float64 `json:"openssf_scorecard_score"`
		SyncedEndpointCount      int      `json:"synced_endpoint_count"`
		DependencyCount          int      `json:"dependency_count"`
		MaxSeverity              *float64 `json:"max_severity"`
		VulnerabilityCount       int      `json:"vulnerability_count"`
		VulnerabilityCountDelta  *int     `json:"vulnerability_count_delta"`
		CveMatches               []struct {
			CveID             *string           `json:"cve_id"`
			CveSummary        *string           `json:"cve_summary"`
			CveDetails        *string           `json:"cve_details"`
			CveSeverityScore  *float64          `json:"cve_severity_score"`
			CveSeverityRating *string           `json:"cve_severity_rating"`
			CvePublished      *string           `json:"cve_published"`
			CveModified       *string           `json:"cve_modified"`
			CveAliases        []string          `json:"cve_aliases"`
			AllAffected       []models.Affected `json:"all_affected"`
			Package           string            `json:"package"`
			Version           string            `json:"version"`
			FullPurl          string            `json:"full_purl"`
			NeedsValidation   bool              `json:"needs_validation"`
		} `json:"cve_matches"`
	}

	var results []interface{}

	for cursor.HasMore() {
		var aggRelease AggregatedRelease
		_, err := cursor.ReadDocument(ctx, &aggRelease)
		if err != nil {
			continue
		}

		releaseKey := aggRelease.ReleaseName + ":" + aggRelease.LatestVersion
		seen := make(map[string]bool)

		for _, cveMatch := range aggRelease.CveMatches {
			if cveMatch.NeedsValidation && len(cveMatch.AllAffected) > 0 {
				if !isVersionAffectedAny(cveMatch.Version, cveMatch.AllAffected) {
					continue
				}
			}

			var cveID string
			if cveMatch.CveID != nil {
				cveID = *cveMatch.CveID
			}
			cveKey := releaseKey + ":" + cveID + ":" + cveMatch.Package + ":" + cveMatch.Version

			if !seen[cveKey] {
				seen[cveKey] = true

				result := map[string]interface{}{
					"cve_id":                     cveID,
					"summary":                    getStringValue(cveMatch.CveSummary),
					"details":                    getStringValue(cveMatch.CveDetails),
					"severity_score":             getFloatValue(cveMatch.CveSeverityScore),
					"severity_rating":            getStringValue(cveMatch.CveSeverityRating),
					"published":                  getStringValue(cveMatch.CvePublished),
					"modified":                   getStringValue(cveMatch.CveModified),
					"aliases":                    cveMatch.CveAliases,
					"package":                    cveMatch.Package,
					"affected_version":           cveMatch.Version,
					"full_purl":                  cveMatch.FullPurl,
					"release_name":               aggRelease.ReleaseName,
					"release_version":            aggRelease.LatestVersion,
					"version_count":              aggRelease.VersionCount,
					"content_sha":                aggRelease.ContentSha,
					"project_type":               aggRelease.ProjectType,
					"openssf_scorecard_score":    aggRelease.OpenSSFScorecardScore,
					"dependency_count":           aggRelease.DependencyCount,
					"synced_endpoint_count":      aggRelease.SyncedEndpointCount,
					"vulnerability_count":        aggRelease.VulnerabilityCount,
					"vulnerability_count_delta":  aggRelease.VulnerabilityCountDelta,
				}

				if len(cveMatch.AllAffected) > 0 {
					result["fixed_in"] = util.ExtractApplicableFixedVersion(cveMatch.Version, cveMatch.AllAffected)
				}

				results = append(results, result)
			}
		}

		if len(aggRelease.CveMatches) == 0 && severityScore == 0.0 {
			releaseOnlyKey := releaseKey + ":NO_CVES"
			if !seen[releaseOnlyKey] {
				seen[releaseOnlyKey] = true

				results = append(results, map[string]interface{}{
					"cve_id":                     nil,
					"summary":                    nil,
					"details":                    nil,
					"severity_score":             nil,
					"severity_rating":            nil,
					"published":                  nil,
					"modified":                   nil,
					"aliases":                    []string{},
					"package":                    nil,
					"affected_version":           nil,
					"full_purl":                  nil,
					"fixed_in":                   []string{},
					"release_name":               aggRelease.ReleaseName,
					"release_version":            aggRelease.LatestVersion,
					"version_count":              aggRelease.VersionCount,
					"content_sha":                aggRelease.ContentSha,
					"project_type":               aggRelease.ProjectType,
					"openssf_scorecard_score":    aggRelease.OpenSSFScorecardScore,
					"dependency_count":           aggRelease.DependencyCount,
					"synced_endpoint_count":      aggRelease.SyncedEndpointCount,
					"vulnerability_count":        aggRelease.VulnerabilityCount,
					"vulnerability_count_delta":  aggRelease.VulnerabilityCountDelta,
				})
			}
		}
	}

	return results, nil
}

func resolveSyncedEndpoints(limit int) ([]map[string]interface{}, error) {
	ctx := context.Background()

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
		return []map[string]interface{}{}, nil
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

	// FIX: Always return non-nil slice
	if endpoints == nil {
		return []map[string]interface{}{}, nil
	}
	return endpoints, nil
}

func resolveVulnerabilities(limit int) ([]map[string]interface{}, error) {
	ctx := context.Background()

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
							
							FILTER (
								purlEdge.version_major != null AND 
								cveEdge.introduced_major != null AND 
								(cveEdge.fixed_major != null OR cveEdge.last_affected_major != null)
							) ? (
								(purlEdge.version_major > cveEdge.introduced_major OR
								 (purlEdge.version_major == cveEdge.introduced_major AND 
								  purlEdge.version_minor > cveEdge.introduced_minor) OR
								 (purlEdge.version_major == cveEdge.introduced_major AND 
								  purlEdge.version_minor == cveEdge.introduced_minor AND 
								  purlEdge.version_patch >= cveEdge.introduced_patch))
								AND
								(cveEdge.fixed_major != null ? (
									purlEdge.version_major < cveEdge.fixed_major OR
									(purlEdge.version_major == cveEdge.fixed_major AND 
									 purlEdge.version_minor < cveEdge.fixed_minor) OR
									(purlEdge.version_major == cveEdge.fixed_major AND 
									 purlEdge.version_minor == cveEdge.fixed_minor AND 
									 purlEdge.version_patch < cveEdge.fixed_patch)
								) : (
									purlEdge.version_major < cveEdge.last_affected_major OR
									(purlEdge.version_major == cveEdge.last_affected_major AND 
									 purlEdge.version_minor < cveEdge.last_affected_minor) OR
									(purlEdge.version_major == cveEdge.last_affected_major AND 
									 purlEdge.version_minor == cveEdge.last_affected_minor AND 
									 purlEdge.version_patch <= cveEdge.last_affected_patch)
								))
							) : true
							
							LET cve = DOCUMENT(cveEdge._from)
							FILTER cve != null
							FILTER cve.database_specific.cvss_base_score != null
							
							LET matchedAffected = (
								FOR affected IN cve.affected != null ? cve.affected : []
									FILTER affected.package != null
									LET cveBasePurl = affected.package.purl != null ? 
										affected.package.purl : 
										CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
									FILTER cveBasePurl == purl.purl
									RETURN affected
							)
							
							FILTER LENGTH(matchedAffected) > 0
							
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
								all_affected: matchedAffected,
								needs_validation: purlEdge.version_major == null OR cveEdge.introduced_major == null
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
				all_affected_data = UNIQUE(vuln.affected_data),
				needs_validation_flags = UNIQUE(vuln.needs_validation)
			
			LET endpointCount = LENGTH(
				FOR rel_str IN releaseList
					LET parts = SPLIT(rel_str, ":")
					FOR sync IN sync
						FILTER sync.release_name == parts[0] AND sync.release_version == parts[1]
						LIMIT 1
						RETURN 1
			)
			
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
				affected_data: FIRST(all_affected_data),
				needs_validation: FIRST(needs_validation_flags)
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
		CveID             string            `json:"cve_id"`
		Summary           string            `json:"summary"`
		SeverityScore     float64           `json:"severity_score"`
		SeverityRating    string            `json:"severity_rating"`
		Package           string            `json:"package"`
		AffectedVersion   string            `json:"affected_version"`
		FullPurl          string            `json:"full_purl"`
		FixedIn           []string          `json:"fixed_in"`
		AffectedReleases  int               `json:"affected_releases"`
		AffectedEndpoints int               `json:"affected_endpoints"`
		AllAffected       []models.Affected `json:"all_affected"`
		NeedsValidation   bool              `json:"needs_validation"`
	}

	var vulnerabilities []map[string]interface{}
	seen := make(map[string]bool)

	for cursor.HasMore() {
		var result VulnerabilityResult
		_, err := cursor.ReadDocument(ctx, &result)
		if err != nil {
			continue
		}

		if result.NeedsValidation {
			if !isVersionAffectedAny(result.AffectedVersion, result.AllAffected) {
				continue
			}
		}

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
			"fixed_in":           util.ExtractApplicableFixedVersion(result.AffectedVersion, result.AllAffected),
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

					// URL decode the name to handle slashes that may be encoded as %2F
					// Example: "deployhub%2Fms-ui" becomes "deployhub/ms-ui"
					decodedName, err := url.QueryUnescape(name)
					if err != nil {
						// If decoding fails, use the original name
						decodedName = name
					}

					ctx := context.Background()
					query := `
						FOR r IN release
							FILTER r.name == @name && r.version == @version
							LIMIT 1
							RETURN r
					`
					cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
						BindVars: map[string]interface{}{
							"name":    decodedName,
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
