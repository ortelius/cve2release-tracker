package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"os"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	fiberrecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/google/osv-scanner/pkg/models"
	"github.com/ortelius/cve2release-tracker/database"
	"github.com/ortelius/cve2release-tracker/model"
	"github.com/ortelius/cve2release-tracker/util"
)

var db database.DBConnection

// ReleaseWithSBOMResponse returns the result of POST operations
type ReleaseWithSBOMResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// ReleaseListItem represents a simplified release for list view
type ReleaseListItem struct {
	Key     string `json:"_key"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// edgeInfo holds edge information for batch processing
type edgeInfo struct {
	from     string
	to       string
	version  string
	fullPurl string
}

// getSBOMContentHash calculates SHA256 hash of SBOM content
func getSBOMContentHash(sbom model.SBOM) string {
	hash := sha256.Sum256(sbom.Content)
	return hex.EncodeToString(hash[:])
}

// populateContentSha sets the ContentSha field based on project type
func populateContentSha(release *model.ProjectRelease) {
	// Use DockerSha for docker/container projects, otherwise use GitCommit
	if release.ProjectType == "docker" || release.ProjectType == "container" {
		if release.DockerSha != "" {
			release.ContentSha = release.DockerSha
		} else if release.GitCommit != "" {
			// Fallback to GitCommit if DockerSha not available
			release.ContentSha = release.GitCommit
		}
	} else {
		// For all other project types, use GitCommit
		if release.GitCommit != "" {
			release.ContentSha = release.GitCommit
		} else if release.DockerSha != "" {
			// Fallback to DockerSha if GitCommit not available
			release.ContentSha = release.DockerSha
		}
	}
}

// processSBOMComponents extracts PURLs from SBOM and creates hub-spoke relationships
// Now uses batch processing for better performance
func processSBOMComponents(ctx context.Context, sbom model.SBOM, sbomID string) error {
	// Parse SBOM content to extract components
	var sbomData struct {
		Components []struct {
			Purl string `json:"purl"`
		} `json:"components"`
	}

	if err := json.Unmarshal(sbom.Content, &sbomData); err != nil {
		return err
	}

	// Step 1: Collect and process all PURLs
	type purlInfo struct {
		basePurl string
		version  string
		fullPurl string
	}

	var purlInfos []purlInfo
	basePurlSet := make(map[string]bool) // For deduplication

	for _, component := range sbomData.Components {
		if component.Purl == "" {
			continue
		}

		// Validate and clean PURL format
		cleanedPurl, err := util.CleanPURL(component.Purl)
		if err != nil {
			// Log but continue with other PURLs
			log.Printf("Failed to clean PURL %s: %v", component.Purl, err)
			continue
		}

		// Parse to extract version
		parsed, err := util.ParsePURL(cleanedPurl)
		if err != nil {
			log.Printf("Failed to parse PURL %s: %v", cleanedPurl, err)
			continue
		}

		// Get base PURL (without version) for hub matching
		basePurl, err := util.GetBasePURL(cleanedPurl)
		if err != nil {
			log.Printf("Failed to get base PURL from %s: %v", cleanedPurl, err)
			continue
		}

		purlInfos = append(purlInfos, purlInfo{
			basePurl: basePurl,
			version:  parsed.Version,
			fullPurl: cleanedPurl,
		})

		basePurlSet[basePurl] = true
	}

	if len(purlInfos) == 0 {
		return nil // No valid PURLs to process
	}

	// Step 2: Batch find/create all unique base PURLs
	uniqueBasePurls := make([]string, 0, len(basePurlSet))
	for basePurl := range basePurlSet {
		uniqueBasePurls = append(uniqueBasePurls, basePurl)
	}

	purlIDMap, err := batchFindOrCreatePURLs(ctx, uniqueBasePurls)
	if err != nil {
		return err
	}

	// Step 3: Prepare all edges for batch insertion

	var edgesToCreate []edgeInfo
	edgeCheckMap := make(map[string]bool) // For deduplication: "from:to:version"

	for _, info := range purlInfos {
		purlID, exists := purlIDMap[info.basePurl]
		if !exists {
			log.Printf("Warning: PURL ID not found for base PURL %s", info.basePurl)
			continue
		}

		// Create unique key for edge deduplication
		edgeKey := sbomID + ":" + purlID + ":" + info.version
		if edgeCheckMap[edgeKey] {
			continue // Skip duplicate
		}
		edgeCheckMap[edgeKey] = true

		edgesToCreate = append(edgesToCreate, edgeInfo{
			from:     sbomID,
			to:       purlID,
			version:  info.version,
			fullPurl: info.fullPurl,
		})
	}

	if len(edgesToCreate) == 0 {
		return nil // No edges to create
	}

	// Step 4: Batch check which edges already exist
	existingEdges, err := batchCheckEdgesExist(ctx, "sbom2purl", edgesToCreate)
	if err != nil {
		return err
	}

	// Step 5: Batch insert only non-existing edges
	var newEdges []map[string]interface{}
	for _, edge := range edgesToCreate {
		edgeKey := edge.from + ":" + edge.to + ":" + edge.version
		if !existingEdges[edgeKey] {
			newEdges = append(newEdges, map[string]interface{}{
				"_from":     edge.from,
				"_to":       edge.to,
				"version":   edge.version,
				"full_purl": edge.fullPurl,
			})
		}
	}

	if len(newEdges) > 0 {
		err = batchInsertEdges(ctx, "sbom2purl", newEdges)
		if err != nil {
			return err
		}
	}

	return nil
}

// batchFindOrCreatePURLs finds or creates multiple PURLs in a single query
// Returns a map of basePurl -> purlID
func batchFindOrCreatePURLs(ctx context.Context, basePurls []string) (map[string]string, error) {
	if len(basePurls) == 0 {
		return make(map[string]string), nil
	}

	// Single query to upsert all PURLs and return their IDs
	query := `
		FOR purl IN @purls
			LET upsertedPurl = FIRST(
				UPSERT { purl: purl }
				INSERT { purl: purl, objtype: "PURL" }
				UPDATE {} IN purl
				RETURN NEW
			)
			RETURN {
				basePurl: purl,
				purlId: CONCAT("purl/", upsertedPurl._key)
			}
	`

	bindVars := map[string]interface{}{
		"purls": basePurls,
	}

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	purlIDMap := make(map[string]string)
	for cursor.HasMore() {
		var result struct {
			BasePurl string `json:"basePurl"`
			PurlID   string `json:"purlId"`
		}
		_, err := cursor.ReadDocument(ctx, &result)
		if err != nil {
			return nil, err
		}
		purlIDMap[result.BasePurl] = result.PurlID
	}

	return purlIDMap, nil
}

// batchCheckEdgesExist checks which edges already exist in a single query
// Returns a map of "from:to:version" -> exists
func batchCheckEdgesExist(ctx context.Context, edgeCollection string, edges []edgeInfo) (map[string]bool, error) {
	if len(edges) == 0 {
		return make(map[string]bool), nil
	}

	// Prepare edge data for query
	type edgeCheck struct {
		From    string `json:"from"`
		To      string `json:"to"`
		Version string `json:"version"`
	}

	var edgeChecks []edgeCheck
	for _, edge := range edges {
		edgeChecks = append(edgeChecks, edgeCheck{
			From:    edge.from,
			To:      edge.to,
			Version: edge.version,
		})
	}

	// Single query to check all edges
	query := `
		FOR check IN @edges
			LET exists = (
				FOR e IN @@edgeCollection
					FILTER e._from == check.from 
					   AND e._to == check.to 
					   AND e.version == check.version
					LIMIT 1
					RETURN true
			)
			RETURN {
				key: CONCAT(check.from, ":", check.to, ":", check.version),
				exists: LENGTH(exists) > 0
			}
	`

	bindVars := map[string]interface{}{
		"@edgeCollection": edgeCollection,
		"edges":           edgeChecks,
	}

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	existsMap := make(map[string]bool)
	for cursor.HasMore() {
		var result struct {
			Key    string `json:"key"`
			Exists bool   `json:"exists"`
		}
		_, err := cursor.ReadDocument(ctx, &result)
		if err != nil {
			return nil, err
		}
		existsMap[result.Key] = result.Exists
	}

	return existsMap, nil
}

// batchInsertEdges inserts multiple edges in a single query
func batchInsertEdges(ctx context.Context, edgeCollection string, edges []map[string]interface{}) error {
	if len(edges) == 0 {
		return nil
	}

	query := `
		FOR edge IN @edges
			INSERT edge INTO @@edgeCollection
	`

	bindVars := map[string]interface{}{
		"@edgeCollection": edgeCollection,
		"edges":           edges,
	}

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	if err != nil {
		return err
	}
	cursor.Close()

	return nil
}

// checkRelease2SBOMEdgeExists checks if a release2sbom edge already exists
func checkRelease2SBOMEdgeExists(ctx context.Context, releaseID, sbomID string) (bool, error) {
	query := `
		FOR e IN release2sbom
			FILTER e._from == @from && e._to == @to
			LIMIT 1
			RETURN e
	`
	bindVars := map[string]interface{}{
		"from": releaseID,
		"to":   sbomID,
	}

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	if err != nil {
		return false, err
	}
	defer cursor.Close()

	return cursor.HasMore(), nil
}

// ============================================================================
// POST Handlers
// ============================================================================

// PostReleaseWithSBOM handles POST requests for creating a release with its SBOM
func PostReleaseWithSBOM(c *fiber.Ctx) error {
	var req model.ReleaseWithSBOM

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Invalid request body: " + err.Error(),
		})
	}

	// Validate required fields for Release
	if req.Name == "" || req.Version == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Release name and version are required fields",
		})
	}

	// Validate SBOM content
	if len(req.SBOM.Content) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "SBOM content is required",
		})
	}

	// Validate SBOM content is valid JSON
	var sbomContent interface{}
	if err := json.Unmarshal(req.SBOM.Content, &sbomContent); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "SBOM content must be valid JSON: " + err.Error(),
		})
	}

	// Set ObjType if not already set
	if req.ObjType == "" {
		req.ObjType = "ProjectRelease"
	}
	if req.SBOM.ObjType == "" {
		req.SBOM.ObjType = "SBOM"
	}

	ctx := context.Background()

	// ============================================================================
	// HYBRID APPROACH: Composite key for Release, Content hash for SBOM
	// ============================================================================

	// Populate ContentSha based on project type
	populateContentSha(&req.ProjectRelease)

	// Validate ContentSha is set
	if req.ContentSha == "" {
		return c.Status(fiber.StatusBadRequest).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "ContentSha is required (GitCommit or DockerSha must be provided)",
		})
	}

	// Check for existing release by composite natural key (name + version + contentsha)
	existingReleaseKey, err := database.FindReleaseByCompositeKey(ctx, db.Database,
		req.Name,
		req.Version,
		req.ContentSha,
	)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Failed to check for existing release: " + err.Error(),
		})
	}

	var releaseID string

	if existingReleaseKey != "" {
		// Release already exists, use existing key
		releaseID = "release/" + existingReleaseKey
		req.ProjectRelease.Key = existingReleaseKey
	} else {
		// Save new ProjectRelease to ArangoDB
		releaseMeta, err := db.Collections["release"].CreateDocument(ctx, req.ProjectRelease)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
				Success: false,
				Message: "Failed to save release: " + err.Error(),
			})
		}
		releaseID = "release/" + releaseMeta.Key
		req.ProjectRelease.Key = releaseMeta.Key
	}

	// Calculate content hash for SBOM (stored in ContentSha field)
	sbomHash := getSBOMContentHash(req.SBOM)
	req.SBOM.ContentSha = sbomHash

	// Check if SBOM with this content hash already exists
	existingSBOMKey, err := database.FindSBOMByContentHash(ctx, db.Database, sbomHash)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Failed to check for existing SBOM: " + err.Error(),
		})
	}

	var sbomID string

	if existingSBOMKey != "" {
		// SBOM already exists, use existing key
		sbomID = "sbom/" + existingSBOMKey
		req.SBOM.Key = existingSBOMKey
	} else {
		// Save new SBOM to ArangoDB
		sbomMeta, err := db.Collections["sbom"].CreateDocument(ctx, req.SBOM)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
				Success: false,
				Message: "Failed to save SBOM: " + err.Error(),
			})
		}
		sbomID = "sbom/" + sbomMeta.Key
		req.SBOM.Key = sbomMeta.Key
	}

	// Check if edge relationship already exists
	edgeExists, err := checkRelease2SBOMEdgeExists(ctx, releaseID, sbomID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Failed to check edge existence: " + err.Error(),
		})
	}

	if !edgeExists {
		// Create edge relationship between release and sbom
		edge := map[string]interface{}{
			"_from": releaseID,
			"_to":   sbomID,
		}
		_, err = db.Collections["release2sbom"].CreateDocument(ctx, edge)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
				Success: false,
				Message: "Failed to create release-sbom relationship: " + err.Error(),
			})
		}
	}

	// Process SBOM components and create PURL relationships
	err = processSBOMComponents(ctx, req.SBOM, sbomID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Failed to process SBOM components: " + err.Error(),
		})
	}

	// Return success response
	message := "Release and SBOM created successfully"
	if existingReleaseKey != "" && existingSBOMKey != "" {
		message = "Release and SBOM already exist (matched by name+version+contentsha and content hash)"
	} else if existingReleaseKey != "" {
		message = "Release already exists (matched by name+version+contentsha), SBOM created and linked"
	} else if existingSBOMKey != "" {
		message = "SBOM already exists (matched by content hash), Release created and linked"
	}

	return c.Status(fiber.StatusCreated).JSON(ReleaseWithSBOMResponse{
		Success: true,
		Message: message,
	})
}

// ============================================================================
// GET Handlers
// ============================================================================

// GetReleaseWithSBOM handles GET requests for fetching a release with its SBOM by name and version
func GetReleaseWithSBOM(c *fiber.Ctx) error {
	name := c.Params("name")
	version := c.Params("version")

	if name == "" || version == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "Release name and version are required",
		})
	}

	ctx := context.Background()

	// Query to find release by name and version
	query := `
		FOR r IN release
			FILTER r.name == @name && r.version == @version
			LIMIT 1
			RETURN r
	`
	bindVars := map[string]interface{}{
		"name":    name,
		"version": version,
	}

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Failed to query release: " + err.Error(),
		})
	}
	defer cursor.Close()

	var release model.ProjectRelease
	if !cursor.HasMore() {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"success": false,
			"message": "Release not found",
		})
	}

	_, err = cursor.ReadDocument(ctx, &release)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Failed to read release: " + err.Error(),
		})
	}

	// Query to find associated SBOM via the edge collection
	sbomQuery := `
		FOR r IN release
			FILTER r.name == @name && r.version == @version
			FOR v IN 1..1 OUTBOUND r release2sbom
				RETURN v
	`

	sbomCursor, err := db.Database.Query(ctx, sbomQuery, &arangodb.QueryOptions{
		BindVars: bindVars,
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Failed to query SBOM: " + err.Error(),
		})
	}
	defer sbomCursor.Close()

	var sbom model.SBOM
	if sbomCursor.HasMore() {
		_, err = sbomCursor.ReadDocument(ctx, &sbom)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"message": "Failed to read SBOM: " + err.Error(),
			})
		}
	} else {
		// No SBOM found, return empty SBOM
		sbom = *model.NewSBOM()
		sbom.Content = json.RawMessage(`{}`)
	}

	return c.Status(fiber.StatusOK).JSON(model.ReleaseWithSBOM{
		ProjectRelease: release,
		SBOM:           sbom,
	})
}

// ============================================================================
// CVE Analysis Handlers
// ============================================================================

// GetAffectedReleasesByCVE returns all releases affected by a specific CVE
// Uses Go-based version matching for accuracy
func GetAffectedReleasesByCVE(c *fiber.Ctx) error {
	cveID := c.Params("cveId")

	if cveID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "CVE ID is required",
		})
	}

	ctx := context.Background()

	// Step 1: Get the CVE with OSV data
	cveQuery := `
		FOR cve IN cve
			FILTER cve.osv.id == @cveId
			LIMIT 1
			RETURN cve
	`

	cveCursor, err := db.Database.Query(ctx, cveQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cveId": cveID,
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Failed to query CVE: " + err.Error(),
		})
	}
	defer cveCursor.Close()

	if !cveCursor.HasMore() {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"success": false,
			"message": "CVE not found",
		})
	}

	var cveDoc struct {
		Key string               `json:"_key"`
		OSV models.Vulnerability `json:"osv"`
	}
	_, err = cveCursor.ReadDocument(ctx, &cveDoc)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Failed to read CVE: " + err.Error(),
		})
	}

	// Step 2: Get all potential matches (simplified AQL - no version logic)
	candidatesQuery := `
		LET cveId = @cveId
		
		FOR cve IN cve
			FILTER cve.osv.id == cveId
			
			// Get all affected packages from CVE
			FOR affected IN cve.osv.affected
				
				// Build base PURL
				LET basePurl = (
					affected.package.purl != null 
					? REGEX_REPLACE(affected.package.purl, "@[^@]*$", "")
					: CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
				)
				
				// Find matching PURL hub
				FOR purl IN purl
					FILTER purl.purl == basePurl
					
					// Get all SBOM edges with versions
					FOR sbomEdge IN sbom2purl
						FILTER sbomEdge._to == purl._id
						
						LET sbom = DOCUMENT(sbomEdge._from)
						
						// Get all releases using this SBOM
						FOR release IN 1..1 INBOUND sbom release2sbom
							
							RETURN {
								affected_index: POSITION(cve.osv.affected, affected),
								package: purl.purl,
								version: sbomEdge.version,
								full_purl: sbomEdge.full_purl,
								release_name: release.name,
								release_version: release.version,
								content_sha: release.contentsha,
								project_type: release.projecttype
							}
	`

	candidatesCursor, err := db.Database.Query(ctx, candidatesQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"cveId": cveID,
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Failed to query candidates: " + err.Error(),
		})
	}
	defer candidatesCursor.Close()

	// Step 3: Filter candidates in Go using proper semver
	type Candidate struct {
		AffectedIndex  int    `json:"affected_index"`
		Package        string `json:"package"`
		Version        string `json:"version"`
		FullPurl       string `json:"full_purl"`
		ReleaseName    string `json:"release_name"`
		ReleaseVersion string `json:"release_version"`
		ContentSha     string `json:"content_sha"`
		ProjectType    string `json:"project_type"`
	}

	var affectedReleases []map[string]interface{}
	seen := make(map[string]bool) // Deduplication

	for candidatesCursor.HasMore() {
		var candidate Candidate
		_, err := candidatesCursor.ReadDocument(ctx, &candidate)
		if err != nil {
			continue
		}

		// Get the affected package info from CVE
		if candidate.AffectedIndex >= len(cveDoc.OSV.Affected) {
			continue
		}
		affected := cveDoc.OSV.Affected[candidate.AffectedIndex]

		// Check if this version is actually affected using Go logic
		if !util.IsVersionAffected(candidate.Version, affected) {
			continue
		}

		// Deduplicate by release
		key := candidate.ReleaseName + ":" + candidate.ReleaseVersion + ":" + candidate.Package + ":" + candidate.Version
		if seen[key] {
			continue
		}
		seen[key] = true

		// Extract severity
		var severity string
		for _, sev := range cveDoc.OSV.Severity {
			if sev.Type == "CVSS_V3" {
				severity = sev.Score
				break
			}
		}

		affectedReleases = append(affectedReleases, map[string]interface{}{
			"cve_id":           cveDoc.OSV.ID,
			"summary":          cveDoc.OSV.Summary,
			"details":          cveDoc.OSV.Details,
			"severity":         severity,
			"published":        cveDoc.OSV.Published,
			"modified":         cveDoc.OSV.Modified,
			"aliases":          cveDoc.OSV.Aliases,
			"package":          candidate.Package,
			"affected_version": candidate.Version,
			"full_purl":        candidate.FullPurl,
			"release_name":     candidate.ReleaseName,
			"release_version":  candidate.ReleaseVersion,
			"content_sha":      candidate.ContentSha,
			"project_type":     candidate.ProjectType,
		})
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success":           true,
		"cve_id":            cveID,
		"count":             len(affectedReleases),
		"affected_releases": affectedReleases,
	})
}

// GetReleaseVulnerabilities returns all CVEs affecting a specific release
func GetReleaseVulnerabilities(c *fiber.Ctx) error {
	name := c.Params("name")
	version := c.Params("version")

	if name == "" || version == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "Release name and version are required",
		})
	}

	ctx := context.Background()

	// Step 1: Get all packages in this release with versions
	packagesQuery := `
		FOR release IN release
			FILTER release.name == @name AND release.version == @version
			
			FOR sbom IN 1..1 OUTBOUND release release2sbom
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbom._id
					
					LET purl = DOCUMENT(sbomEdge._to)
					
					RETURN {
						package: purl.purl,
						version: sbomEdge.version,
						full_purl: sbomEdge.full_purl
					}
	`

	packagesCursor, err := db.Database.Query(ctx, packagesQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name":    name,
			"version": version,
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Failed to query packages: " + err.Error(),
		})
	}
	defer packagesCursor.Close()

	type PackageVersion struct {
		Package  string `json:"package"`
		Version  string `json:"version"`
		FullPurl string `json:"full_purl"`
	}

	var packages []PackageVersion
	for packagesCursor.HasMore() {
		var pkg PackageVersion
		_, err := packagesCursor.ReadDocument(ctx, &pkg)
		if err != nil {
			continue
		}
		packages = append(packages, pkg)
	}

	// Step 2: Get all CVEs (we'll filter in Go)
	cvesQuery := `
		FOR cve IN cve
			RETURN {
				id: cve.osv.id,
				summary: cve.osv.summary,
				details: cve.osv.details,
				severity: cve.osv.severity,
				published: cve.osv.published,
				modified: cve.osv.modified,
				aliases: cve.osv.aliases,
				affected: cve.osv.affected
			}
	`

	cvesCursor, err := db.Database.Query(ctx, cvesQuery, nil)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Failed to query CVEs: " + err.Error(),
		})
	}
	defer cvesCursor.Close()

	type CVEData struct {
		ID        string            `json:"id"`
		Summary   string            `json:"summary"`
		Details   string            `json:"details"`
		Severity  []models.Severity `json:"severity"`
		Published string            `json:"published"`
		Modified  string            `json:"modified"`
		Aliases   []string          `json:"aliases"`
		Affected  []models.Affected `json:"affected"`
	}

	var vulnerabilities []map[string]interface{}
	seen := make(map[string]bool)

	for cvesCursor.HasMore() {
		var cve CVEData
		_, err := cvesCursor.ReadDocument(ctx, &cve)
		if err != nil {
			continue
		}

		// Check each package in the release against this CVE
		for _, pkg := range packages {
			for _, affected := range cve.Affected {
				// Build base PURL from affected package
				var basePurl string
				if affected.Package.Purl != "" {
					basePurl, _ = util.GetBasePURL(affected.Package.Purl)
				} else {
					ecosystem := util.EcosystemToPurlType(string(affected.Package.Ecosystem))
					if ecosystem != "" {
						basePurl = "pkg:" + ecosystem + "/" + affected.Package.Name
					}
				}

				// Check if this package matches
				if pkg.Package != basePurl {
					continue
				}

				// Check if the version is affected
				if !util.IsVersionAffected(pkg.Version, affected) {
					continue
				}

				// Deduplicate
				key := cve.ID + ":" + pkg.Package + ":" + pkg.Version
				if seen[key] {
					continue
				}
				seen[key] = true

				// Extract severity
				var severity string
				for _, sev := range cve.Severity {
					if sev.Type == "CVSS_V3" {
						severity = sev.Score
						break
					}
				}

				vulnerabilities = append(vulnerabilities, map[string]interface{}{
					"cve_id":           cve.ID,
					"summary":          cve.Summary,
					"details":          cve.Details,
					"severity":         severity,
					"published":        cve.Published,
					"modified":         cve.Modified,
					"aliases":          cve.Aliases,
					"package":          pkg.Package,
					"affected_version": pkg.Version,
					"full_purl":        pkg.FullPurl,
				})
			}
		}
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success":         true,
		"release_name":    name,
		"release_version": version,
		"count":           len(vulnerabilities),
		"vulnerabilities": vulnerabilities,
	})
}

// ============================================================================
// LIST Handlers
// ============================================================================

// ListReleases handles GET requests for listing all releases with key, name, and version
func ListReleases(c *fiber.Ctx) error {
	ctx := context.Background()

	// Query to get all releases with only key, name, and version
	query := `
		FOR r IN release
			SORT r.name, r.version
			RETURN {
				_key: r._key,
				name: r.name,
				version: r.version
			}
	`

	cursor, err := db.Database.Query(ctx, query, nil)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Failed to query releases: " + err.Error(),
		})
	}
	defer cursor.Close()

	var releases []ReleaseListItem
	for cursor.HasMore() {
		var release ReleaseListItem
		_, err := cursor.ReadDocument(ctx, &release)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"success": false,
				"message": "Failed to read release: " + err.Error(),
			})
		}
		releases = append(releases, release)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success":  true,
		"count":    len(releases),
		"releases": releases,
	})
}

// ============================================================================
// Main
// ============================================================================

func main() {
	// Initialize database connection
	db = database.InitializeDatabase()

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName: "CVE2Release-Tracker API v1.0",
	})

	// Middleware
	app.Use(fiberrecover.New())
	app.Use(logger.New())
	app.Use(cors.New())

	// Health check endpoint
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"status": "healthy",
		})
	})

	// API routes
	api := app.Group("/api/v1")

	// POST endpoints
	api.Post("/releases", PostReleaseWithSBOM)

	// GET endpoints
	api.Get("/releases/:name/:version", GetReleaseWithSBOM)
	api.Get("/releases/:name/:version/vulnerabilities", GetReleaseVulnerabilities)

	// CVE analysis endpoints
	api.Get("/cve/:cveId/affected-releases", GetAffectedReleasesByCVE)

	// LIST endpoints
	api.Get("/releases", ListReleases)

	// Get port from environment or default to 3000
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	// Start server
	log.Printf("Starting server on port %s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
