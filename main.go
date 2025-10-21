package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

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

// SyncRequest represents the request body for creating a sync
type SyncRequest struct {
	ReleaseName    string `json:"release_name"`
	ReleaseVersion string `json:"release_version"`
	EndpointName   string `json:"endpoint_name"`
	SyncStatus     string `json:"sync_status,omitempty"`
	SyncMessage    string `json:"sync_message,omitempty"`
}

// SyncResponse represents the response for sync operations
type SyncResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	SyncKey string `json:"sync_key,omitempty"`
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

// deleteRelease2SBOMEdges deletes all existing release2sbom edges for a given release
func deleteRelease2SBOMEdges(ctx context.Context, releaseID string) error {
	query := `
		FOR e IN release2sbom
			FILTER e._from == @releaseID
			REMOVE e IN release2sbom
	`
	bindVars := map[string]interface{}{
		"releaseID": releaseID,
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

	// Delete any existing release2sbom edges for this release
	// This ensures a release only has one SBOM (the latest)
	err = deleteRelease2SBOMEdges(ctx, releaseID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Failed to remove old release-sbom relationships: " + err.Error(),
		})
	}

	// Create new edge relationship between release and sbom
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

// PostSyncWithEndpoint handles POST requests for syncing a release to an endpoint
func PostSyncWithEndpoint(c *fiber.Ctx) error {
	var req model.SyncWithEndpoint

	// Parse request body
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(SyncResponse{
			Success: false,
			Message: "Invalid request body: " + err.Error(),
		})
	}

	// Validate required fields for Sync
	if req.ReleaseName == "" || req.ReleaseVersion == "" || req.EndpointName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(SyncResponse{
			Success: false,
			Message: "release_name, release_version, and endpoint_name are required fields",
		})
	}

	ctx := context.Background()

	// Verify that the release exists
	releaseQuery := `
		FOR r IN release
			FILTER r.name == @name && r.version == @version
			LIMIT 1
			RETURN r
	`
	releaseCursor, err := db.Database.Query(ctx, releaseQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name":    req.ReleaseName,
			"version": req.ReleaseVersion,
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(SyncResponse{
			Success: false,
			Message: "Failed to query release: " + err.Error(),
		})
	}
	defer releaseCursor.Close()

	if !releaseCursor.HasMore() {
		return c.Status(fiber.StatusNotFound).JSON(SyncResponse{
			Success: false,
			Message: fmt.Sprintf("Release not found: %s version %s", req.ReleaseName, req.ReleaseVersion),
		})
	}

	// Check if endpoint exists
	endpointQuery := `
		FOR e IN endpoint
			FILTER e.name == @name
			LIMIT 1
			RETURN e
	`
	endpointCursor, err := db.Database.Query(ctx, endpointQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name": req.EndpointName,
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(SyncResponse{
			Success: false,
			Message: "Failed to query endpoint: " + err.Error(),
		})
	}
	defer endpointCursor.Close()

	endpointExists := endpointCursor.HasMore()

	// If endpoint doesn't exist, create it from the provided endpoint data
	if !endpointExists {
		// Validate endpoint fields are provided
		if req.Endpoint.Name == "" || req.Endpoint.EndpointType == "" || req.Endpoint.Environment == "" {
			return c.Status(fiber.StatusNotFound).JSON(SyncResponse{
				Success: false,
				Message: fmt.Sprintf("Endpoint not found: %s. Provide endpoint name, endpoint_type, and environment to create it.", req.EndpointName),
			})
		}

		// Ensure endpoint name matches
		if req.Endpoint.Name != req.EndpointName {
			return c.Status(fiber.StatusBadRequest).JSON(SyncResponse{
				Success: false,
				Message: "Endpoint name in sync does not match endpoint name in endpoint object",
			})
		}

		// Set ObjType if not already set
		if req.Endpoint.ObjType == "" {
			req.Endpoint.ObjType = "Endpoint"
		}

		// Create new endpoint
		_, err := db.Collections["endpoint"].CreateDocument(ctx, req.Endpoint)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(SyncResponse{
				Success: false,
				Message: "Failed to create endpoint: " + err.Error(),
			})
		}
	}

	// Create the sync record using model.NewSync()
	sync := model.NewSync()
	sync.ReleaseName = req.ReleaseName
	sync.ReleaseVersion = req.ReleaseVersion
	sync.EndpointName = req.EndpointName

	// Save sync to database
	syncMeta, err := db.Collections["sync"].CreateDocument(ctx, sync)
	if err != nil {
		// Check if it's a unique constraint violation
		if strings.Contains(err.Error(), "unique constraint") {
			return c.Status(fiber.StatusConflict).JSON(SyncResponse{
				Success: false,
				Message: "Sync already exists for this release and endpoint",
			})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(SyncResponse{
			Success: false,
			Message: "Failed to save sync: " + err.Error(),
		})
	}

	message := fmt.Sprintf("Successfully synced release %s version %s to endpoint %s",
		req.ReleaseName, req.ReleaseVersion, req.EndpointName)

	if !endpointExists {
		message += " (endpoint created)"
	}

	return c.Status(fiber.StatusCreated).JSON(SyncResponse{
		Success: true,
		Message: message,
		SyncKey: syncMeta.Key,
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

// REPLACE GetReleaseVulnerabilities with this version that uses the cve2purl edges
// This is the TRUE hub-and-spoke approach - should be VERY fast

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

	log.Printf("Fetching vulnerabilities for release %s:%s using hub-and-spoke", name, version)

	// Pure graph traversal query using the hub-and-spoke architecture
	// This traverses: Release -> SBOM -> PURL <- CVE
	query := `
		FOR release IN release
			FILTER release.name == @name AND release.version == @version
			
			// Get SBOM
			FOR sbom IN 1..1 OUTBOUND release release2sbom
				
				// Get all PURLs used by this SBOM (with versions)
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbom._id
					
					LET purl = DOCUMENT(sbomEdge._to)
					LET packageVersion = sbomEdge.version
					LET packageFullPurl = sbomEdge.full_purl
					
					// Find CVEs affecting this PURL (via cve2purl edges!)
					FOR cve IN 1..1 INBOUND purl cve2purl
						
						// Get the affected data that matches this PURL
						FOR affected IN cve.affected
							
							// Match this specific PURL
							LET cveBasePurl = affected.package.purl != null ? 
								affected.package.purl : 
								CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
							
							FILTER cveBasePurl == purl.purl

							RETURN {
								cve_id: cve.id,
								summary: cve.summary,
								details: cve.details,
								severity: cve.severity,
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
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Failed to query vulnerabilities: " + err.Error(),
		})
	}
	defer cursor.Close()

	// Process results and filter by version
	type CVEResult struct {
		CveID          string            `json:"cve_id"`
		Summary        string            `json:"summary"`
		Details        string            `json:"details"`
		Severity       []models.Severity `json:"severity"`
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
	candidateCount := 0

	for cursor.HasMore() {
		var result CVEResult
		_, err := cursor.ReadDocument(ctx, &result)
		if err != nil {
			continue
		}
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))

		candidateCount++

		// Check if this version is actually affected
		if !util.IsVersionAffected(result.PackageVersion, result.AffectedData) {
			continue
		}

		// Deduplicate
		key := result.CveID + ":" + result.Package + ":" + result.PackageVersion
		if seen[key] {
			continue
		}
		seen[key] = true

		// Extract severity score
		var severity string
		for _, sev := range result.Severity {
			if sev.Type == "CVSS_V3" {
				severity = sev.Score
				break
			}
		}

		vulnerabilities = append(vulnerabilities, map[string]interface{}{
			"cve_id":           result.CveID,
			"summary":          result.Summary,
			"details":          result.Details,
			"severity":         severity,
			"published":        result.Published,
			"modified":         result.Modified,
			"aliases":          result.Aliases,
			"package":          result.Package,
			"affected_version": result.PackageVersion,
			"full_purl":        result.FullPurl,
		})
	}

	log.Printf("Hub-and-spoke query returned %d candidates, %d actual vulnerabilities for release %s:%s",
		candidateCount, len(vulnerabilities), name, version)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success":         true,
		"release_name":    name,
		"release_version": version,
		"count":           len(vulnerabilities),
		"vulnerabilities": vulnerabilities,
	})
}

// GetAffectedReleasesBySeverity returns all releases affected by CVEs of a specific severity
// OPTIMIZED: Uses pre-calculated CVSS scores stored during ingestion
// CVEs without severity scores are defaulted to LOW (0.1)
func GetAffectedReleasesBySeverity(c *fiber.Ctx) error {
	severity := c.Params("severity")

	if severity == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "Severity is required",
		})
	}

	// Validate severity
	validSeverities := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
	}

	severityLower := strings.ToLower(severity)
	if !validSeverities[severityLower] {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "Invalid severity. Must be one of: critical, high, medium, low",
		})
	}

	// Convert to uppercase for database comparison
	severityUpper := strings.ToUpper(severityLower)

	ctx := context.Background()

	log.Printf("Querying releases affected by %s severity", severityLower)

	// Query uses pre-calculated severity_rating from database_specific
	combinedQuery := `
		FOR release IN release
			
			// Get SBOM for this release
			FOR sbom IN 1..1 OUTBOUND release release2sbom
				
				// Get all PURLs used by this SBOM (with versions)
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbom._id
					
					LET purl = DOCUMENT(sbomEdge._to)
					FILTER purl != null
					
					LET packageVersion = sbomEdge.version
					LET packageFullPurl = sbomEdge.full_purl
					
					// Find CVEs affecting this PURL
					FOR cveEdge IN cve2purl
						FILTER cveEdge._to == purl._id
						
						LET cve = DOCUMENT(cveEdge._from)
						FILTER cve != null
						
						// Filter by pre-calculated severity rating
						LET severityRating = cve.database_specific.severity_rating
						FILTER severityRating == @severityRating
						
						// Get the affected data that matches this PURL
						FILTER cve.affected != null
						FOR affected IN cve.affected
							
							// Match this specific PURL
							LET cveBasePurl = affected.package.purl != null ? 
								affected.package.purl : 
								CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
							
							FILTER cveBasePurl == purl.purl
							
							RETURN {
								cve_id: cve.id,
								cve_summary: cve.summary,
								cve_details: cve.details,
								cve_severity_score: cve.database_specific.cvss_base_score,
								cve_severity_rating: severityRating,
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
								project_type: release.projecttype
							}
	`

	cursor, err := db.Database.Query(ctx, combinedQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"severityRating": severityUpper,
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Failed to query CVEs and releases: " + err.Error(),
		})
	}
	defer cursor.Close()

	type Candidate struct {
		CveID             string          `json:"cve_id"`
		CveSummary        string          `json:"cve_summary"`
		CveDetails        string          `json:"cve_details"`
		CveSeverityScore  float64         `json:"cve_severity_score"`
		CveSeverityRating string          `json:"cve_severity_rating"`
		CvePublished      string          `json:"cve_published"`
		CveModified       string          `json:"cve_modified"`
		CveAliases        []string        `json:"cve_aliases"`
		AffectedData      models.Affected `json:"affected_data"`
		Package           string          `json:"package"`
		Version           string          `json:"version"`
		FullPurl          string          `json:"full_purl"`
		ReleaseName       string          `json:"release_name"`
		ReleaseVersion    string          `json:"release_version"`
		ContentSha        string          `json:"content_sha"`
		ProjectType       string          `json:"project_type"`
	}

	var affectedReleases []model.AffectedRelease
	seen := make(map[string]bool)
	candidateCount := 0

	for cursor.HasMore() {
		var candidate Candidate
		_, err := cursor.ReadDocument(ctx, &candidate)
		if err != nil {
			continue
		}

		candidateCount++

		// Check if this version is actually affected using Go logic
		if !util.IsVersionAffected(candidate.Version, candidate.AffectedData) {
			continue
		}

		// Deduplicate
		key := candidate.ReleaseName + ":" + candidate.ReleaseVersion + ":" + candidate.Package + ":" + candidate.Version + ":" + candidate.CveID
		if seen[key] {
			continue
		}
		seen[key] = true

		affectedReleases = append(affectedReleases, model.AffectedRelease{
			CveID:           candidate.CveID,
			Summary:         candidate.CveSummary,
			Details:         candidate.CveDetails,
			Severity:        fmt.Sprintf("%.1f", candidate.CveSeverityScore),
			Published:       candidate.CvePublished,
			Modified:        candidate.CveModified,
			Aliases:         candidate.CveAliases,
			Package:         candidate.Package,
			AffectedVersion: candidate.Version,
			FullPurl:        candidate.FullPurl,
			ReleaseName:     candidate.ReleaseName,
			ReleaseVersion:  candidate.ReleaseVersion,
			ContentSha:      candidate.ContentSha,
			ProjectType:     candidate.ProjectType,
		})
	}

	log.Printf("Query returned %d candidates, %d actual affected releases for %s severity",
		candidateCount, len(affectedReleases), severityLower)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success":           true,
		"severity":          severityLower,
		"count":             len(affectedReleases),
		"affected_releases": affectedReleases,
	})
}

// GetEndpointsWithSeverity returns all endpoints affected by CVEs of a specific severity
// OPTIMIZED: Uses pre-calculated CVSS scores stored during ingestion
// CVEs without severity scores are defaulted to LOW (0.1)
func GetEndpointsWithSeverity(c *fiber.Ctx) error {
	severity := c.Params("severity")

	if severity == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "Severity is required",
		})
	}

	// Validate severity
	validSeverities := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
	}

	severityLower := strings.ToLower(severity)
	if !validSeverities[severityLower] {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "Invalid severity. Must be one of: critical, high, medium, low",
		})
	}

	// Convert to uppercase for database comparison
	severityUpper := strings.ToUpper(severityLower)

	ctx := context.Background()

	log.Printf("Querying endpoints affected by %s severity", severityLower)

	// Query uses pre-calculated severity_rating from database_specific
	combinedQuery := `
		FOR release IN release
			
			// Get SBOM for this release
			FOR sbom IN 1..1 OUTBOUND release release2sbom
				
				// Get all PURLs used by this SBOM (with versions)
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbom._id
					
					LET purl = DOCUMENT(sbomEdge._to)
					FILTER purl != null
					
					LET packageVersion = sbomEdge.version
					LET packageFullPurl = sbomEdge.full_purl
					
					// Find CVEs affecting this PURL
					FOR cveEdge IN cve2purl
						FILTER cveEdge._to == purl._id
						
						LET cve = DOCUMENT(cveEdge._from)
						FILTER cve != null
						
						// Filter by pre-calculated severity rating
						LET severityRating = cve.database_specific.severity_rating
						FILTER severityRating == @severityRating
						
						// Get the affected data that matches this PURL
						FILTER cve.affected != null
						FOR affected IN cve.affected
							
							// Match this specific PURL
							LET cveBasePurl = affected.package.purl != null ? 
								affected.package.purl : 
								CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name)
							
							FILTER cveBasePurl == purl.purl
							
							// Get all syncs for this release
							FOR sync IN sync
								FILTER sync.release_name == release.name 
								   AND sync.release_version == release.version
								
								// Get endpoint details
								FOR endpoint IN endpoint
									FILTER endpoint.name == sync.endpoint_name
									
									RETURN {
										cve_id: cve.id,
										cve_summary: cve.summary,
										cve_details: cve.details,
										cve_severity_score: cve.database_specific.cvss_base_score,
										cve_severity_rating: severityRating,
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
	`

	cursor, err := db.Database.Query(ctx, combinedQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"severityRating": severityUpper,
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"success": false,
			"message": "Failed to query CVEs and endpoints: " + err.Error(),
		})
	}
	defer cursor.Close()

	type Candidate struct {
		CveID             string          `json:"cve_id"`
		CveSummary        string          `json:"cve_summary"`
		CveDetails        string          `json:"cve_details"`
		CveSeverityScore  float64         `json:"cve_severity_score"`
		CveSeverityRating string          `json:"cve_severity_rating"`
		CvePublished      string          `json:"cve_published"`
		CveModified       string          `json:"cve_modified"`
		CveAliases        []string        `json:"cve_aliases"`
		AffectedData      models.Affected `json:"affected_data"`
		Package           string          `json:"package"`
		Version           string          `json:"version"`
		FullPurl          string          `json:"full_purl"`
		ReleaseName       string          `json:"release_name"`
		ReleaseVersion    string          `json:"release_version"`
		ContentSha        string          `json:"content_sha"`
		ProjectType       string          `json:"project_type"`
		EndpointName      string          `json:"endpoint_name"`
		EndpointType      string          `json:"endpoint_type"`
		Environment       string          `json:"environment"`
		SyncedAt          time.Time       `json:"synced_at"`
	}

	var affectedEndpoints []model.AffectedEndpoint
	seen := make(map[string]bool)
	candidateCount := 0

	for cursor.HasMore() {
		var candidate Candidate
		_, err := cursor.ReadDocument(ctx, &candidate)
		if err != nil {
			continue
		}

		candidateCount++

		// Check if this version is actually affected
		if !util.IsVersionAffected(candidate.Version, candidate.AffectedData) {
			continue
		}

		// Deduplicate
		key := candidate.EndpointName + ":" + candidate.ReleaseName + ":" + candidate.ReleaseVersion + ":" + candidate.Package + ":" + candidate.Version + ":" + candidate.CveID
		if seen[key] {
			continue
		}
		seen[key] = true

		affectedEndpoints = append(affectedEndpoints, model.AffectedEndpoint{
			CveID:           candidate.CveID,
			Summary:         candidate.CveSummary,
			Details:         candidate.CveDetails,
			Severity:        fmt.Sprintf("%.1f", candidate.CveSeverityScore),
			Published:       candidate.CvePublished,
			Modified:        candidate.CveModified,
			Aliases:         candidate.CveAliases,
			Package:         candidate.Package,
			AffectedVersion: candidate.Version,
			FullPurl:        candidate.FullPurl,
			ReleaseName:     candidate.ReleaseName,
			ReleaseVersion:  candidate.ReleaseVersion,
			ContentSha:      candidate.ContentSha,
			ProjectType:     candidate.ProjectType,
			EndpointName:    candidate.EndpointName,
			EndpointType:    candidate.EndpointType,
			Environment:     candidate.Environment,
			SyncedAt:        candidate.SyncedAt,
		})
	}

	log.Printf("Query returned %d candidates, %d actual affected endpoints for %s severity",
		candidateCount, len(affectedEndpoints), severityLower)

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"success":            true,
		"severity":           severityLower,
		"count":              len(affectedEndpoints),
		"affected_endpoints": affectedEndpoints,
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

// Add this diagnostic endpoint to check how SBOMs are being processed

func DiagnoseSBOMPURLs(c *fiber.Ctx) error {
	name := c.Params("name")
	version := c.Params("version")

	ctx := context.Background()

	// Get the SBOM content
	sbomQuery := `
		FOR release IN release
			FILTER release.name == @name AND release.version == @version
			FOR sbom IN 1..1 OUTBOUND release release2sbom
				RETURN sbom.content
	`

	sbomCursor, err := db.Database.Query(ctx, sbomQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name":    name,
			"version": version,
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to query SBOM: " + err.Error(),
		})
	}
	defer sbomCursor.Close()

	var sbomContent json.RawMessage
	if !sbomCursor.HasMore() {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "SBOM not found",
		})
	}
	sbomCursor.ReadDocument(ctx, &sbomContent)

	// Parse SBOM to see what PURLs look like
	var sbomData struct {
		Components []struct {
			Name string `json:"name"`
			Purl string `json:"purl"`
		} `json:"components"`
	}

	if err := json.Unmarshal(sbomContent, &sbomData); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to parse SBOM: " + err.Error(),
		})
	}

	// Sample first 5 components
	samples := []map[string]interface{}{}
	for i, comp := range sbomData.Components {
		if i >= 5 {
			break
		}

		// Try to parse and get base PURL
		cleaned, _ := util.CleanPURL(comp.Purl)
		basePurl, _ := util.GetBasePURL(comp.Purl)
		parsed, _ := util.ParsePURL(comp.Purl)

		sample := map[string]interface{}{
			"component_name": comp.Name,
			"original_purl":  comp.Purl,
			"cleaned_purl":   cleaned,
			"base_purl":      basePurl,
		}

		if parsed != nil {
			sample["parsed_type"] = parsed.Type
			sample["parsed_namespace"] = parsed.Namespace
			sample["parsed_name"] = parsed.Name
			sample["parsed_version"] = parsed.Version
		}

		samples = append(samples, sample)
	}

	// Check what's actually stored in the PURL collection
	storedPurlsQuery := `
		FOR release IN release
			FILTER release.name == @name AND release.version == @version
			FOR sbom IN 1..1 OUTBOUND release release2sbom
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbom._id
					LIMIT 5
					LET purl = DOCUMENT(sbomEdge._to)
					RETURN {
						purl_stored: purl.purl,
						version_stored: sbomEdge.version,
						full_purl_stored: sbomEdge.full_purl
					}
	`

	storedCursor, _ := db.Database.Query(ctx, storedPurlsQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name":    name,
			"version": version,
		},
	})
	defer storedCursor.Close()

	var storedPurls []map[string]interface{}
	for storedCursor.HasMore() {
		var stored map[string]interface{}
		storedCursor.ReadDocument(ctx, &stored)
		storedPurls = append(storedPurls, stored)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"sbom_component_samples": samples,
		"stored_purls_in_db":     storedPurls,
		"issue":                  "Compare 'base_purl' from SBOM with 'purl_stored' in DB - they should match!",
	})
}

// Add this function before the main() function in main.go

func DebugReleaseVulnerabilities(c *fiber.Ctx) error {
	name := c.Params("name")
	version := c.Params("version")

	if name == "" || version == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"success": false,
			"message": "Release name and version are required",
		})
	}

	ctx := context.Background()
	debug := make(map[string]interface{})

	// Step 1: Verify release exists
	releaseQuery := `
		FOR release IN release
			FILTER release.name == @name AND release.version == @version
			RETURN release
	`
	releaseCursor, err := db.Database.Query(ctx, releaseQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name":    name,
			"version": version,
		},
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to query release: " + err.Error(),
		})
	}
	defer releaseCursor.Close()

	if !releaseCursor.HasMore() {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "Release not found",
		})
	}

	var release model.ProjectRelease
	releaseCursor.ReadDocument(ctx, &release)
	debug["release_found"] = true
	debug["release_key"] = release.Key

	// Step 2: Get packages from SBOM
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
			"error": "Failed to query packages: " + err.Error(),
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
		packagesCursor.ReadDocument(ctx, &pkg)
		packages = append(packages, pkg)
	}

	debug["package_count"] = len(packages)
	debug["packages_sample"] = packages[:min(10, len(packages))] // First 10

	// Step 3: Get total CVE count
	cveCountQuery := `RETURN LENGTH(cve)`
	cveCountCursor, _ := db.Database.Query(ctx, cveCountQuery, nil)
	var cveCount int
	if cveCountCursor.HasMore() {
		cveCountCursor.ReadDocument(ctx, &cveCount)
	}
	cveCountCursor.Close()
	debug["total_cve_count"] = cveCount

	// Step 4: Sample CVE check - get first 5 CVEs
	sampleCVEQuery := `
		FOR cve IN cve
			LIMIT 5
			RETURN {
				id: cve.id,
				summary: cve.summary,
				affected_count: LENGTH(cve.affected)
			}
	`
	sampleCursor, _ := db.Database.Query(ctx, sampleCVEQuery, nil)
	defer sampleCursor.Close()

	var sampleCVEs []interface{}
	for sampleCursor.HasMore() {
		var cve interface{}
		sampleCursor.ReadDocument(ctx, &cve)
		sampleCVEs = append(sampleCVEs, cve)
	}
	debug["sample_cves"] = sampleCVEs

	// Step 5: Try to find CVEs that match first package using database query (EFFICIENT)
	if len(packages) > 0 {
		firstPkg := packages[0]
		debug["first_package"] = firstPkg

		// Use a database query to find matching CVEs efficiently
		matchQuery := `
			FOR cve IN cve
				FOR affected IN cve.affected
					FILTER affected.package.purl == @package OR
					       CONCAT("pkg:", LOWER(affected.package.ecosystem), "/", affected.package.name) == @package
					LIMIT 10
					RETURN {
						cve_id: cve.id,
						cve_summary: cve.summary,
						package_purl: affected.package.purl,
						package_ecosystem: affected.package.ecosystem,
						package_name: affected.package.name,
						ranges: affected.ranges,
						versions: affected.versions
					}
		`

		matchCursor, err := db.Database.Query(ctx, matchQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"package": firstPkg.Package,
			},
		})
		if err != nil {
			debug["match_query_error"] = err.Error()
		} else {
			defer matchCursor.Close()

			var matches []interface{}
			for matchCursor.HasMore() {
				var match interface{}
				matchCursor.ReadDocument(ctx, &match)
				matches = append(matches, match)
			}
			debug["first_package_potential_matches"] = matches
			debug["first_package_match_count"] = len(matches)
		}
	}

	// Step 6: Check SBOM structure
	sbomStructureQuery := `
		FOR release IN release
			FILTER release.name == @name AND release.version == @version
			FOR sbom IN 1..1 OUTBOUND release release2sbom
				RETURN {
					sbom_key: sbom._key,
					sbom_contentsha: sbom.contentsha,
					has_content: sbom.content != null,
					component_count: LENGTH(JSON_PARSE(sbom.content).components)
				}
	`
	sbomStructCursor, _ := db.Database.Query(ctx, sbomStructureQuery, &arangodb.QueryOptions{
		BindVars: map[string]interface{}{
			"name":    name,
			"version": version,
		},
	})
	if sbomStructCursor.HasMore() {
		var sbomInfo interface{}
		sbomStructCursor.ReadDocument(ctx, &sbomInfo)
		debug["sbom_info"] = sbomInfo
	}
	sbomStructCursor.Close()

	return c.Status(fiber.StatusOK).JSON(debug)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Add this diagnostic endpoint to check if the graph is complete

func DiagnoseGraphCompleteness(c *fiber.Ctx) error {
	ctx := context.Background()

	// Check all collections and edge collections
	checks := map[string]string{
		"releases":     "RETURN LENGTH(release)",
		"sboms":        "RETURN LENGTH(sbom)",
		"purls":        "RETURN LENGTH(purl)",
		"cves":         "RETURN LENGTH(cve)",
		"endpoints":    "RETURN LENGTH(endpoint)",
		"syncs":        "RETURN LENGTH(sync)",
		"release2sbom": "RETURN LENGTH(release2sbom)",
		"sbom2purl":    "RETURN LENGTH(sbom2purl)",
		"cve2purl":     "RETURN LENGTH(cve2purl)",
	}

	results := make(map[string]interface{})

	for name, query := range checks {
		cursor, err := db.Database.Query(ctx, query, nil)
		if err != nil {
			results[name] = "ERROR: " + err.Error()
			continue
		}

		var count int
		if cursor.HasMore() {
			cursor.ReadDocument(ctx, &count)
		}
		cursor.Close()
		results[name] = count
	}

	// Check if we have any CVEs with severity info
	severityQuery := `
		FOR cve IN cve
			FILTER LENGTH(cve.severity) > 0
			LIMIT 1
			RETURN cve.id
	`

	severityCursor, _ := db.Database.Query(ctx, severityQuery, nil)
	hasCVEsWithSeverity := severityCursor.HasMore()
	var sampleCVEWithSeverity string
	if hasCVEsWithSeverity {
		severityCursor.ReadDocument(ctx, &sampleCVEWithSeverity)
	}
	severityCursor.Close()

	results["has_cves_with_severity"] = hasCVEsWithSeverity
	results["sample_cve_with_severity"] = sampleCVEWithSeverity

	// Check if any release has a path to CVEs via the graph
	pathQuery := `
		FOR release IN release
			LIMIT 1
			FOR sbom IN 1..1 OUTBOUND release release2sbom
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbom._id
					LIMIT 1
					LET purl = DOCUMENT(sbomEdge._to)
					LET cveCount = LENGTH(
						FOR cve IN 1..1 INBOUND purl cve2purl
							LIMIT 1
							RETURN cve
					)
					RETURN {
						has_release: true,
						has_sbom: true,
						has_purl: true,
						has_cve_connection: cveCount > 0,
						purl_example: purl.purl
					}
	`

	pathCursor, _ := db.Database.Query(ctx, pathQuery, nil)
	var pathInfo map[string]interface{}
	if pathCursor.HasMore() {
		pathCursor.ReadDocument(ctx, &pathInfo)
	}
	pathCursor.Close()

	results["graph_path_check"] = pathInfo

	// Determine what's missing
	var issues []string
	if results["cve2purl"].(int) == 0 {
		issues = append(issues, "CRITICAL: No cve2purl edges! You need to reload CVEs with the fixed PURL construction code.")
	}
	if results["sbom2purl"].(int) == 0 {
		issues = append(issues, "CRITICAL: No sbom2purl edges! You need to upload SBOMs.")
	}
	if results["release2sbom"].(int) == 0 {
		issues = append(issues, "CRITICAL: No release2sbom edges! You need to upload releases with SBOMs.")
	}
	if !hasCVEsWithSeverity {
		issues = append(issues, "WARNING: No CVEs have severity information.")
	}

	if len(issues) == 0 {
		issues = append(issues, "Graph appears complete! If queries still fail, check query syntax.")
	}

	results["issues"] = issues

	return c.Status(fiber.StatusOK).JSON(results)
}

// DiagnoseInboundTraversal - Debug endpoint to find what's causing INBOUND traversal to fail
func DiagnoseInboundTraversal(c *fiber.Ctx) error {
	ctx := context.Background()
	debug := make(map[string]interface{})

	// Step 1: Check if cve2purl edge collection exists and has data
	cve2purlCountQuery := `RETURN LENGTH(cve2purl)`
	cursor, _ := db.Database.Query(ctx, cve2purlCountQuery, nil)
	if cursor.HasMore() {
		var count int
		cursor.ReadDocument(ctx, &count)
		debug["cve2purl_edge_count"] = count
	}
	cursor.Close()

	// Step 2: Sample some cve2purl edges
	sampleEdgesQuery := `
		FOR edge IN cve2purl
			LIMIT 5
			RETURN {
				from: edge._from,
				to: edge._to,
				from_exists: DOCUMENT(edge._from) != null,
				to_exists: DOCUMENT(edge._to) != null
			}
	`
	cursor, _ = db.Database.Query(ctx, sampleEdgesQuery, nil)
	var sampleEdges []interface{}
	for cursor.HasMore() {
		var edge interface{}
		cursor.ReadDocument(ctx, &edge)
		sampleEdges = append(sampleEdges, edge)
	}
	cursor.Close()
	debug["sample_cve2purl_edges"] = sampleEdges

	// Step 3: Get a sample release and its PURLs
	releasePurlQuery := `
		FOR release IN release
			LIMIT 1
			FOR sbom IN 1..1 OUTBOUND release release2sbom
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbom._id
					LIMIT 3
					LET purl = DOCUMENT(sbomEdge._to)
					RETURN {
						release_name: release.name,
						release_version: release.version,
						purl_id: purl._id,
						purl_key: purl._key,
						purl_value: purl.purl,
						sbom_edge_from: sbomEdge._from,
						sbom_edge_to: sbomEdge._to
					}
	`
	cursor, _ = db.Database.Query(ctx, releasePurlQuery, nil)
	var releasePurls []interface{}
	for cursor.HasMore() {
		var rp interface{}
		cursor.ReadDocument(ctx, &rp)
		releasePurls = append(releasePurls, rp)
	}
	cursor.Close()
	debug["sample_release_purls"] = releasePurls

	// Step 4: Try the INBOUND traversal on a specific PURL
	if len(releasePurls) > 0 {
		// Extract purl_id from first sample
		firstPurl := releasePurls[0].(map[string]interface{})
		purlID := firstPurl["purl_id"].(string)

		// Try INBOUND traversal
		inboundTestQuery := `
			LET purl = DOCUMENT(@purlId)
			RETURN {
				purl_id: purl._id,
				purl_value: purl.purl,
				inbound_test: (
					FOR cve IN 1..1 INBOUND purl cve2purl
						LIMIT 3
						RETURN {
							cve_id: cve.id,
							cve_key: cve._key
						}
				)
			}
		`
		cursor, err := db.Database.Query(ctx, inboundTestQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"purlId": purlID,
			},
		})
		if err != nil {
			debug["inbound_traversal_error"] = err.Error()
		} else {
			var result interface{}
			if cursor.HasMore() {
				cursor.ReadDocument(ctx, &result)
				debug["inbound_traversal_test"] = result
			}
			cursor.Close()
		}

		// Try the alternative approach (FOR edge IN collection)
		alternativeQuery := `
			LET purl = DOCUMENT(@purlId)
			RETURN {
				purl_id: purl._id,
				purl_value: purl.purl,
				alternative_test: (
					FOR cveEdge IN cve2purl
						FILTER cveEdge._to == purl._id
						LIMIT 3
						LET cve = DOCUMENT(cveEdge._from)
						RETURN {
							cve_id: cve.id,
							cve_key: cve._key,
							edge_from: cveEdge._from,
							edge_to: cveEdge._to
						}
				)
			}
		`
		cursor, err = db.Database.Query(ctx, alternativeQuery, &arangodb.QueryOptions{
			BindVars: map[string]interface{}{
				"purlId": purlID,
			},
		})
		if err != nil {
			debug["alternative_approach_error"] = err.Error()
		} else {
			var result interface{}
			if cursor.HasMore() {
				cursor.ReadDocument(ctx, &result)
				debug["alternative_approach_test"] = result
			}
			cursor.Close()
		}
	}

	// Step 5: Check if there are any NULL values in the graph
	nullCheckQuery := `
		FOR release IN release
			LIMIT 5
			FOR sbom IN 1..1 OUTBOUND release release2sbom
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbom._id
					LET purl = DOCUMENT(sbomEdge._to)
					RETURN {
						release_name: release.name,
						sbom_id: sbom._id,
						purl_id: purl._id,
						purl_is_null: purl == null,
						sbom_edge_to: sbomEdge._to,
						purl_document_lookup: DOCUMENT(sbomEdge._to) != null
					}
	`
	cursor, _ = db.Database.Query(ctx, nullCheckQuery, nil)
	var nullChecks []interface{}
	for cursor.HasMore() {
		var nc interface{}
		cursor.ReadDocument(ctx, &nc)
		nullChecks = append(nullChecks, nc)
	}
	cursor.Close()
	debug["null_checks"] = nullChecks

	// Step 6: Try the full problematic query on a small subset
	problemQueryTest := `
		FOR release IN release
			LIMIT 1
			FOR sbom IN 1..1 OUTBOUND release release2sbom
				FOR sbomEdge IN sbom2purl
					FILTER sbomEdge._from == sbom._id
					LET purl = DOCUMENT(sbomEdge._to)
					LET packageVersion = sbomEdge.version
					RETURN {
						release: release.name,
						purl_id: purl._id,
						purl_value: purl.purl,
						purl_type: TYPENAME(purl),
						inbound_result_type: TYPENAME(
							FOR cve IN 1..1 INBOUND purl cve2purl
								LIMIT 1
								RETURN cve
						)
					}
	`
	cursor, err := db.Database.Query(ctx, problemQueryTest, nil)
	if err != nil {
		debug["problem_query_test_error"] = err.Error()
	} else {
		var results []interface{}
		for cursor.HasMore() {
			var result interface{}
			cursor.ReadDocument(ctx, &result)
			results = append(results, result)
		}
		debug["problem_query_test_results"] = results
		cursor.Close()
	}

	// Step 7: Check the actual structure of purl documents
	purlStructureQuery := `
		FOR purl IN purl
			LIMIT 3
			RETURN {
				id: purl._id,
				key: purl._key,
				purl: purl.purl,
				objtype: purl.objtype,
				all_fields: ATTRIBUTES(purl)
			}
	`
	cursor, _ = db.Database.Query(ctx, purlStructureQuery, nil)
	var purlStructures []interface{}
	for cursor.HasMore() {
		var ps interface{}
		cursor.ReadDocument(ctx, &ps)
		purlStructures = append(purlStructures, ps)
	}
	cursor.Close()
	debug["purl_document_structures"] = purlStructures

	return c.Status(fiber.StatusOK).JSON(debug)
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
	api.Post("/sync", PostSyncWithEndpoint)

	// GET endpoints
	api.Get("/releases/:name/:version", GetReleaseWithSBOM)
	api.Get("/releases/:name/:version/vulnerabilities", GetReleaseVulnerabilities)

	// CVE analysis endpoints
	api.Get("/severity/:severity/affected-releases", GetAffectedReleasesBySeverity)
	api.Get("/severity/:severity/affected-endpoints", GetEndpointsWithSeverity)

	// LIST endpoints
	api.Get("/releases", ListReleases)

	// DEBUG
	api.Get("/releases/:name/:version/diagnose-sbom-purls", DiagnoseSBOMPURLs)
	api.Get("/releases/:name/:version/vulnerabilities/debug", DebugReleaseVulnerabilities)
	api.Get("/debug/inbound-traversal", DiagnoseInboundTraversal)

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
