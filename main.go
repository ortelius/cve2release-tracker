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

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	fiberrecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/graphql-go/graphql"
	"github.com/ortelius/cve2release-tracker/database"
	gqlschema "github.com/ortelius/cve2release-tracker/graphql"
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
// GraphQL Handler
// ============================================================================

// GraphQLHandler handles GraphQL requests
func GraphQLHandler(schema graphql.Schema) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var params struct {
			Query         string                 `json:"query"`
			OperationName string                 `json:"operationName"`
			Variables     map[string]interface{} `json:"variables"`
		}

		if err := c.BodyParser(&params); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"errors": []map[string]interface{}{
					{
						"message": "Invalid request body",
					},
				},
			})
		}

		result := graphql.Do(graphql.Params{
			Schema:         schema,
			RequestString:  params.Query,
			VariableValues: params.Variables,
			OperationName:  params.OperationName,
		})

		if len(result.Errors) > 0 {
			log.Printf("GraphQL errors: %v", result.Errors)
		}

		return c.JSON(result)
	}
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

	// Initialize GraphQL schema
	gqlschema.InitDB(db)
	schema, err := gqlschema.CreateSchema()
	if err != nil {
		log.Fatalf("Failed to create GraphQL schema: %v", err)
	}

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

	// GraphQL endpoint - replaces all GET endpoints
	api.Post("/graphql", GraphQLHandler(schema))

	// LIST endpoints
	api.Get("/releases", ListReleases)

	// Get port from environment or default to 3000
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	// Start server
	log.Printf("Starting server on port %s", port)
	log.Printf("GraphQL endpoint available at /api/v1/graphql")
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
