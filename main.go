package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	fiberrecover "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/ortelius/scec-db/database"
	"github.com/ortelius/scec-db/model"
	"github.com/package-url/packageurl-go"
)

var db database.DBConnection

// ReleaseWithSBOMResponse returns the result of POST operations
type ReleaseWithSBOMResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// cleanPURL removes qualifiers (after ?) and subpath (after #) to create canonical PURL
func cleanPURL(purlStr string) (string, error) {
	parsed, err := packageurl.FromString(purlStr)
	if err != nil {
		return "", err
	}

	// Create new PURL without qualifiers and subpath
	cleaned := packageurl.PackageURL{
		Type:      parsed.Type,
		Namespace: parsed.Namespace,
		Name:      parsed.Name,
		Version:   parsed.Version,
		// Qualifiers and Subpath are intentionally omitted
	}

	return cleaned.ToString(), nil
}

// processSBOMComponents extracts PURLs from SBOM and creates hub-spoke relationships
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

	// Process each component and create PURL relationships
	for _, component := range sbomData.Components {
		if component.Purl == "" {
			continue
		}

		// Validate and clean PURL format
		cleanedPurl, err := cleanPURL(component.Purl)
		if err != nil {
			// Skip invalid PURLs
			continue
		}

		// Find or create PURL document in the purl collection using cleaned PURL
		purlKey, purlID, err := findOrCreatePURL(ctx, cleanedPurl)
		if err != nil {
			return err
		}

		// Create edge from SBOM to PURL (sbom2purl)
		edge := map[string]any{
			"_from": sbomID,
			"_to":   purlID,
		}

		// Check if edge already exists
		edgeExists, err := checkEdgeExists(ctx, "sbom2purl", sbomID, purlID)
		if err != nil {
			return err
		}

		if !edgeExists {
			_, err = db.Collections["sbom2purl"].CreateDocument(ctx, edge)
			if err != nil {
				return err
			}
		}

		_ = purlKey // purlKey available for future use
	}

	return nil
}

// findOrCreatePURL finds an existing PURL or creates a new one, returns key and ID
func findOrCreatePURL(ctx context.Context, purlStr string) (string, string, error) {
	// Query to find existing PURL
	query := `
		FOR p IN purl
			FILTER p.purl == @purl
			LIMIT 1
			RETURN p
	`
	bindVars := map[string]any{
		"purl": purlStr,
	}

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars})
	if err != nil {
		return "", "", err
	}
	defer cursor.Close()

	// If PURL exists, return it
	if cursor.HasMore() {
		var existingPURL model.PURL
		_, err = cursor.ReadDocument(ctx, &existingPURL)
		if err != nil {
			return "", "", err
		}
		return existingPURL.Key, "purl/" + existingPURL.Key, nil
	}

	// Create new PURL if it doesn't exist
	newPURL := model.PURL{
		Purl:    purlStr,
		ObjType: "PURL",
	}

	meta, err := db.Collections["purl"].CreateDocument(ctx, newPURL)
	if err != nil {
		return "", "", err
	}

	return meta.Key, "purl/" + meta.Key, nil
}

// checkEdgeExists checks if an edge already exists between two documents
func checkEdgeExists(ctx context.Context, edgeCollection, fromID, toID string) (bool, error) {
	query := `
		FOR e IN @@edgeCollection
			FILTER e._from == @from && e._to == @to
			LIMIT 1
			RETURN e
	`
	bindVars := map[string]any{
		"@edgeCollection": edgeCollection,
		"from":            fromID,
		"to":              toID,
	}

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars})
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
			Message: "Release name, and version are required fields",
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

	// Save ProjectRelease to ArangoDB
	releaseMeta, err := db.Collections["release"].CreateDocument(ctx, req.ProjectRelease)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Failed to save release: " + err.Error(),
		})
	}
	req.Key = releaseMeta.Key

	// Save SBOM to ArangoDB
	sbomMeta, err := db.Collections["sbom"].CreateDocument(ctx, req.SBOM)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Failed to save SBOM: " + err.Error(),
		})
	}
	req.SBOM.Key = sbomMeta.Key

	// Create edge relationship between release and sbom
	edge := map[string]any{
		"_from": "release/" + releaseMeta.Key,
		"_to":   "sbom/" + sbomMeta.Key,
	}
	_, err = db.Collections["release2sbom"].CreateDocument(ctx, edge)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Failed to create release-sbom relationship: " + err.Error(),
		})
	}

	// Process SBOM components and create PURL relationships
	err = processSBOMComponents(ctx, req.SBOM, "sbom/"+sbomMeta.Key)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(ReleaseWithSBOMResponse{
			Success: false,
			Message: "Failed to process SBOM components: " + err.Error(),
		})
	}

	// Return success response
	return c.Status(fiber.StatusCreated).JSON(ReleaseWithSBOMResponse{
		Success: true,
		Message: "Release and SBOM created successfully",
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
	bindVars := map[string]any{
		"name":    name,
		"version": version,
	}

	cursor, err := db.Database.Query(ctx, query, &arangodb.QueryOptions{BindVars: bindVars})
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

	sbomCursor, err := db.Database.Query(ctx, sbomQuery, &arangodb.QueryOptions{BindVars: bindVars})
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
// LIST Handlers
// ============================================================================

// ReleaseListItem represents a simplified release for list view
type ReleaseListItem struct {
	Key     string `json:"_key"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

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
		AppName: "SCEC-DB API v1.0",
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
