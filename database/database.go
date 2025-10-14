// Package database - Handles all interaction with ArangoDB and Long Term Storage (LTS).
// Contains utility functions for marshaling/unmarshaling json to cid/nfts
package database

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"fmt"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/connection"
	"github.com/cenkalti/backoff"
	"github.com/ortelius/scec-db/util"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

//lint:file-ignore S1034 Ignore all assignments for switch statements

var logger = InitLogger() // setup the logger

// DBConnection is the structure that defined the database engine and collections
type DBConnection struct {
	Collections map[string]arangodb.Collection
	Database    arangodb.Database
}

// Define a struct to hold the index definition
type indexConfig struct {
	Collection string
	IdxName    string
	IdxField   string
}

var initDone = false          // has the data been initialized
var dbConnection DBConnection // database connection definition

// InitLogger sets up the Zap Logger to log to the console in a human readable format
func InitLogger() *zap.Logger {
	prodConfig := zap.NewProductionConfig()
	prodConfig.Encoding = "console"
	prodConfig.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	prodConfig.EncoderConfig.EncodeDuration = zapcore.StringDurationEncoder
	logger, _ := prodConfig.Build()
	return logger
}

func dbConnectionConfig(endpoint connection.Endpoint, dbuser string, dbpass string) connection.HttpConfiguration {
	return connection.HttpConfiguration{
		Authentication: connection.NewBasicAuth(dbuser, dbpass),
		Endpoint:       endpoint,
		ContentType:    connection.ApplicationJSON,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // #nosec G402
			},
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 90 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}

// InitializeDatabase is the function for connecting to the db engine, creating the database and collections
func InitializeDatabase() DBConnection {

	const initialInterval = 10 * time.Second
	const maxInterval = 2 * time.Minute

	var db arangodb.Database
	var collections map[string]arangodb.Collection
	const databaseName = "vulnmgt"

	ctx := context.Background()

	if initDone {
		return dbConnection
	}

	False := false
	dbhost := util.GetEnvDefault("ARANGO_HOST", "localhost")
	dbport := util.GetEnvDefault("ARANGO_PORT", "8529")
	dbuser := util.GetEnvDefault("ARANGO_USER", "root")
	dbpass := util.GetEnvDefault("ARANGO_PASS", "")
	dburl := util.GetEnvDefault("ARANGO_URL", "http://"+dbhost+":"+dbport)

	var client arangodb.Client

	//
	// Database connection with backuoff retry
	//

	// Configure exponential backoff
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = initialInterval
	bo.MaxInterval = maxInterval
	bo.MaxElapsedTime = 0 // Set to 0 for indefinite retries

	// Retry logic
	err := backoff.RetryNotify(func() error {
		fmt.Println("Attempting to connect to ArangoDB")
		endpoint := connection.NewRoundRobinEndpoints([]string{dburl})
		conn := connection.NewHttpConnection(dbConnectionConfig(endpoint, dbuser, dbpass))

		client = arangodb.NewClient(conn)

		// Ask the version of the server
		versionInfo, err := client.Version(context.Background())
		if err != nil {
			return err
		}

		logger.Sugar().Infof("Database has version '%s' and license '%s'\n", versionInfo.Version, versionInfo.License)
		return nil

	}, bo, func(err error, _ time.Duration) {
		// Optionally, you can add a message here to be printed after each retry
		fmt.Printf("Retrying connection to ArangoDB: %v\n", err)
	})

	if err != nil {
		logger.Sugar().Fatalf("Backoff Error %v\n", err)
	}

	//
	// Database creation
	//

	exists := false
	dblist, _ := client.Databases(ctx)

	for _, dbinfo := range dblist {
		if dbinfo.Name() == databaseName {
			exists = true
			break
		}
	}

	if exists {
		var options arangodb.GetDatabaseOptions
		if db, err = client.GetDatabase(ctx, databaseName, &options); err != nil {
			logger.Sugar().Fatalf("Failed to create Database: %v", err)
		}
	} else {
		if db, err = client.CreateDatabase(ctx, databaseName, nil); err != nil {
			logger.Sugar().Fatalf("Failed to create Database: %v", err)
		}
	}

	//
	// Collection creation for document storage
	//

	collections = make(map[string]arangodb.Collection)
	collectionNames := []string{"release", "sbom", "purl", "cve"}

	for _, collectionName := range collectionNames {
		var col arangodb.Collection

		exists, _ = db.CollectionExists(ctx, collectionName)
		if exists {
			var options arangodb.GetCollectionOptions
			if col, err = db.GetCollection(ctx, collectionName, &options); err != nil {
				logger.Sugar().Fatalf("Failed to use collection: %v", err)
			}
		} else {
			if col, err = db.CreateCollectionV2(ctx, collectionName, nil); err != nil {
				logger.Sugar().Fatalf("Failed to create collection: %v", err)
			}
		}

		collections[collectionName] = col
	}

	//
	// Edge collection creation
	//

	edgeCollectionNames := []string{"release2sbom", "sbom2purl", "cve2purl"}

	for _, edgeCollectionName := range edgeCollectionNames {
		var col arangodb.Collection

		exists, _ = db.CollectionExists(ctx, edgeCollectionName)
		if exists {
			var options arangodb.GetCollectionOptions
			if col, err = db.GetCollection(ctx, edgeCollectionName, &options); err != nil {
				logger.Sugar().Fatalf("Failed to use edge collection: %v", err)
			}
		} else {
			edgeType := arangodb.CollectionTypeEdge
			if col, err = db.CreateCollectionV2(ctx, edgeCollectionName, &arangodb.CreateCollectionPropertiesV2{
				Type: &edgeType,
			}); err != nil {
				logger.Sugar().Fatalf("Failed to create edge collection: %v", err)
			}
		}

		collections[edgeCollectionName] = col
	}

	//
	// Index creation for document collections
	//

	idxList := []indexConfig{
		{Collection: "cve", IdxName: "package_name", IdxField: "affected[*].package.name"},
		{Collection: "cve", IdxName: "package_purl", IdxField: "affected[*].package.purl"},
		{Collection: "sbom", IdxName: "sbom_cid", IdxField: "cid"},
		{Collection: "purl", IdxName: "purl_idx", IdxField: "purl"},
		// Edge collection indexes for optimized traversals
		{Collection: "release2sbom", IdxName: "release2sbom_from", IdxField: "_from"},
		{Collection: "release2sbom", IdxName: "release2sbom_to", IdxField: "_to"},
		{Collection: "sbom2purl", IdxName: "sbom2purl_from", IdxField: "_from"},
		{Collection: "sbom2purl", IdxName: "sbom2purl_to", IdxField: "_to"},
		{Collection: "cve2purl", IdxName: "cve2purl_from", IdxField: "_from"},
		{Collection: "cve2purl", IdxName: "cve2purl_to", IdxField: "_to"},
	}

	for _, idx := range idxList {

		found := false

		if indexes, err := collections[idx.Collection].Indexes(ctx); err == nil {
			for _, index := range indexes {
				if idx.IdxName == index.Name {
					found = true
					break
				}
			}
		}

		if !found {
			// Define the index options
			indexOptions := arangodb.CreatePersistentIndexOptions{
				Unique: &False,
				Sparse: &False,
				Name:   idx.IdxName,
			}

			// Create the index
			_, _, err = collections[idx.Collection].EnsurePersistentIndex(ctx, []string{idx.IdxField}, &indexOptions)
			if err != nil {
				logger.Sugar().Fatalln("Error creating index:", err)
			}
		}
	}

	initDone = true

	dbConnection = DBConnection{
		Database:    db,
		Collections: collections,
	}

	return dbConnection
}
