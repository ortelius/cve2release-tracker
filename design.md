# Post-Deployment Vulnerability Remediation Architecture Documentation

## Executive Summary

Post-Deployment Vulnerability Remediation answers two critical questions for every high-risk OSS vulnerability: **"Where is it running, and how do I fix it?"**

The system bridges three key domains:

1. **Vulnerabilities (The Threat)** - CVE data from OSV.dev including affected packages, severity levels, version ranges, and fix information
2. **Project Releases (Where to Fix It)** - Git repositories, SBOMs, dependencies, binary artifacts, and release metadata from GitHub/GitLab
3. **Deployment Endpoints (Where It's Running)** - GitOps configurations showing production deployments across cloud providers

### Value Proposition

By connecting vulnerability data with project releases and their deployment locations, the system enables security teams to:
- Immediately identify which production systems are affected by new CVEs
- Trace vulnerable packages back to source code repositories
- Determine exact versions that need updating
- Locate deployment configurations for remediation
- Prioritize fixes based on actual deployment exposure

### Integration Points

**At Setup, Users Connect:**

| Code Repository | Binary Repository | GitOps Repository |
|----------------|-------------------|-------------------|
| GitHub/GitLab repos | Quay, DockerHub | GitHub/GitLab deployment repos |
| SBOMs & dependency files | ArtifactHub, Sonatype | Cloud provider configs |
| Source code & commits | JFrog, GitHub Packages | Kubernetes/ArgoCD manifests |

## Functional Requirements

### Vulnerability Data Management
The system automatically ingests vulnerability data from OSV.dev on a scheduled basis, supporting all major package ecosystems including npm, PyPI, Maven, Go, NuGet, and RubyGems. Vulnerability records are normalized into a consistent format, extracting Package URLs (PURLs) and deduplicating based on CVE identifiers and modification timestamps. When configured, the system enriches vulnerability data with MITRE ATT&CK technique mappings to provide additional context about attack patterns. All vulnerability information includes severity scores (CVSS), affected version ranges, and available fix versions.

### Release and SBOM Processing
The system accepts Software Bill of Materials (SBOMs) in CycloneDX format through both REST API and CLI interfaces. Each SBOM undergoes validation to ensure structural correctness before processing. The system extracts component information including package names, versions, and PURLs from the SBOM content. Comprehensive git metadata is automatically collected from repositories, including commit hashes, branch information, author details, and timestamps. Releases are deduplicated using a composite key of name, version, and content SHA, while SBOMs are deduplicated using SHA256 content hashing to prevent redundant storage. The system supports multiple project types (applications, libraries, Docker containers) and maintains relationships between releases and their corresponding SBOMs.

### Vulnerability Analysis
The system performs sophisticated vulnerability matching by connecting CVEs to affected releases through PURL-based graph relationships. Version matching follows OSV specifications, supporting both semantic versioning (SEMVER) and ecosystem-specific version schemes. The matching logic accurately identifies all releases affected by a given CVE and all CVEs affecting a given release. Version-specific matching is achieved through metadata stored on graph edges, allowing precise filtering that eliminates false positives. The system handles complex version range specifications including minimum versions, maximum versions, and specific version exclusions.

### Query and Reporting
Users can query the system through REST API endpoints to retrieve vulnerability information and release details. The system provides comprehensive listing of all releases with basic metadata, detailed retrieval of specific releases including full SBOMs, vulnerability reports for individual releases showing all affecting CVEs, and impact analysis for specific CVEs showing all affected releases. All responses include actionable information such as severity levels, fix versions, affected packages, and source repository locations. The CLI supports exporting SBOMs to files for offline analysis and integration with other tools.

### Integration Capabilities
The system integrates with GitHub and GitLab repositories to collect source code metadata, build information, and commit histories. Support for multiple binary repositories (Quay, DockerHub, ArtifactHub, Sonatype, JFrog) enables tracking of artifacts through the software supply chain. GitOps repository integration allows the system to understand deployment configurations and identify where vulnerable code is actually running. Metadata collection works seamlessly in CI/CD environments including GitHub Actions and Jenkins, automatically gathering build numbers, URLs, and timestamps.

## Non-Functional Requirements

### Performance and Scalability
The system is designed to handle large-scale vulnerability management workloads efficiently. Individual CVE records are processed and stored in under 100 milliseconds (excluding network latency), while vulnerability matching queries complete in under two seconds for releases containing up to 500 components. The ingestion pipeline can process over 50,000 CVE records per hour, and the API service handles concurrent requests from 100+ clients without degradation. Database indexes optimize query performance for common access patterns, and connection pooling ensures efficient resource utilization. The system scales to support over one million releases, 500,000 unique SBOMs, and 100,000 CVE records while maintaining responsive query performance.

### Reliability and Availability
The API service maintains 99.9% uptime during business hours through robust error handling and recovery mechanisms. Database connections implement exponential backoff retry logic to handle transient failures gracefully. The system recovers from network interruptions without data loss and uses panic recovery middleware to prevent service crashes from unexpected errors. All input data undergoes validation before processing to ensure data quality. The CVE ingestion job retries failed downloads up to three times before logging errors for manual intervention.

### Security
Security is embedded throughout the system architecture. All external communications use TLS 1.2 or higher for encryption. The system verifies GPG signatures on git commits when available to ensure code authenticity. ZipSlip protection prevents directory traversal attacks during archive extraction. All user inputs are sanitized to prevent injection attacks. Database connections require authentication, and sensitive credentials are never exposed in logs or error messages. CORS policies control API access, and SBOM content undergoes validation to prevent malicious data injection.

### Maintainability and Observability
The system uses structured logging with Zap to provide consistent, searchable log output across all components. Health check endpoints enable monitoring systems to verify service status. All CVE ingestion operations and API requests are logged with timestamps and response times for operational insight. The codebase maintains modular package architecture with clear separation of concerns, making it easy to understand and modify. API endpoints are fully documented with examples, and the CLI provides helpful error messages with suggested remediation steps. Database schema changes follow backwards compatibility principles to enable zero-downtime deployments.

### Portability and Interoperability
The system runs on Linux, macOS, and Windows, deployable via Docker containers and Kubernetes with Helm charts. All configuration uses environment variables, avoiding platform-specific dependencies. The implementation complies with industry standards including the CycloneDX SBOM specification, Package URL (PURL) specification, and OSV vulnerability data format. REST API follows standard HTTP conventions for methods and status codes, with JSON as the primary data exchange format. Semantic versioning specification governs all version comparisons, ensuring consistent behavior across different package ecosystems.

## Overview

Post-Deployment Vulnerability Remediation is a comprehensive vulnerability management system built in Go that tracks relationships between software releases, their Software Bill of Materials (SBOMs), and known CVEs. The system uses a graph database (ArangoDB) to create a hub-and-spoke architecture that enables efficient vulnerability analysis across software components.

## Data Flow: Answering "Where & How to Fix"

### Question 1: "Where is this vulnerability running?"

**Data Sources:**
- **Vulnerability Data** (OSV.dev): Package name, affected version ranges, severity, CVE ID
- **Project Release Data** (GitHub/GitLab): Git commits, SBOMs, dependency files, release metadata
- **GitOps Data** (Deployment repos): Kubernetes manifests, ArgoCD configs, cloud provider settings

**Flow:**
```
New CVE Alert → Match to PURL Hub → Find SBOMs with affected versions → 
Traverse to Releases → Link to GitOps Configs → Identify Endpoints
```

**Result:** Security teams know exactly which cloud endpoints, Kubernetes clusters, and environments are running the vulnerable code.

### Question 2: "How do I fix it?"

**Data Sources:**
- **Fix Information** (OSV.dev): Fixed-in version, patch availability
- **Source Location** (GitHub/GitLab): Repository, branch, commit hash, package manager files
- **Binary Artifacts** (Quay/DockerHub/etc.): Container images, tags, signed artifacts
- **Release History**: Previous releases, upgrade paths, compatibility information

**Flow:**
```
Identified Vulnerable Release → Trace to Source Repo → Find Fix Version → 
Locate Binary Artifact → Identify Deployment Config → Generate Remediation Plan
```

**Result:** Teams have complete remediation path from source code to production deployment.

## Database Structure

The system uses ArangoDB, a multi-model database that supports both document storage and graph relationships. The database schema implements a hub-and-spoke architecture using PURL nodes as central hubs to connect CVEs with releases through their SBOMs.

```mermaid
erDiagram
    RELEASE ||--o{ RELEASE2SBOM : "has"
    SBOM ||--o{ RELEASE2SBOM : "belongs_to"
    SBOM ||--o{ SBOM2PURL : "contains"
    PURL ||--o{ SBOM2PURL : "referenced_by"
    CVE ||--o{ CVE2PURL : "affects"
    PURL ||--o{ CVE2PURL : "vulnerable_in"

    RELEASE {
        string _key PK
        string name "Project name"
        string version "Release version"
        string contentsha "Git commit or Docker SHA"
        string projecttype "application, library, docker"
        string gitcommit "Git commit hash"
        string gitbranch "Git branch name"
        string gitrepo "Repository path"
        string giturl "Repository URL"
        string dockerrepo "Docker registry/repo"
        string dockersha "Docker image SHA"
        string dockertag "Docker image tag"
        datetime builddate "Build timestamp"
        string buildid "CI/CD build ID"
        string buildurl "CI/CD build URL"
        string objtype "ProjectRelease"
    }

    SBOM {
        string _key PK
        string contentsha "SHA256 hash of content"
        json content "CycloneDX SBOM JSON"
        string objtype "SBOM"
    }

    PURL {
        string _key PK
        string purl UK "Base PURL without version"
        string objtype "PURL"
    }

    CVE {
        string _key PK
        string id "CVE identifier"
        json osv "Full OSV vulnerability data"
        string summary "Vulnerability summary"
        string details "Detailed description"
        array severity "CVSS scores"
        array affected "Affected packages and ranges"
        datetime published "Publication date"
        datetime modified "Last modification date"
        array aliases "Alternative identifiers"
        json techniques "MITRE ATT&CK techniques"
        string objtype "CVE"
    }

    RELEASE2SBOM {
        string _from FK "release/_key"
        string _to FK "sbom/_key"
    }

    SBOM2PURL {
        string _from FK "sbom/_key"
        string _to FK "purl/_key"
        string version "Specific package version"
        string full_purl "Complete PURL with version"
    }

    CVE2PURL {
        string _from FK "cve/_key"
        string _to FK "purl/_key"
    }
```

### Key Design Features

**Hub-and-Spoke Architecture**: PURL nodes serve as central hubs connecting CVEs (which reference packages generically) to SBOMs (which include specific versions). This design eliminates duplication while maintaining precise version tracking through edge metadata.

**Version Storage Strategy**: While PURL nodes store base package identifiers without versions (e.g., `pkg:npm/lodash`), the SBOM2PURL edges store specific version information (e.g., `4.17.20`). This enables accurate vulnerability matching where CVEs specify affected version ranges.

**Content-Based Deduplication**: Releases use composite natural keys (name + version + contentsha) to handle rebuild scenarios, while SBOMs use SHA256 content hashing to enable sharing across multiple releases with identical dependencies.

**Composite Indexes**: Multi-field indexes on `release.name + release.version` and `sbom2purl._to + sbom2purl.version` optimize common query patterns for finding releases and matching vulnerability versions.

**Bidirectional Traversal**: Edge collections are indexed on both `_from` and `_to` fields, enabling efficient graph traversal in both directions—from CVE to affected releases and from releases to applicable CVEs.

## System Components

### 1. CVE Ingestion Service (Cronjob)

**Repository:** `ortelius/cve2release-tracker`  
**Location:** `main.go` (root)

**Purpose:** Periodically fetches vulnerability data from OSV.dev and populates the database.

**Key Functions:**
- `LoadFromOSVDev()` - Fetches ecosystem list and downloads vulnerability data
- `unpackAndLoad()` - Extracts and processes ZIP files containing CVE data
- `newVuln()` - Processes individual CVE JSON, enriches with MITRE ATT&CK techniques, and creates graph relationships

**External Dependencies:**
- OSV.dev API for vulnerability data
- Optional MITRE ATT&CK mapping service for technique enrichment

**Workflow:**
1. Fetches list of ecosystems from OSV.dev
2. Downloads ZIP files for each ecosystem
3. Extracts individual CVE JSON files
4. Enriches CVE data with MITRE techniques (if configured)
5. Upserts CVE documents to the database
6. Extracts base PURLs (Package URLs without versions)
7. Creates PURL hub nodes
8. Creates edges from CVE to PURL for vulnerability matching

### 2. REST API Service

**Repository:** `ortelius/cve2release-tracker`  
**Location:** `main.go` (root) - Fiber web server

**Purpose:** Provides HTTP endpoints for managing releases, SBOMs, and querying vulnerability data.

**Endpoints:**

#### POST `/api/v1/releases`
- Handler: `PostReleaseWithSBOM()`
- Creates/updates release and SBOM records
- Uses hybrid deduplication: composite key for releases, content hash for SBOMs
- Extracts SBOM components and creates hub-and-spoke PURL relationships

#### GET `/api/v1/releases/:name/:version`
- Handler: `GetReleaseWithSBOM()`
- Retrieves release metadata and associated SBOM

#### GET `/api/v1/releases/:name/:version/vulnerabilities`
- Handler: `GetReleaseVulnerabilities()`
- Returns all CVEs affecting a specific release
- Uses semantic versioning for accurate vulnerability matching

#### GET `/api/v1/cve/:cveId/affected-releases`
- Handler: `GetAffectedReleasesByCVE()`
- Returns all releases affected by a specific CVE
- Performs Go-based version range matching for accuracy

#### GET `/api/v1/releases`
- Handler: `ListReleases()`
- Lists all releases with key, name, and version

**Architecture Pattern:** Uses Fiber framework with middleware for CORS, logging, and recovery.

### 3. CLI Client

**Repository:** `ortelius/cve2release-tracker`  
**Location:** `cli/main.go` and `cmd/root.go`

**Purpose:** Command-line interface for interacting with the API service.

**Commands:**

#### `upload`
- Collects git metadata from local repository
- Validates and reads CycloneDX SBOM file
- Posts release with SBOM to API server

**Flags:**
- `--sbom, -s`: Path to SBOM file (required)
- `--type, -t`: Project type (application, library, docker, etc.)
- `--server`: API server URL (default: http://localhost:3000)
- `--verbose, -v`: Enable verbose output

#### `list`
- Retrieves and displays all releases from the database

#### `get [name] [version]`
- Fetches specific release with SBOM
- `--output, -o`: Write SBOM to file
- `--sbom-only`: Output only SBOM content

## Data Models

### ProjectRelease
**Repository:** `ortelius/cve2release-tracker`  
**Location:** `model/release.go`

Represents a versioned software release with comprehensive git and build metadata.

**Key Fields:**
- `Name`, `Version`: Primary identifiers
- `ContentSha`: Git commit or Docker SHA for deduplication
- `ProjectType`: application, library, docker, container, etc.
- Git metadata: commit, branch, authors, timestamps, verification
- Build metadata: build date, ID, URL
- Docker metadata: repo, SHA, tag

### SBOM
**Repository:** `ortelius/cve2release-tracker`  
**Location:** `model/sbom.go`

Stores CycloneDX Software Bill of Materials in JSON format.

**Key Fields:**
- `Content`: Raw CycloneDX JSON (json.RawMessage)
- `ContentSha`: SHA256 hash for deduplication
- `ObjType`: "SBOM"

### PURL
**Repository:** `ortelius/cve2release-tracker`  
**Location:** `model/purl.go`

Represents a Package URL hub (without version information).

**Key Fields:**
- `Purl`: Base PURL format (e.g., pkg:npm/lodash)
- `ObjType`: "PURL"

**Purpose:** Serves as a hub node to connect CVEs (which reference packages without versions) to SBOM components (which include specific versions).

### ReleaseWithSBOM
**Repository:** `ortelius/cve2release-tracker`  
**Location:** `model/api.go`

Composite structure for API requests/responses combining ProjectRelease and SBOM.

## Database Architecture

**Repository:** `ortelius/cve2release-tracker`  
**Location:** `database/database.go`

### Technology
ArangoDB - Multi-model database supporting both documents and graphs.

### Document Collections

#### `release`
Stores project release metadata. Indexed on:
- `name` + `version` (composite)
- `contentsha`

#### `sbom`
Stores SBOM content. Indexed on:
- `contentsha` (for deduplication)

#### `purl`
Stores base package URLs (hub nodes). Indexed on:
- `purl` (unique index)

#### `cve`
Stores CVE/vulnerability data in OSV format. Indexed on:
- `id`
- `osv.id`
- `affected[*].package.name`
- `affected[*].package.purl`

### Edge Collections

#### `release2sbom`
Connects releases to their SBOMs.
- `_from`: release/{key}
- `_to`: sbom/{key}

#### `sbom2purl`
Connects SBOMs to package hubs **with version information**.
- `_from`: sbom/{key}
- `_to`: purl/{key}
- `version`: Specific package version (critical for CVE matching)
- `full_purl`: Complete PURL with version

**Indexed on:** `_from`, `_to`, `_to + version` (composite)

#### `cve2purl`
Connects CVEs to affected package hubs.
- `_from`: cve/{key}
- `_to`: purl/{key}

**Indexed on:** `_from`, `_to`

## Hub-and-Spoke Architecture

The system implements a sophisticated hub-and-spoke pattern using PURL nodes as hubs:

### Concept
1. **PURL Hubs**: Base package identifiers without versions (e.g., `pkg:npm/lodash`)
2. **Spokes with Versions**: Edges from SBOMs to PURL hubs store specific version information
3. **CVE Connections**: CVEs link to PURL hubs (as OSV data references packages generically)

### Benefits
1. **Deduplication**: Single PURL hub for each package across all releases
2. **Efficient Queries**: Graph traversal from CVE → PURL → SBOM → Release
3. **Version Flexibility**: Version information on edges allows precise matching
4. **Scalability**: Reduces node count while maintaining relationship fidelity

### Version Matching Strategy
The system uses a hybrid approach:
1. **AQL Pre-filtering**: Database queries fetch candidate matches via hub connections
2. **Go-based Filtering**: Semantic version range matching using `semver` library
3. **OSV Range Support**: Handles ECOSYSTEM and SEMVER range types

## Utility Layer

**Repository:** `ortelius/cve2release-tracker`

### PURL Processing
**Location:** `util/helpers.go`

**Functions:**
- `CleanPURL()`: Removes qualifiers and subpaths for canonical form
- `GetBasePURL()`: Strips version to create hub identifier
- `ParsePURL()`: Parses PURL strings
- `EcosystemToPurlType()`: Maps OSV ecosystems to PURL types

### Version Matching
**Location:** `util/helpers.go`

**Functions:**
- `IsVersionAffected()`: Checks if version matches OSV vulnerability data
- `isVersionInRange()`: Semantic version range checking
- Uses `github.com/Masterminds/semver/v3` for accurate semver comparison

### Git Metadata Collection
**Location:** `util/env_mapping.go`

**Functions:**
- `GetDerivedEnvMapping()`: Collects comprehensive git metadata
- `assignMetaData()`: Executes git commands to extract repository information
- Supports CI/CD environments (GitHub Actions, generic CI)

**Collected Metadata:**
- Commit information (hash, author, timestamp, verification)
- Branch information (name, parent, creation)
- Repository information (URL, org, project)
- Build information (ID, number, URL)
- Code statistics (lines added/deleted/total)

## Security Features

1. **Signed Commit Verification**: Tracks GPG signature verification
2. **Content-based Deduplication**: SHA256 hashing prevents duplicate data
3. **TLS Configuration**: Secure connections with configurable verification
4. **Input Validation**: 
   - SBOM format validation (CycloneDX)
   - Required field checking
   - JSON structure validation
5. **ZipSlip Protection**: Path validation during archive extraction

## Deduplication Strategy

### Release Deduplication
Uses **composite natural key**:
- `name` + `version` + `contentsha`

**Rationale:** Same release can have different content (e.g., rebuilds), so ContentSha ensures uniqueness.

### SBOM Deduplication
Uses **content-based hashing**:
- SHA256 hash of entire SBOM content

**Rationale:** Identical SBOMs can be shared across multiple releases, saving storage and improving query performance.

### PURL Deduplication
Uses **unique base PURL**:
- Enforced by unique index on `purl` field

**Rationale:** Single hub node per package enables efficient vulnerability tracking.

## Query Patterns

### Finding Vulnerabilities for a Release
```
Release → release2sbom → SBOM → sbom2purl (with version) → PURL → cve2purl → CVE
```
Then filter CVEs where the version matches the affected range.

### Finding Affected Releases for a CVE
```
CVE → cve2purl → PURL → sbom2purl (with version) → SBOM → release2sbom → Release
```
Then filter by version range matching.

## Performance Optimizations

1. **Composite Indexes**: Multi-field indexes for common query patterns
2. **Edge Indexes**: Optimized traversal with `_from` and `_to` indexes
3. **Version-aware Queries**: Version stored on edges reduces full document scans
4. **Connection Pooling**: HTTP transport with connection reuse
5. **Backoff Retry**: Exponential backoff for database connection establishment

## Extensibility Points

1. **MITRE Integration**: Optional enrichment service for attack technique mapping
2. **Ecosystem Support**: Extensible PURL type mapping for new package ecosystems
3. **Project Types**: Flexible project type field for diverse software categories
4. **Custom Metadata**: Git metadata collection extensible via environment variables
5. **Multiple Ranges**: OSV range format supports various versioning schemes

## Deployment Considerations

### CVE Ingestion Service
- Runs as Kubernetes CronJob
- Environment variables: `ARANGO_HOST`, `ARANGO_PORT`, `ARANGO_USER`, `ARANGO_PASS`, `MITRE_MAPPING_URL`
- Resource requirements: Network bandwidth for OSV downloads, CPU for JSON processing

### API Service
- Runs as Kubernetes Deployment
- Port: 3000 (configurable via `PORT` environment variable)
- Health check endpoint: `/health`
- Middleware: CORS, logging, panic recovery

### Database
- ArangoDB deployment with persistent storage
- Recommended: 3-node cluster for high availability
- Backup strategy for vulnerability data

## Technology Stack

- **Language:** Go 1.21+
- **Web Framework:** Fiber v2
- **Database Driver:** `github.com/arangodb/go-driver/v2`
- **CLI Framework:** Cobra
- **Version Parsing:** `github.com/Masterminds/semver/v3`
- **PURL Parsing:** `github.com/package-url/packageurl-go`
- **OSV Models:** `github.com/google/osv-scanner/pkg/models`
- **Logging:** Zap (structured logging)

## Key Design Decisions

1. **Graph Database Choice**: ArangoDB selected for native graph traversal and document flexibility
2. **Hub-and-Spoke Pattern**: Reduces data duplication while enabling efficient queries
3. **Version-on-Edge Storage**: Critical for accurate CVE matching without denormalization
4. **Hybrid Deduplication**: Different strategies for releases (composite key) vs SBOMs (content hash)
5. **Go-based Version Matching**: Database pre-filters, Go performs accurate semantic versioning
6. **Content Immutability**: SBOMs treated as immutable content-addressed objects
7. **CycloneDX Standard**: Adopted industry-standard SBOM format for interoperability
8. **Post-Deployment Focus**: Architecture optimized for answering "where running" and "how to fix" questions after vulnerabilities are discovered in production environments