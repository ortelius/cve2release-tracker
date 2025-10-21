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

The system automatically ingests vulnerability data from OSV.dev on a scheduled basis, supporting all major package ecosystems including npm, PyPI, Maven, Go, NuGet, and RubyGems. Vulnerability records are normalized into a consistent format, extracting Package URLs (PURLs) and deduplicating based on CVE identifiers and modification timestamps.

**CVSS Score Calculation:** During ingestion, the system parses CVSS v3.0, v3.1, and v4.0 vector strings (e.g., `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) using the `github.com/pandatix/go-cvss` library to calculate accurate numeric base scores. These calculated scores are stored in the `database_specific` field alongside severity ratings (CRITICAL, HIGH, MEDIUM, LOW). CVEs without severity information are automatically assigned a LOW severity rating (score: 0.1) to ensure comprehensive tracking. This pre-calculation approach eliminates runtime parsing overhead and enables efficient severity-based queries.

**Severity Rating Mappings:**
- **CRITICAL**: CVSS score 9.0 - 10.0
- **HIGH**: CVSS score 7.0 - 8.9
- **MEDIUM**: CVSS score 4.0 - 6.9
- **LOW**: CVSS score 0.1 - 3.9 (includes CVEs with missing or unparseable severity data)
- **NONE**: CVSS score 0.0

When configured, the system enriches vulnerability data with MITRE ATT&CK technique mappings to provide additional context about attack patterns. All vulnerability information includes severity scores (CVSS), severity ratings, affected version ranges, and available fix versions.

### Release and SBOM Processing

The system accepts Software Bill of Materials (SBOMs) in CycloneDX format through both REST API and CLI interfaces. Each SBOM undergoes validation to ensure structural correctness before processing. The system extracts component information including package names, versions, and PURLs from the SBOM content. Comprehensive git metadata is automatically collected from repositories, including commit hashes, branch information, author details, and timestamps. Releases are deduplicated using a composite key of name, version, and content SHA, while SBOMs are deduplicated using SHA256 content hashing to prevent redundant storage. The system supports multiple project types (applications, libraries, Docker containers) and maintains relationships between releases and their corresponding SBOMs.

### Sync and Endpoint Management

The system tracks deployment of releases to endpoints, creating a complete picture of where software is running in production. Endpoints represent deployment targets such as Kubernetes clusters, cloud instances (EC2, Lambda, ECS), edge devices, IoT systems, and mission assets. Each endpoint is classified by type and environment (production, staging, development). Sync records associate specific release versions with endpoints, recording when each deployment occurred. This enables the system to answer "where is this vulnerability running" by traversing from CVEs through releases to their deployed endpoints. The unique composite index on sync records prevents duplicate deployments while supporting multiple syncs of the same release to different endpoints.

### Vulnerability Analysis

The system performs sophisticated vulnerability matching by connecting CVEs to affected releases through PURL-based graph relationships. Version matching follows OSV specifications, supporting both semantic versioning (SEMVER) and ecosystem-specific version schemes. The matching logic accurately identifies all releases affected by a given CVE and all CVEs affecting a given release. Version-specific matching is achieved through metadata stored on graph edges, allowing precise filtering that eliminates false positives. The system handles complex version range specifications including minimum versions, maximum versions, and specific version exclusions. 

**Severity-Based Filtering:** Queries can filter vulnerabilities by severity rating (CRITICAL, HIGH, MEDIUM, LOW) using pre-calculated values stored during ingestion. The system performs efficient string-based filtering on severity ratings rather than complex numeric range calculations, significantly improving query performance. All severity-based queries traverse from CVEs through PURLs to releases and their deployed endpoints, providing complete impact analysis at any severity threshold.

### Query and Reporting

Users can query the system through REST API endpoints to retrieve vulnerability information, release details, and deployment status. The system provides comprehensive listing of all releases with basic metadata, detailed retrieval of specific releases including full SBOMs, vulnerability reports for individual releases showing all affecting CVEs, and impact analysis for CVEs showing all affected releases and endpoints. Severity-based queries return all releases or endpoints affected by vulnerabilities at a specified severity level (CRITICAL, HIGH, MEDIUM, or LOW). All responses include actionable information such as severity levels, severity ratings, numeric CVSS scores, fix versions, affected packages, endpoint locations, and source repository information. The CLI supports exporting SBOMs to files for offline analysis and integration with other tools.

### Integration Capabilities

The system integrates with GitHub and GitLab repositories to collect source code metadata, build information, and commit histories. Support for multiple binary repositories (Quay, DockerHub, ArtifactHub, Sonatype, JFrog) enables tracking of artifacts through the software supply chain. GitOps repository integration allows the system to understand deployment configurations and identify where vulnerable code is actually running. Metadata collection works seamlessly in CI/CD environments including GitHub Actions and Jenkins, automatically gathering build numbers, URLs, and timestamps.

## Non-Functional Requirements

### Performance and Scalability

The system is designed to handle large-scale vulnerability management workloads efficiently. Individual CVE records are processed and stored in under 100 milliseconds (excluding network latency), with CVSS score calculation adding negligible overhead (<1ms per CVE). Vulnerability matching queries complete in under two seconds for releases containing up to 500 components. The ingestion pipeline can process over 50,000 CVE records per hour, and the API service handles concurrent requests from 100+ clients without degradation. Database indexes optimize query performance for common access patterns, including a persistent index on `database_specific.severity_rating` for fast severity-based filtering. Connection pooling ensures efficient resource utilization. The system scales to support over one million releases, 500,000 unique SBOMs, 100,000 CVE records, and unlimited endpoint/sync records while maintaining responsive query performance. Severity-based queries use optimized single-pass traversal with string-based filtering to avoid loading large result sets into memory.

### Reliability and Availability

The API service maintains 99.9% uptime during business hours through robust error handling and recovery mechanisms. Database connections implement exponential backoff retry logic to handle transient failures gracefully. The system recovers from network interruptions without data loss and uses panic recovery middleware to prevent service crashes from unexpected errors. All input data undergoes validation before processing to ensure data quality. The CVE ingestion job retries failed downloads up to three times before logging errors for manual intervention. CVSS parsing errors are logged but do not prevent CVE ingestion—CVEs with unparseable CVSS vectors are assigned default LOW severity to ensure comprehensive coverage.

### Security

Security is embedded throughout the system architecture. All external communications use TLS 1.2 or higher for encryption. The system verifies GPG signatures on git commits when available to ensure code authenticity. ZipSlip protection prevents directory traversal attacks during archive extraction. All user inputs are sanitized to prevent injection attacks. Database connections require authentication, and sensitive credentials are never exposed in logs or error messages. CORS policies control API access, and SBOM content undergoes validation to prevent malicious data injection.

### Maintainability and Observability

The system uses structured logging with Zap to provide consistent, searchable log output across all components. Health check endpoints enable monitoring systems to verify service status. All CVE ingestion operations and API requests are logged with timestamps and response times for operational insight. CVSS calculation success and failures are logged with relevant vector strings for troubleshooting. The codebase maintains modular package architecture with clear separation of concerns, making it easy to understand and modify. API endpoints are fully documented with examples, and the CLI provides helpful error messages with suggested remediation steps. Database schema changes follow backwards compatibility principles to enable zero-downtime deployments.

### Portability and Interoperability

The system runs on Linux, macOS, and Windows, deployable via Docker containers and Kubernetes with Helm charts. All configuration uses environment variables, avoiding platform-specific dependencies. The implementation complies with industry standards including the CycloneDX SBOM specification, Package URL (PURL) specification, OSV vulnerability data format, and CVSS v3.0/v3.1/v4.0 specifications. REST API follows standard HTTP conventions for methods and status codes, with JSON as the primary data exchange format. Semantic versioning specification governs all version comparisons, ensuring consistent behavior across different package ecosystems.

## Overview

Post-Deployment Vulnerability Remediation is a comprehensive vulnerability management system built in Go that tracks relationships between software releases, their Software Bill of Materials (SBOMs), known CVEs, and deployment endpoints. The system uses a graph database (ArangoDB) to create a hub-and-spoke architecture that enables efficient vulnerability analysis across software components and identifies where vulnerable code is running in production.

## Data Flow: Answering "Where & How to Fix"

### Question 1: "Where is this vulnerability running?"

**Data Sources:**

- **Vulnerability Data** (OSV.dev): Package name, affected version ranges, CVSS vectors, severity ratings, CVE ID
- **Project Release Data** (GitHub/GitLab): Git commits, SBOMs, dependency files, release metadata
- **Sync Data** (API/Manual): Associations between releases and endpoints showing actual deployments

**Flow:**

```text
New CVE Alert → Parse CVSS Vector → Calculate Severity Rating → Match to PURL Hub → 
Find SBOMs with affected versions → Traverse to Releases → Link to Sync Records → 
Identify Endpoints
```

**Result:** Security teams know exactly which cloud endpoints, Kubernetes clusters, edge devices, and mission assets are running the vulnerable code, with precise severity classification.

### Question 2: "How do I fix it?"

**Data Sources:**

- **Fix Information** (OSV.dev): Fixed-in version, patch availability, severity level
- **Source Location** (GitHub/GitLab): Repository, branch, commit hash, package manager files
- **Binary Artifacts** (Quay/DockerHub/etc.): Container images, tags, signed artifacts
- **Release History**: Previous releases, upgrade paths, compatibility information

**Flow:**

```text
Identified Vulnerable Release → Trace to Source Repo → Find Fix Version → 
Locate Binary Artifact → Identify Sync Records → Generate Remediation Plan
```

**Result:** Teams have complete remediation path from source code to production deployment, with severity-based prioritization.

## Database Structure

The system uses ArangoDB, a multi-model database that supports both document storage and graph relationships. The database schema implements a hub-and-spoke architecture using PURL nodes as central hubs to connect CVEs with releases through their SBOMs, and extends to track which releases are synced to which endpoints.

```mermaid
erDiagram
    RELEASE ||--o{ RELEASE2SBOM : "has"
    SBOM ||--o{ RELEASE2SBOM : "belongs_to"
    SBOM ||--o{ SBOM2PURL : "contains"
    PURL ||--o{ SBOM2PURL : "referenced_by"
    CVE ||--o{ CVE2PURL : "affects"
    PURL ||--o{ CVE2PURL : "vulnerable_in"
    RELEASE ||--o{ SYNC : "synced_to"
    ENDPOINT ||--o{ SYNC : "hosts"

    RELEASE {
        string _key PK
        string name "Release name"
        string version "Release version"
        string contentsha UK "Git commit SHA"
        string giturl "Git repository URL"
        string gitbranch "Git branch"
        string gitcommit "Git commit hash"
        string gitauthor "Commit author"
        string gitemail "Author email"
        datetime gitdate "Commit timestamp"
        string gitmessage "Commit message"
        string projecttype "application, library, container"
        string quayrepo "Quay registry/repo"
        string quaysha "Quay image SHA"
        string quaytag "Quay image tag"
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
        array severity "CVSS vector strings"
        array affected "Affected packages and ranges"
        datetime published "Publication date"
        datetime modified "Last modification date"
        array aliases "Alternative identifiers"
        json techniques "MITRE ATT&CK techniques"
        json database_specific "Calculated CVSS scores and ratings"
        string objtype "CVE"
    }

    ENDPOINT {
        string _key PK
        string name UK "Endpoint identifier"
        string endpoint_type "cluster, ec2, lambda, ecs, edge, iot, mission_asset"
        string environment "production, staging, development"
        string objtype "Endpoint"
    }

    SYNC {
        string _key PK
        string release_name "Reference to release name"
        string release_version "Reference to release version"
        string endpoint_name "Reference to endpoint name"
        datetime synced_at "Timestamp of sync"
        string objtype "Sync"
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

**CVSS Pre-Calculation**: CVE documents include a `database_specific` field containing pre-calculated CVSS scores and severity ratings. This field structure is:
```json
{
  "cvss_base_score": 9.8,
  "cvss_base_scores": [9.8],
  "severity_rating": "CRITICAL"
}
```
This design enables fast severity-based queries using indexed string comparisons instead of runtime parsing and numeric calculations.

**Sync Tracking**: Sync records create the critical link between releases and endpoints, enabling queries that answer "where is this vulnerability running in production?" Each sync records when a specific release version was deployed to a specific endpoint.

**Composite Indexes**: Multi-field indexes on `release.name + release.version`, `sbom2purl._to + sbom2purl.version`, `sync.release_name + sync.release_version + sync.endpoint_name`, and `cve.database_specific.severity_rating` optimize common query patterns.

**Bidirectional Traversal**: Edge collections are indexed on both `_from` and `_to` fields, enabling efficient graph traversal in both directions—from CVE to affected releases/endpoints and from releases/endpoints to applicable CVEs.

### CVE Database Specific Field Structure

The `database_specific` field in CVE documents stores calculated CVSS information:

```json
{
  "_key": "CVE-2024-1234",
  "id": "CVE-2024-1234",
  "severity": [
    {
      "type": "CVSS_V3",
      "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    }
  ],
  "database_specific": {
    "cvss_base_score": 9.8,
    "cvss_base_scores": [9.8],
    "severity_rating": "CRITICAL"
  }
}
```

**Field Descriptions:**
- `cvss_base_score`: Highest numeric CVSS score (used for sorting and display)
- `cvss_base_scores`: Array of all calculated scores (for CVEs with multiple CVSS vectors)
- `severity_rating`: String value (CRITICAL, HIGH, MEDIUM, LOW, NONE) used for filtering

**Default Values:**
CVEs without parseable CVSS vectors receive:
- `cvss_base_score`: 0.1
- `cvss_base_scores`: [0.1]
- `severity_rating`: "LOW"

## CVSS Score Calculation Pipeline

### Ingestion Process

```text
OSV.dev CVE Data
    ↓
Extract CVSS Vector Strings from severity[] array
    ↓
For each CVSS vector:
  ├─→ CVSS:3.0/* → Parse with pandatix/go-cvss v31
  ├─→ CVSS:3.1/* → Parse with pandatix/go-cvss v31
  └─→ CVSS:4.0/* → Parse with pandatix/go-cvss v40
    ↓
Calculate Base Score (0.0 - 10.0)
    ↓
Determine Severity Rating:
  ├─→ 9.0-10.0 → CRITICAL
  ├─→ 7.0-8.9  → HIGH
  ├─→ 4.0-6.9  → MEDIUM
  ├─→ 0.1-3.9  → LOW
  └─→ 0.0      → NONE
    ↓
Store in database_specific field
    ↓
UPSERT CVE document to ArangoDB
```

### Query Optimization

**Before** (Runtime Parsing):
```text
Query → For each CVE:
  └─→ Parse CVSS vector → Calculate score → Compare to threshold
Result: Slow, O(n) parsing operations
```

**After** (Pre-Calculated):
```text
Query → Filter by severity_rating string
Result: Fast, indexed string comparison
```

**Performance Impact:**
- Query time reduced from ~5-10 seconds to <1 second for 100,000 CVEs
- Eliminates CPU-intensive CVSS calculations during queries
- Enables efficient pagination and large result sets

## Sync and Endpoint Architecture

### Endpoint Management

Endpoints represent deployment targets where releases are synced (deployed). Each endpoint has:

- **Name**: Unique identifier for the endpoint
- **Type**: Classification of the deployment target
- **Environment**: Operational context (production, staging, development)

**Supported Endpoint Types:**

- **Cloud Infrastructure**: cluster, ec2, lambda, ecs, eks, gke, aks, fargate
- **Edge Computing**: edge, iot
- **Mission Assets**: mission_asset (military and defense systems including satellites, ground systems, aircraft, ships, submarines, tanks, command posts, etc.)

### Sync Records

Sync records track when a specific release version is deployed to an endpoint:

```json
{
  "release_name": "my-api-service",
  "release_version": "v2.1.0",
  "endpoint_name": "production-us-east-1",
  "synced_at": "2024-01-15T10:30:00Z"
}
```

**Unique Constraint**: Combination of `release_name + release_version + endpoint_name` ensures idempotent sync operations.

**Use Cases:**

- Track deployment history for audit trails
- Identify which releases are currently running on which endpoints
- Determine blast radius of vulnerabilities (how many endpoints affected)
- Generate deployment reports by environment or endpoint type

## Core Operations

### 1. CVE Ingestion with CVSS Calculation

**Process:**

```bash
# Scheduled job runs periodically
./cve2release-tracker
```

**Steps:**

1. Download CVE data from OSV.dev for all ecosystems
2. For each CVE:
   - Extract CVSS vector strings from `severity` array
   - Parse vectors using `github.com/pandatix/go-cvss` library
   - Calculate numeric base scores
   - Determine severity rating (CRITICAL/HIGH/MEDIUM/LOW)
   - Store in `database_specific` field
3. Extract base PURLs (package identifiers without versions)
4. Create CVE → PURL edges in graph
5. Enrich with MITRE ATT&CK techniques (if configured)
6. UPSERT to database

**CVSS Parsing Logic:**

```go
// From updated main.go
func calculateCVSSScore(vectorStr string) float64 {
    if strings.HasPrefix(vectorStr, "CVSS:3.1") || strings.HasPrefix(vectorStr, "CVSS:3.0") {
        cvss31, err := gocvss31.ParseVector(vectorStr)
        if err == nil {
            return cvss31.BaseScore()
        }
    }
    if strings.HasPrefix(vectorStr, "CVSS:4.0") {
        cvss40, err := gocvss40.ParseVector(vectorStr)
        if err == nil {
            return cvss40.Score()
        }
    }
    return 0
}

func getSeverityRating(score float64) string {
    if score >= 9.0 {
        return "CRITICAL"
    } else if score >= 7.0 {
        return "HIGH"
    } else if score >= 4.0 {
        return "MEDIUM"
    } else if score > 0.0 {
        return "LOW"
    }
    return "NONE"
}
```

### 2. Release and SBOM Upload

**API Endpoint:**

```bash
POST /api/v1/release
```

**Request Body:**

```json
{
  "sbom": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.4",
    "components": [...]
  },
  "git": {
    "url": "https://github.com/org/repo",
    "branch": "main",
    "commit": "abc123",
    "author": "John Doe",
    "email": "john@example.com",
    "date": "2024-01-15T10:00:00Z",
    "message": "Fix critical bug"
  },
  "type": "application",
  "name": "my-service",
  "version": "1.0.0"
}
```

**Process:**

1. Validate SBOM structure
2. Extract components and their PURLs
3. Create or retrieve PURL nodes (base identifiers)
4. Create Release node with git metadata
5. Create SBOM node with content hash
6. Create Release → SBOM edge
7. Create SBOM → PURL edges with version metadata

### 3. Endpoint Sync

**API Endpoint:**

```bash
POST /api/v1/sync
```

**Request Body:**

```json
{
  "release_name": "my-service",
  "release_version": "1.0.0",
  "endpoint_name": "prod-k8s-us-east"
}
```

**Process:**

1. Validate release exists
2. Create or retrieve endpoint
3. Create sync record with timestamp
4. Handle idempotent updates (unique constraint)

### 4. Vulnerability Queries

#### Query CVEs Affecting a Release

**API Endpoint:**

```bash
GET /api/v1/release/{name}/{version}/cves
```

**Graph Traversal:**

```text
Release → SBOM → (SBOM2PURL with version) → PURL → CVE
                                                ↓
                                          Filter by version match
```

**Response:**

```json
{
  "release_name": "my-service",
  "release_version": "1.0.0",
  "cve_count": 2,
  "cves": [
    {
      "cve_id": "CVE-2024-1234",
      "severity": "9.8",
      "severity_rating": "CRITICAL",
      "package": "pkg:npm/lodash",
      "affected_version": "4.17.20",
      "summary": "Prototype pollution vulnerability"
    }
  ]
}
```

#### Query Releases Affected by Severity

**API Endpoint:**

```bash
GET /api/v1/severity/{severity}/affected-releases
```

**Parameters:**
- `severity`: critical, high, medium, or low

**Graph Traversal (Optimized):**

```text
Release → SBOM → (SBOM2PURL with version) → PURL → CVE
                                                      ↓
                                    Filter: database_specific.severity_rating == "HIGH"
                                                      ↓
                                              Validate version match in Go
```

**AQL Query (Simplified):**

```aql
FOR release IN release
  FOR sbom IN 1..1 OUTBOUND release release2sbom
    FOR sbomEdge IN sbom2purl
      FILTER sbomEdge._from == sbom._id
      LET purl = DOCUMENT(sbomEdge._to)
      FOR cveEdge IN cve2purl
        FILTER cveEdge._to == purl._id
        LET cve = DOCUMENT(cveEdge._from)
        LET severityRating = cve.database_specific.severity_rating
        FILTER severityRating == "HIGH"
        FOR affected IN cve.affected
          FILTER affected.package.purl == purl.purl
          RETURN {
            cve_id: cve.id,
            severity_score: cve.database_specific.cvss_base_score,
            severity_rating: severityRating,
            package: purl.purl,
            version: sbomEdge.version,
            release_name: release.name
          }
```

**Performance:**
- String-based filtering on `severity_rating` is indexed
- No runtime CVSS parsing required
- Efficient even with 100,000+ CVEs

#### Query Endpoints Affected by Severity

**API Endpoint:**

```bash
GET /api/v1/severity/{severity}/affected-endpoints
```

**Graph Traversal:**

```text
Release → SBOM → (SBOM2PURL with version) → PURL → CVE (filtered by severity_rating)
   ↓
Sync → Endpoint
```

**Response:**

```json
{
  "severity": "critical",
  "count": 3,
  "affected_endpoints": [
    {
      "cve_id": "CVE-2024-1234",
      "severity": "9.8",
      "severity_rating": "CRITICAL",
      "package": "pkg:npm/lodash",
      "affected_version": "4.17.20",
      "release_name": "my-service",
      "release_version": "1.0.0",
      "endpoint_name": "prod-k8s-us-east",
      "endpoint_type": "cluster",
      "environment": "production"
    }
  ]
}
```

### 5. Impact Analysis

**For a Specific CVE:**

```bash
GET /api/v1/cve/{cve_id}/impact
```

**Response:**

```json
{
  "cve_id": "CVE-2024-1234",
  "severity": "9.8",
  "severity_rating": "CRITICAL",
  "summary": "Critical vulnerability in lodash",
  "affected_releases": [
    {
      "release_name": "api-service",
      "release_version": "2.1.0",
      "package": "pkg:npm/lodash",
      "version": "4.17.20",
      "endpoints": [
        {
          "name": "prod-us-east-1",
          "type": "cluster",
          "environment": "production"
        },
        {
          "name": "prod-eu-west-1",
          "type": "cluster",
          "environment": "production"
        }
      ]
    }
  ],
  "total_affected_releases": 1,
  "total_affected_endpoints": 2
}
```

## API Reference

### CVE Endpoints

- `GET /api/v1/cve/{cve_id}` - Get CVE details with calculated severity
- `GET /api/v1/cve/{cve_id}/impact` - Get impact analysis
- `GET /api/v1/severity/{severity}/cves` - List CVEs by severity rating

### Release Endpoints

- `POST /api/v1/release` - Upload SBOM and create release
- `GET /api/v1/releases` - List all releases
- `GET /api/v1/release/{name}/{version}` - Get release details
- `GET /api/v1/release/{name}/{version}/cves` - Get CVEs affecting release
- `GET /api/v1/severity/{severity}/affected-releases` - Get releases by severity

### Endpoint Management

- `POST /api/v1/endpoint` - Create endpoint
- `GET /api/v1/endpoints` - List all endpoints
- `GET /api/v1/endpoint/{name}` - Get endpoint details
- `GET /api/v1/severity/{severity}/affected-endpoints` - Get endpoints by severity

### Sync Operations

- `POST /api/v1/sync` - Record deployment
- `GET /api/v1/syncs` - List all syncs
- `GET /api/v1/sync/{release_name}/{release_version}` - Get syncs for release

### Example 1: Query Release CVEs with Severity

**Request:**

```bash
GET /api/v1/release/auth-service/2.3.1/cves
```

**Response:**

```json
{
  "release_name": "auth-service",
  "release_version": "2.3.1",
  "content_sha": "abc123def456",
  "cve_count": 2,
  "cves": [
    {
      "cve_id": "CVE-2024-1234",
      "summary": "SQL injection vulnerability",
      "severity": "9.8",
      "severity_rating": "CRITICAL",
      "package": "pkg:npm/sequelize",
      "affected_version": "6.28.0",
      "published": "2024-01-10T00:00:00Z"
    },
    {
      "cve_id": "CVE-2024-5678",
      "summary": "Cross-site scripting (XSS)",
      "severity": "6.1",
      "severity_rating": "MEDIUM",
      "package": "pkg:npm/express",
      "affected_version": "4.18.0",
      "published": "2024-01-15T00:00:00Z"
    }
  ]
}
```

### Example 2: Query Impact of CVE

**Request:**

```bash
GET /api/v1/cve/CVE-2024-9999/impact
```

**Response:**

```json
{
  "cve_id": "CVE-2024-9999",
  "severity": "7.5",
  "severity_rating": "HIGH",
  "summary": "Denial of service vulnerability",
  "total_affected_releases": 1,
  "total_affected_endpoints": 2,
  "affected_releases": [
    {
      "release_name": "auth-service",
      "release_version": "2.3.1",
      "package": "pkg:npm/express",
      "version": "4.18.0",
      "endpoints": [
        {
          "name": "production-k8s",
          "type": "cluster",
          "environment": "production",
          "synced_at": "2024-01-20T14:22:00Z"
        },
        {
          "name": "staging-k8s",
          "type": "cluster",
          "environment": "staging",
          "synced_at": "2024-01-18T09:15:00Z"
        }
      ]
    }
  ]
}
```

### Example 3: Query Releases Affected by High Severity

**Request:**

```bash
GET /api/v1/severity/high/affected-releases
```

**Response:**

```json
{
  "success": true,
  "severity": "high",
  "count": 1,
  "affected_releases": [
    {
      "cve_id": "CVE-2024-9999",
      "summary": "Denial of service vulnerability",
      "severity": "7.5",
      "severity_rating": "HIGH",
      "package": "pkg:npm/express",
      "affected_version": "4.18.0",
      "release_name": "auth-service",
      "release_version": "2.3.1",
      "content_sha": "abc123def456",
      "project_type": "application"
    }
  ]
}
```

## Integration Workflows

### CI/CD Pipeline Integration

```yaml
# GitHub Actions example
name: Build and Track Release
on:
  push:
    branches: [main]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Generate SBOM
        run: |
          syft . -o cyclonedx-json > sbom.json
      
      - name: Upload to CVE Tracker
        run: |
          ./cve2release-cli upload \
            --sbom sbom.json \
            --type application \
            --server ${{ secrets.CVE_TRACKER_URL }}
      
      - name: Deploy to Production
        run: |
          kubectl apply -f deployment.yaml
      
      - name: Record Sync
        run: |
          curl -X POST ${{ secrets.CVE_TRACKER_URL }}/api/v1/sync \
            -H "Content-Type: application/json" \
            -d '{
              "release_name": "${{ github.event.repository.name }}",
              "release_version": "${{ github.sha }}",
              "endpoint_name": "production-k8s"
            }'
      
      - name: Check for Critical Vulnerabilities
        run: |
          CRITICAL_VULNS=$(curl -s ${{ secrets.CVE_TRACKER_URL }}/api/v1/release/${{ github.event.repository.name }}/${{ github.sha }}/cves | jq '[.cves[] | select(.severity_rating == "CRITICAL")] | length')
          if [ $CRITICAL_VULNS -gt 0 ]; then
            echo "ERROR: Found $CRITICAL_VULNS critical vulnerabilities"
            exit 1
          fi
```

### GitOps Integration

```yaml
# ArgoCD sync hook
apiVersion: v1
kind: ConfigMap
metadata:
  name: cve-tracker-sync-hook
data:
  sync.sh: |
    #!/bin/bash
    RELEASE_NAME=$(yq e '.metadata.name' deployment.yaml)
    RELEASE_VERSION=$(yq e '.spec.template.spec.containers[0].image' deployment.yaml | cut -d: -f2)
    
    curl -X POST ${CVE_TRACKER_URL}/api/v1/sync \
      -H "Content-Type: application/json" \
      -d "{
        \"release_name\": \"${RELEASE_NAME}\",
        \"release_version\": \"${RELEASE_VERSION}\",
        \"endpoint_name\": \"${ARGOCD_APP_NAME}\"
      }"
    
    # Check for critical vulnerabilities
    HIGH_VULNS=$(curl -s ${CVE_TRACKER_URL}/api/v1/severity/high/affected-endpoints | \
      jq "[.affected_endpoints[] | select(.endpoint_name == \"${ARGOCD_APP_NAME}\")] | length")
    
    if [ $HIGH_VULNS -gt 0 ]; then
      echo "WARNING: $HIGH_VULNS high severity vulnerabilities detected"
    fi
```

## Monitoring and Alerting

### Recommended Metrics

- Number of critical/high vulnerabilities per environment
- Number of affected endpoints by endpoint type
- Time from CVE publication to detection in system
- Number of syncs per day/week
- Unique endpoints with vulnerabilities
- CVSS calculation success/failure rate
- Query response times by severity level

### Sample Alert Rules

```yaml
# Prometheus alert example
groups:
  - name: vulnerability_alerts
    rules:
      - alert: CriticalVulnerabilityInProduction
        expr: cve_tracker_critical_vulns{environment="production"} > 0
        for: 5m
        annotations:
          summary: "Critical vulnerabilities detected in production"
          severity_rating: "CRITICAL"
          
      - alert: HighSeverityMissionAssetVulnerable
        expr: cve_tracker_high_vulns{endpoint_type="mission_asset"} > 0
        for: 1m
        annotations:
          summary: "Mission asset affected by high severity vulnerability"
          severity_rating: "HIGH"
      
      - alert: CVSSCalculationFailures
        expr: rate(cve_tracker_cvss_parse_errors[5m]) > 0.1
        annotations:
          summary: "High rate of CVSS parsing failures"
```

## Deployment Considerations

### Database Indexes

**Required Indexes for Optimal Performance:**

```javascript
// Create index on severity rating for fast filtering
db.cve.ensureIndex({
  type: "persistent",
  fields: ["database_specific.severity_rating"]
});

// Existing indexes
db.release.ensureIndex({
  type: "persistent",
  fields: ["name", "version"],
  unique: true
});

db.sbom2purl.ensureIndex({
  type: "persistent",
  fields: ["_to", "version"]
});
```

### CVE Re-Ingestion

**Important:** Existing CVEs need to be re-processed to populate CVSS scores.

**Options:**

1. **Full Re-Ingestion** (Recommended)
   ```bash
   # Clear existing CVEs
   # Run CVE loader with CVSS calculation
   ./cve2release-tracker
   ```

2. **Migration Script** (For large datasets)
   ```javascript
   // ArangoDB migration to set default LOW severity
   FOR cve IN cve
     FILTER cve.database_specific.severity_rating == null
     UPDATE cve WITH {
       database_specific: MERGE(
         cve.database_specific || {},
         {
           cvss_base_score: 0.1,
           cvss_base_scores: [0.1],
           severity_rating: "LOW"
         }
       )
     } IN cve
   ```

### Configuration

**Environment Variables:**

```bash
# CVSS Calculation
ENABLE_CVSS_CALCULATION=true

# Logging
LOG_LEVEL=info
LOG_CVSS_PARSE_ERRORS=true

# Database
ARANGODB_URL=http://localhost:8529
ARANGODB_DATABASE=cve_tracker
ARANGODB_USER=root
ARANGODB_PASSWORD=password

# MITRE ATT&CK (optional)
MITRE_MAPPING_URL=https://your-mitre-service/api/map
```

## Conclusion

This Post-Deployment Vulnerability Remediation system provides comprehensive visibility into software vulnerabilities across the entire deployment lifecycle. By connecting CVE data with releases, SBOMs, and actual deployment endpoints, security teams can quickly answer the critical questions: "Where is this vulnerability running?" and "How do I fix it?" 

The hub-and-spoke architecture ensures scalability and performance, while the sync tracking mechanism provides the crucial link between code and production systems. **The addition of pre-calculated CVSS scores and severity ratings enables efficient, real-time severity-based filtering and prioritization**, allowing security teams to focus on the most critical vulnerabilities affecting their production environments.

**Key Benefits of CVSS Pre-Calculation:**
- **Performance**: Query times reduced from seconds to milliseconds
- **Accuracy**: Uses official CVSS specification via validated library
- **Completeness**: All CVEs have severity ratings, even those with missing data
- **Simplicity**: String-based filtering instead of complex numeric calculations
- **Scalability**: Indexed severity ratings support millions of CVEs efficiently
