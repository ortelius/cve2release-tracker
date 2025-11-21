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

| Code Repository          | Binary Repository      | GitOps Repository              |
|--------------------------|------------------------|--------------------------------|
| GitHub/GitLab repos      | Quay, DockerHub        | GitHub/GitLab deployment repos |
| SBOMs & dependency files | ArtifactHub, Sonatype  | Cloud provider configs         |
| Source code & commits    | JFrog, GitHub Packages | Kubernetes/ArgoCD manifests    |

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

Users can query the system through GraphQL API endpoints to retrieve vulnerability information, release details, and deployment status. The system provides comprehensive listing of all releases with basic metadata, detailed retrieval of specific releases including full SBOMs, vulnerability reports for individual releases showing all affecting CVEs, and impact analysis for CVEs showing all affected releases and endpoints. Severity-based queries return all releases or endpoints affected by vulnerabilities at a specified severity level (CRITICAL, HIGH, MEDIUM, or LOW). All responses include actionable information such as severity levels, severity ratings, numeric CVSS scores, fix versions, affected packages, endpoint locations, and source repository information. The CLI supports exporting SBOMs to files for offline analysis and integration with other tools.

### Integration Capabilities

The system integrates with GitHub and GitLab repositories to collect source code metadata, build information, and commit histories. Support for multiple binary repositories (Quay, DockerHub, ArtifactHub, Sonatype, JFrog) enables tracking of artifacts through the software supply chain. GitOps repository integration allows the system to understand deployment configurations and identify where vulnerable code is actually running. Metadata collection works seamlessly in CI/CD environments including GitHub Actions and Jenkins, automatically gathering build numbers, URLs, and timestamps.

## Non-Functional Requirements

### Performance and Scalability

The system is designed to handle large-scale vulnerability management workloads with optimal end-user experience. All API endpoints maintain an end-user response time of less than 3 seconds under normal load conditions, including:

- Release upload with SBOM processing
- Vulnerability query for releases with up to 500 components
- Severity-based filtering across large datasets (affected-releases, affected-endpoints)
- Release-to-endpoint impact analysis with graph traversal
- List operations for releases, endpoints, and syncs

Individual CVE records are processed and stored during ingestion with CVSS score calculation adding negligible overhead (<1ms per CVE). The ingestion pipeline can process over 50,000 CVE records per hour. The API service handles concurrent requests from 100+ clients without degradation. Database indexes optimize query performance for common access patterns, including a persistent index on `database_specific.severity_rating` for fast severity-based filtering. Connection pooling ensures efficient resource utilization.

The system scales to support over one million releases, 500,000 unique SBOMs, 100,000 CVE records, and unlimited endpoint/sync records while maintaining responsive query performance. Severity-based queries use optimized single-pass traversal with string-based filtering to avoid loading large result sets into memory.

**Deployment Strategy:** Rolling updates are used for all system deployments to ensure zero-downtime operation and eliminate the need for maintenance windows. The rolling update strategy progressively replaces instances of the previous version with the new version, maintaining service availability throughout the deployment process.

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

```mermaid
flowchart LR
    A[New CVE Alert] --> B[Parse CVSS Vector]
    B --> C[Calculate Severity Rating]
    C --> D[Match to PURL Hub]
    D --> E[Find SBOMs with<br/>affected versions]
    E --> F[Traverse to Releases]
    F --> G[Link to Sync Records]
    G --> H[Identify Endpoints]
    
    style A fill:#ff6b6b
    style H fill:#51cf66
```

**Result:** Security teams know exactly which cloud endpoints, Kubernetes clusters, edge devices, and mission assets are running the vulnerable code, with precise severity classification.

### Question 2: "How do I fix it?"

**Data Sources:**

- **Fix Information** (OSV.dev): Fixed-in version, patch availability, severity level
- **Source Location** (GitHub/GitLab): Repository, branch, commit hash, package manager files
- **Binary Artifacts** (Quay/DockerHub/etc.): Container images, tags, signed artifacts
- **Release History**: Previous releases, upgrade paths, compatibility information

**Flow:**

```mermaid
flowchart LR
    A[Identified Vulnerable Release] --> B[Trace to Source Repo]
    B --> C[Find Fix Version]
    C --> D[Locate Binary Artifact]
    D --> E[Identify Sync Records]
    E --> F[Generate Remediation Plan]
    
    style A fill:#ff6b6b
    style F fill:#51cf66
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

## Hub-and-Spoke Architecture: Visual Guide

This section provides visual representations of the hub-and-spoke architecture to make it easier to understand how vulnerabilities, packages, and releases are connected. See [Hub and Spoke Guide](hub_and_spoke_guide.md) for detailed explanation and examples.

### Architecture Overview Diagram

```mermaid
flowchart TB
    subgraph VulnDomain["VULNERABILITY DOMAIN (Spokes)"]
        CVEDocs["CVE DOCUMENTS<br/>CVE-2024-1234 (lodash)<br/>CVE-2024-5678 (express)<br/>CVE-2024-9999 (axios)"]
    end
    
    subgraph PURLHub["PURL HUB LAYER (Central Hub Nodes)"]
        PURLNodes["pkg:npm/lodash<br/>pkg:npm/express<br/>pkg:npm/axios<br/>pkg:pypi/django<br/>pkg:maven/log4j"]
    end
    
    subgraph SBOMDomain["SBOM DOCUMENTS"]
        SBOMDocs["SBOM-A (500 components)<br/>SBOM-B (350 components)<br/>SBOM-C (420 components)"]
    end
    
    subgraph ReleaseDomain["PROJECT RELEASES (Spokes)"]
        Releases["frontend-app v1.0<br/>api-service v2.1<br/>worker-service v3.0"]
    end
    
    subgraph EndpointDomain["DEPLOYMENT ENDPOINTS (Spokes)"]
        Endpoints["prod-k8s-us-east (cluster)<br/>prod-lambda-us-west<br/>edge-device-001"]
    end
    
    CVEDocs -->|CVE2PURL Edges| PURLHub
    PURLHub -->|SBOM2PURL Edges<br/>with version metadata| SBOMDomain
    SBOMDomain -->|RELEASE2SBOM Edges| ReleaseDomain
    ReleaseDomain -->|SYNC Records| EndpointDomain
    
    style VulnDomain fill:#ffe0e0
    style PURLHub fill:#e0f0ff
    style SBOMDomain fill:#e0ffe0
    style ReleaseDomain fill:#fff0e0
    style EndpointDomain fill:#f0e0ff
```

### Detailed Hub Example: Single Package

This diagram shows how multiple CVEs and multiple SBOMs connect through a single PURL hub:

```mermaid
flowchart TB
    subgraph CVELayer["CVE LAYER - Vulnerabilities"]
        CVE1["CVE-2024-1234<br/>'Prototype Pollution'<br/>affects: 4.17.0-4.17.20"]
        CVE2["CVE-2024-5678<br/>'ReDoS Attack'<br/>affects: 4.0.0-4.17.19"]
    end
    
    subgraph Hub["PURL HUB"]
        PURL["pkg:npm/lodash<br/>(version-free)<br/>Single hub node for<br/>ALL lodash references"]
    end
    
    subgraph SBOMLayer["SBOM LAYER - Releases"]
        SBOM1["SBOM-001<br/>├─ lodash: 4.17.20<br/>├─ express: 4.18.0<br/>└─ axios: 1.3.0"]
        SBOM2["SBOM-002<br/>├─ lodash: 4.17.19<br/>├─ react: 18.0.0<br/>└─ redux: 4.2.0"]
    end
    
    subgraph ReleaseLayer["RELEASES"]
        REL1["frontend-app v1.0"]
        REL2["api-service v2.1"]
    end
    
    subgraph EndpointLayer["ENDPOINTS"]
        EP1["prod-k8s-us-east"]
        EP2["prod-lambda"]
    end
    
    subgraph Matching["VULNERABILITY MATCHING LOGIC"]
        Match1["CVE-2024-1234 affects 4.17.0-4.17.20<br/>✓ Matches SBOM-001 (version 4.17.20)<br/>✗ Skips SBOM-002 (version 4.17.19)"]
        Match2["CVE-2024-5678 affects 4.0.0-4.17.19<br/>✗ Skips SBOM-001 (version 4.17.20)<br/>✓ Matches SBOM-002 (version 4.17.19)"]
    end
    
    CVE1 & CVE2 -->|CVE2PURL| PURL
    PURL -->|SBOM2PURL<br/>version: 4.17.20<br/>on edge metadata| SBOM1
    PURL -->|SBOM2PURL<br/>version: 4.17.19<br/>on edge metadata| SBOM2
    SBOM1 -->|RELEASE2SBOM| REL1
    SBOM2 -->|RELEASE2SBOM| REL2
    REL1 -->|SYNC| EP1
    REL2 -->|SYNC| EP2
    
    style CVE1 fill:#ff6b6b
    style CVE2 fill:#ff6b6b
    style PURL fill:#4dabf7
    style SBOM1 fill:#69db7c
    style SBOM2 fill:#69db7c
    style Matching fill:#fff3bf
```

### Query Flow Visualization

This shows how a query traverses the graph from CVE to deployed endpoint:

```mermaid
flowchart TB
    Start["<b>QUERY:</b> Which production endpoints<br/>are running CVE-2024-1234?"] --> Step1
    
    Step1["<b>STEP 1:</b> Start at CVE Document"] --> CVE
    CVE["CVE-2024-1234<br/>├─ id: CVE-2024-1234<br/>├─ summary: Prototype Pollution<br/>├─ severity_rating: CRITICAL<br/>
    └─ affected:<br/>    └─ package: pkg:npm/lodash<br/>       versions: 4.17.0-4.17.20"]
    
    CVE -->|CVE2PURL Edge| Step2["<b>STEP 2:</b> Traverse to PURL Hub"]
    Step2 --> PURL["PURL Hub: pkg:npm/lodash<br/>(Unique hub for all lodash refs)"]
    
    PURL -->|SBOM2PURL Edges<br/>with version metadata| Step3["<b>STEP 3:</b> Find Connected SBOMs"]
    
    Step3 --> SBOMs
    subgraph SBOMs["SBOMs Found"]
        SBOM_A["SBOM-A<br/>v4.17.20"]
        SBOM_B["SBOM-B<br/>v4.17.19"]
        SBOM_C["SBOM-C<br/>v4.17.21"]
    end
    
    SBOMs --> Step4["<b>STEP 4:</b> Filter by Version Range<br/>(in Go code)"]
    
    Step4 --> Filters
    subgraph Filters["Version Filtering"]
        Filter_A["✓ MATCHES<br/>(4.17.20)"]
        Filter_B["✗ TOO OLD<br/>(4.17.19)"]
        Filter_C["✗ TOO NEW<br/>(4.17.21)"]
    end
    
    Filter_A -->|RELEASE2SBOM Edge| Step5["<b>STEP 5:</b> Traverse to Releases"]
    Step5 --> REL["Release<br/>frontend-app v1.0"]
    
    REL -->|SYNC Record| Step6["<b>STEP 6:</b> Find Deployment Endpoints"]
    Step6 --> EP["Endpoint<br/>prod-k8s-us-east<br/>type: cluster<br/>env: production"]
    
    EP --> Result["<b>RESULT:</b><br/>frontend-app v1.0 on prod-k8s-us-east<br/>is VULNERABLE to CVE-2024-1234"]
    
    style Start fill:#e3f2fd
    style CVE fill:#ff6b6b
    style PURL fill:#4dabf7
    style Filter_A fill:#51cf66
    style Filter_B fill:#ffd43b
    style Filter_C fill:#ffd43b
    style EP fill:#cc5de8
    style Result fill:#ff6b6b
```

### Edge Metadata: The Key to Version Tracking

```mermaid
flowchart TB
    subgraph Wrong["❌ APPROACH 1: Version in PURL Node (Rejected)"]
        W1["pkg:npm/lodash@4.17.20"]
        W2["pkg:npm/lodash@4.17.19"]
        W3["pkg:npm/lodash@4.17.21"]
        W4["... (thousands of version-specific nodes)"]
        
        WProblems["<b>PROBLEMS:</b><br/>- Massive node duplication (1 node per version)<br/>- CVE edges must connect to ALL version nodes<br/>
        - Harder to query 'all versions of lodash'<br/>- More storage, slower queries"]
    end
    
    subgraph Right["✓ APPROACH 2: Version in Edge Metadata (Implemented)"]
        Hub["PURL Hub<br/>pkg:npm/lodash<br/>Single node for package"]
        
        Hub -->|SBOM2PURL Edge #1<br/>version: 4.17.20| S1["SBOM-A"]
        Hub -->|SBOM2PURL Edge #2<br/>version: 4.17.19| S2["SBOM-B"]
        Hub -->|SBOM2PURL Edge #3<br/>version: 4.17.21| S3["SBOM-C"]
        Hub -->|SBOM2PURL Edge #4<br/>version: 4.17.18| S4["SBOM-D"]
        
        RBenefits["<b>BENEFITS:</b><br/>✓ One PURL node per package (minimal nodes)<br/>✓ CVE connects to one hub (simple edges)<br/>
        ✓ Version filtering done on edges (fast)<br/>✓ Easy to query 'all versions' or 'specific version'"]
    end
    
    style Wrong fill:#ffe0e0
    style Right fill:#e0ffe0
    style Hub fill:#4dabf7
    style WProblems fill:#ff6b6b
    style RBenefits fill:#51cf66
```

### Scale Comparison: With vs. Without Hub Architecture

```mermaid
flowchart TB
    subgraph Scenario["<b>SCENARIO:</b> 1,000 CVEs affecting lodash across 10,000 SBOMs"]
    end
    
    subgraph Without["WITHOUT HUB (Direct CVE → SBOM edges)"]
        WC1["CVE-0001"] -.->|10,000 edges| WS1["SBOM-01"]
        WC1 -.-> WS2["SBOM-02"]
        WC2["CVE-0002"] -.-> WS1
        WC2 -.-> WS2
        WC3["..."] -.-> WS3["..."]
        WC4["CVE-1000"] -.-> WS4["SBOM-10K"]
        
        WStats["<b>Total Edges:</b> 10,000,000<br/><b>Edge Growth:</b> O(N × M) - Exponential<br/><b>Storage:</b> ~1GB for edges alone<br/>
        <b>Query Time:</b> Seconds"]
    end
    
    subgraph With["WITH HUB (CVE → PURL → SBOM)"]
        HC1["CVE-0001"] --> HHub["PURL HUB<br/>lodash"]
        HC2["CVE-0002"] --> HHub
        HC3["..."] --> HHub
        HC4["CVE-1000"] --> HHub
        
        HHub --> HS1["SBOM-01"]
        HHub --> HS2["SBOM-02"]
        HHub --> HS3["..."]
        HHub --> HS4["SBOM-10K"]
        
        HStats["<b>Total Edges:</b> 11,000<br/><b>Edge Growth:</b> O(N + M) - Linear<br/><b>Storage:</b> ~10MB for edges<br/>
        <b>Query Time:</b> Milliseconds"]
    end
    
    Scenario --> Without
    Scenario --> With
    
    Without -.->|"<b>REDUCTION:</b><br/>99.89% fewer edges!"| With
    
    style Scenario fill:#e3f2fd
    style Without fill:#ffe0e0
    style With fill:#e0ffe0
    style HHub fill:#4dabf7
    style WStats fill:#ff6b6b
    style HStats fill:#51cf66
```

### Real-World Data Flow Example

```mermaid
flowchart TB
    Step1["<b>1. CVE PUBLICATION (OSV.dev)</b><br/>CVE-2024-1234 published for lodash<br/>Affected: 4.17.0 ≤ version ≤ 4.17.20<br/>
    CVSS: 9.8 (CRITICAL)"]
    
    Step1 -->|Ingestion Pipeline| Step2
    
    Step2["<b>2. CVE INGESTION</b><br/>Parse OSV data<br/>Extract PURL: pkg:npm/lodash (base form)<br/>Calculate CVSS score: 9.8<br/>
    Determine severity_rating: CRITICAL<br/>Create CVE document in ArangoDB<br/>Create CVE2PURL edge to lodash hub"]
    
    Step2 -->|Graph Connection| Step3
    
    Step3["<b>3. PURL HUB</b><br/>Node: pkg:npm/lodash<br/>Connected to:<br/>  ← 15 CVEs (via CVE2PURL edges)<br/>
      → 1,247 SBOMs (via SBOM2PURL edges)"]
    
    Step3 -->|SBOM References| Step4
    
    Step4["<b>4. EXISTING SBOMs</b><br/>SBOM-A: frontend-app → lodash@4.17.20 ✓ VULNERABLE<br/>
    SBOM-B: api-service → lodash@4.17.19 ✓ VULNERABLE<br/>SBOM-C: worker-svc → lodash@4.17.21 ✗ SAFE (too new)<br/>
    SBOM-D: auth-service → lodash@4.18.0 ✗ SAFE (too new)"]
    
    Step4 -->|Version Match Filter| Step5
    
    Step5["<b>5. AFFECTED RELEASES</b><br/>frontend-app v1.0 (via SBOM-A)<br/>api-service v2.1 (via SBOM-B)"]
    
    Step5 -->|SYNC Records| Step6
    
    Step6["<b>6. DEPLOYED ENDPOINTS</b><br/>frontend-app v1.0:<br/>  ├─ prod-k8s-us-east (cluster, production)<br/>
      └─ staging-k8s (cluster, staging)<br/>api-service v2.1:<br/>  ├─ prod-lambda-us-west (lambda, production)<br/>
      └─ prod-ecs-eu-west (ecs, production)"]
    
    Step6 --> Result
    
    Result["<b>FINAL RESULT:</b><br/>4 production endpoints running vulnerable code:<br/>1. prod-k8s-us-east (frontend-app v1.0)<br/>
    2. prod-lambda-us-west (api-service v2.1)<br/>3. prod-ecs-eu-west (api-service v2.1)<br/><br/><b>Security team can now:</b><br/>
    → Create tickets for remediation<br/>→ Apply patches to these specific endpoints<br/>→ Monitor for exploitation attempts<br/>
    → Generate compliance reports"]
    
    style Step1 fill:#ff6b6b
    style Step2 fill:#ffd43b
    style Step3 fill:#4dabf7
    style Step4 fill:#69db7c
    style Step5 fill:#ffd43b
    style Step6 fill:#cc5de8
    style Result fill:#ff6b6b
```

### Key Design Features

#### Hub-and-Spoke Architecture (Detailed)

The system implements a **hub-and-spoke architecture** using PURL (Package URL) nodes as central hubs to efficiently connect vulnerability data with software releases through their SBOMs. This architectural pattern is commonly used in graph databases to optimize queries and reduce data duplication.

**Core Concept:**

Instead of creating direct connections between every CVE and every SBOM component (which would result in exponential edge growth), we use PURL nodes as intermediary hubs. Think of it like an airport hub system: rather than having direct flights between every pair of cities, major airlines route through hub airports, significantly reducing the number of routes needed.

**How It Works:**

```mermaid
flowchart LR
    subgraph VulnDomain["VULNERABILITY DOMAIN"]
        CVE1[CVE-2024-1234]
        CVE2[CVE-2024-5678]
        CVE3[CVE-2024-9999]
    end
    
    subgraph HubLayer["HUB LAYER"]
        Hub["PURL Hub<br/>pkg:npm/lodash<br/>(Base Package)"]
    end
    
    subgraph ReleaseDomain["RELEASE DOMAIN"]
        SBOM1["SBOM-A<br/>(v4.17.20)"]
        SBOM2["SBOM-B<br/>(v4.17.19)"]
        SBOM3["SBOM-C<br/>(v4.17.21)"]
    end
    
    CVE1 & CVE2 & CVE3 -->|Multiple CVEs<br/>affecting same package| Hub
    Hub -->|Single hub node<br/>for all lodash CVEs| SBOM1 & SBOM2 & SBOM3
    
    Note1["Multiple SBOMs using<br/>different versions"]
    
    style VulnDomain fill:#ffe0e0
    style HubLayer fill:#4dabf7
    style ReleaseDomain fill:#e0ffe0
```

**The Three-Layer Architecture:**

1. **CVE Layer (Spoke)**: Vulnerability nodes containing CVE data
   - Each CVE references affected packages generically (without versions)
   - Links to PURL hubs via `CVE2PURL` edges
   - Example: CVE-2024-1234 affects "lodash" (any vulnerable version)

2. **PURL Hub Layer (Hub)**: Package identifier nodes
   - Each PURL node represents a unique package (without version)
   - Stored as base PURL: `pkg:npm/lodash` (no version component)
   - Acts as a connection point between CVEs and SBOMs
   - Dramatically reduces edge count: N CVEs + M SBOMs = N+M edges (not N×M)

3. **SBOM Layer (Spoke)**: Software Bill of Materials with version data
   - Each SBOM contains specific package versions
   - Links to PURL hubs via `SBOM2PURL` edges
   - Edge metadata stores the specific version: `4.17.20`
   - Multiple SBOMs can reference the same PURL hub with different versions

**Mathematical Advantage:**

- **Without Hub Architecture**: Direct CVE → SBOM connections
  - For 1,000 CVEs affecting 10,000 SBOMs: up to 10,000,000 edges
  - Exponential growth: O(N × M)

- **With Hub Architecture**: CVE → PURL → SBOM connections
  - For same scenario: 1,000 CVE→PURL edges + 10,000 PURL→SBOM edges = 11,000 edges
  - Linear growth: O(N + M)

**Query Flow Example:**

When asking "Which releases are affected by CVE-2024-1234?", the system:

```mermaid
flowchart TB
    Start["1. Start: CVE-2024-1234 document"] --> Trav1
    Trav1["2. Traverse: CVE2PURL edge<br/>to find PURL hub"] --> Result1
    Result1["→ Result: pkg:npm/lodash"] --> Trav2
    Trav2["3. Traverse: SBOM2PURL edges<br/>FROM the PURL hub"] --> Result2
    Result2["→ Result: All SBOMs using lodash<br/>(with version metadata on edges)"] --> Filter
    Filter["4. Filter: Check version ranges<br/>in Go code"] --> Result3
    Result3["→ Keep only: versions 4.17.0 - 4.17.20<br/>(vulnerable range)"] --> Trav3
    Trav3["5. Traverse: RELEASE2SBOM edges<br/>to find releases"] --> Result4
    Result4["→ Result: All releases using<br/>vulnerable lodash versions"] --> Trav4
    Trav4["6. Traverse: SYNC edges<br/>to find endpoints"] --> Result5
    Result5["→ Result: Production endpoints<br/>running vulnerable code"]
    
    style Start fill:#e3f2fd
    style Result1 fill:#4dabf7
    style Result2 fill:#69db7c
    style Result3 fill:#ffd43b
    style Result4 fill:#fff3bf
    style Result5 fill:#cc5de8
```

**Version Matching Strategy:**

The hub-and-spoke design separates version-agnostic package identification from version-specific matching:

- **PURL Hub**: Stores `pkg:npm/lodash` (version-agnostic identifier)
- **Edge Metadata**: Stores `version: "4.17.20"` on SBOM2PURL edge
- **CVE Data**: Contains version ranges in `affected` field
- **Runtime Matching**: Go code compares edge version against CVE ranges

This separation enables:

- ✅ Efficient storage (one PURL node per package, not per version)
- ✅ Fast hub identification (CVE → PURL lookup is instant)
- ✅ Precise version filtering (metadata on edges, not on nodes)
- ✅ Flexible version semantics (npm, PyPI, Maven, etc. all supported)

**Deduplication Benefits:**

```mermaid
flowchart TB
    subgraph Scenario["Scenario: 3 releases all use the same dependencies"]
    end
    
    subgraph Without["WITHOUT HUB ARCHITECTURE"]
        RA["Release-A"] --> D1["500 dependency nodes"]
        RB["Release-B"] --> D2["500 dependency nodes<br/>(DUPLICATED)"]
        RC["Release-C"] --> D3["500 dependency nodes<br/>(DUPLICATED)"]
        
        WStats["Total: 1,500 nodes<br/>+ CVE edges to each<br/>= massive duplication"]
    end
    
    subgraph With["WITH HUB ARCHITECTURE"]
        RA2["Release-A"] --> SBOM["SBOM-X"]
        RB2["Release-B"] --> SBOM
        RC2["Release-C"] --> SBOM
        SBOM --> HubSet["500 PURL hubs"]
        CVEs["CVEs"] --> HubSet
        
        WStats2["Total: 1 SBOM + 500 PURLs (reused)<br/>= 501 nodes"]
    end
    
    Scenario --> Without
    Scenario --> With
    
    style Without fill:#ffe0e0
    style With fill:#e0ffe0
    style WStats fill:#ff6b6b
    style WStats2 fill:#51cf66
```

**Real-World Example:**

Consider a vulnerability in `lodash@4.17.20`:

```mermaid
flowchart TB
    CVE["CVE-2024-1234<br/>'Prototype Pollution in lodash'"]
    
    CVE -->|CVE2PURL edge| Hub["PURL Hub: pkg:npm/lodash"]
    
    Hub -->|SBOM2PURL<br/>version: 4.17.20| SBOM1
    Hub -->|SBOM2PURL<br/>version: 4.17.19| SBOM2
    Hub -->|SBOM2PURL<br/>version: 4.17.21| SBOM3
    Hub -->|SBOM2PURL<br/>version: 4.17.20| SBOM4
    
    SBOM1["SBOM-A"] --> REL1["Release:<br/>frontend-app v1.0"]
    SBOM2["SBOM-B"] --> REL2["Release:<br/>api-service v2.1"]
    SBOM3["SBOM-C"] --> REL3["Release:<br/>worker-service v3.0"]
    SBOM4["SBOM-D"] --> REL4["Release:<br/>auth-service v1.5"]
    
    Result["<b>Query Result:</b><br/>frontend-app v1.0 and auth-service v1.5<br/>are vulnerable<br/>
    (both use 4.17.20, which falls<br/>in CVE's affected range)"]
    
    style CVE fill:#ff6b6b
    style Hub fill:#4dabf7
    style SBOM1 fill:#51cf66
    style SBOM2 fill:#69db7c
    style SBOM3 fill:#69db7c
    style SBOM4 fill:#51cf66
    style REL1 fill:#ff6b6b
    style REL4 fill:#ff6b6b
    style Result fill:#fff3bf
```

**References & Standards:**

This hub-and-spoke pattern follows established graph database practices:

1. **ArangoDB Graph Pattern**: Uses named edge collections for typed relationships
   - Documentation: <https://docs.arangodb.com/stable/graphs/>
   - Our implementation: `CVE2PURL`, `SBOM2PURL`, `RELEASE2SBOM` edge collections

2. **Package URL (PURL) Specification**: Standardized package identifiers
   - Spec: <https://github.com/package-url/purl-spec>
   - Format: `scheme:type/namespace/name@version?qualifiers#subpath`
   - Our hubs use: `pkg:npm/lodash` (base form without version/qualifiers)

3. **OSV Schema**: Open Source Vulnerability format
   - Spec: <https://ossf.github.io/osv-schema/>
   - CVE data includes affected packages as PURLs
   - Our edges connect OSV PURLs to SBOM component PURLs

4. **CycloneDX SBOM**: Industry standard for software bill of materials
   - Spec: <https://cyclonedx.org/specification/overview/>
   - Components include PURL identifiers with versions
   - Our SBOM2PURL edges extract these PURLs

5. **Graph Database Hub Pattern**: Documented in graph theory literature
   - Neo4j: "Intermediate Node Pattern" for reducing fan-out
   - TigerGraph: "Hub Vertices" for centralized connections
   - Our adaptation: PURL nodes as package-level hubs

**Performance Characteristics:**

| Operation              | Complexity   | Example Time             |
|------------------------|--------------|--------------------------|
| CVE → PURL lookup      | O(1)         | <1ms                     |
| PURL → SBOMs traversal | O(log N)     | <10ms for 10K SBOMs      |
| Version filtering      | O(M)         | <50ms for 500 components |
| Full CVE impact query  | O(log N + M) | <1s for 100K CVEs        |

**Alternative Architectures Considered:**

1. **Direct CVE-to-SBOM edges**: Rejected due to exponential edge growth
2. **Version-specific PURL nodes**: Rejected due to excessive node duplication
3. **Denormalized CVE data in SBOMs**: Rejected due to update complexity
4. **Separate graphs per ecosystem**: Rejected due to cross-ecosystem queries

The hub-and-spoke architecture provides the optimal balance of:

- Query performance (indexed hub lookups)
- Storage efficiency (minimal duplication)
- Version flexibility (edge metadata)
- Query simplicity (bidirectional traversal)

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

```mermaid
flowchart TB
    Start["OSV.dev CVE Data"] --> Extract
    Extract["Extract CVSS Vector Strings<br/>from severity[] array"] --> Parse
    
    subgraph Parse["Parse Each CVSS Vector"]
        V30["CVSS:3.0/*<br/>→ Parse with pandatix/go-cvss v31"]
        V31["CVSS:3.1/*<br/>→ Parse with pandatix/go-cvss v31"]
        V40["CVSS:4.0/*<br/>→ Parse with pandatix/go-cvss v40"]
    end
    
    Parse --> Calc["Calculate Base Score (0.0 - 10.0)"]
    
    Calc --> Det["Determine Severity Rating"]
    
    subgraph Det
        C["9.0-10.0 → CRITICAL"]
        H["7.0-8.9 → HIGH"]
        M["4.0-6.9 → MEDIUM"]
        L["0.1-3.9 → LOW"]
        N["0.0 → NONE"]
    end
    
    Det --> Store["Store in database_specific field"]
    Store --> Upsert["UPSERT CVE document to ArangoDB"]
    
    style Start fill:#e3f2fd
    style Parse fill:#fff3bf
    style Det fill:#ffd43b
    style Upsert fill:#51cf66
```

### Query Optimization

```mermaid
flowchart LR
    subgraph Before["BEFORE (Runtime Parsing)"]
        B1["Query"] --> B2["For each CVE:<br/>Parse CVSS vector"]
        B2 --> B3["Calculate score"]
        B3 --> B4["Compare to threshold"]
        B5["Result: Slow,<br/>O(n) parsing operations"]
    end
    
    subgraph After["AFTER (Pre-Calculated)"]
        A1["Query"] --> A2["Filter by severity_rating string"]
        A3["Result: Fast,<br/>indexed string comparison"]
    end
    
    Before -.->|Performance Impact:<br/>~5-10s → <1s for 100K CVEs| After
    
    style Before fill:#ffe0e0
    style After fill:#e0ffe0
    style B5 fill:#ff6b6b
    style A3 fill:#51cf66
```

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

```mermaid
flowchart TB
    Start["CVE Ingestion Job Starts"] --> Download
    Download["1. Download CVE data from OSV.dev<br/>for all ecosystems"] --> ForEach
    
    ForEach["2. For each CVE:"] --> Extract
    Extract["Extract CVSS vector strings<br/>from severity array"] --> Parse
    Parse["Parse vectors using<br/>github.com/pandatix/go-cvss library"] --> Calculate
    Calculate["Calculate numeric base scores"] --> Determine
    Determine["Determine severity rating<br/>(CRITICAL/HIGH/MEDIUM/LOW)"] --> Store
    Store["Store in database_specific field"] --> PURLs
    
    PURLs["3. Extract base PURLs<br/>(package identifiers without versions)"] --> Edges
    Edges["4. Create CVE → PURL edges in graph"] --> Enrich
    Enrich["5. Enrich with MITRE ATT&CK techniques<br/>(if configured)"] --> Upsert
    Upsert["6. UPSERT to database"]
    
    style Start fill:#e3f2fd
    style Parse fill:#fff3bf
    style Determine fill:#ffd43b
    style Upsert fill:#51cf66
```

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
POST /api/v1/releases
```

**Request Body (ReleaseWithSBOM):**

```json
{
  "name": "my-service",
  "version": "1.0.0",
  "projecttype": "application",
  "contentsha": "abc123def456",
  "giturl": "https://github.com/org/repo",
  "gitbranch": "main",
  "gitcommit": "abc123",
  "gitcommittimestamp": "2024-01-15T10:00:00Z",
  "sbom": {
    "content": {
      "bomFormat": "CycloneDX",
      "specVersion": "1.4",
      "components": [...]
    }
  }
}
```

**Process:**

```mermaid
flowchart TB
    Start["API Request Received"] --> Validate
    Validate["1. Validate SBOM structure<br/>(must be CycloneDX format)"] --> Extract
    Extract["2. Extract components and their PURLs"] --> CreatePURL
    CreatePURL["3. Create or retrieve PURL nodes<br/>(base identifiers)"] --> CreateRelease
    CreateRelease["4. Create Release node<br/>with git metadata"] --> CreateSBOM
    CreateSBOM["5. Create SBOM node<br/>with content hash"] --> EdgeRS
    EdgeRS["6. Create Release → SBOM edge"] --> EdgeSP
    EdgeSP["7. Create SBOM → PURL edges<br/>with version metadata"] --> Response
    Response["8. Return success response"]
    
    style Start fill:#e3f2fd
    style Validate fill:#fff3bf
    style Response fill:#51cf66
```

**Response:**

```json
{
  "success": true,
  "message": "Release created successfully",
  "release_key": "12345"
}
```

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

```mermaid
flowchart TB
    Start["Sync Request Received"] --> Validate
    Validate["1. Validate release exists"] --> CreateEndpoint
    CreateEndpoint["2. Create or retrieve endpoint"] --> CreateSync
    CreateSync["3. Create sync record with timestamp"] --> Handle
    Handle["4. Handle idempotent updates<br/>(unique constraint)"] --> Response
    Response["5. Return success response"]
    
    style Start fill:#e3f2fd
    style Response fill:#51cf66
```

### 4. Vulnerability Queries

#### Query CVEs Affecting a Release

**GraphQL Query:**

```graphql
query GetRelease($name: String!, $version: String!) {
  release(name: $name, version: $version) {
    name
    version
    vulnerabilities {
      cve_id
      severity_score
      severity_rating
      package
      affected_version
      summary
    }
  }
}
```

**Graph Traversal:**

```mermaid
flowchart LR
    Release["Release"] --> SBOM["SBOM"]
    SBOM -->|SBOM2PURL<br/>with version| PURL["PURL"]
    PURL --> CVE["CVE"]
    CVE --> Filter["Filter by<br/>version match"]
    
    style Release fill:#fff0e0
    style SBOM fill:#69db7c
    style PURL fill:#4dabf7
    style CVE fill:#ff6b6b
    style Filter fill:#ffd43b
```

**Response:**

```json
{
  "data": {
    "release": {
      "name": "my-service",
      "version": "1.0.0",
      "vulnerabilities": [
        {
          "cve_id": "CVE-2024-1234",
          "severity_score": 9.8,
          "severity_rating": "CRITICAL",
          "package": "pkg:npm/lodash",
          "affected_version": "4.17.20",
          "summary": "Prototype pollution vulnerability"
        }
      ]
    }
  }
}
```

**AQL Query (Optimized):**

```aql
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
```

#### Query Releases Affected by Severity

**GraphQL Query:**

```graphql
query GetAffectedReleases($severity: Severity!, $limit: Int) {
  affectedReleases(severity: $severity, limit: $limit) {
    cve_id
    severity_score
    severity_rating
    package
    affected_version
    release_name
    release_version
  }
}
```

**Graph Traversal (Optimized):**

```mermaid
flowchart LR
    Release["Release"] --> SBOM["SBOM"]
    SBOM -->|SBOM2PURL<br/>with version| PURL["PURL"]
    PURL --> CVE["CVE"]
    CVE --> Filter1["Filter:<br/>database_specific<br/>.severity_rating<br/>== 'HIGH'"]
    Filter1 --> Filter2["Validate<br/>version match<br/>in Go"]
    
    style Release fill:#fff0e0
    style SBOM fill:#69db7c
    style PURL fill:#4dabf7
    style CVE fill:#ff6b6b
    style Filter1 fill:#ffd43b
    style Filter2 fill:#ffd43b
```

**AQL Query (Optimized with Better Aggregation):**

```aql
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
```

**Performance:**

- String-based filtering on `severity_rating` is indexed
- No runtime CVSS parsing required
- Efficient even with 100,000+ CVEs
- SORT/LIMIT outside loops for optimal performance

#### Query Endpoints Affected by Severity

**GraphQL Query:**

```graphql
query GetSyncedEndpoints($limit: Int) {
  syncedEndpoints(limit: $limit) {
    endpoint_name
    endpoint_url
    endpoint_type
    environment
    status
    last_sync
    release_count
    total_vulnerabilities {
      critical
      high
      medium
      low
    }
    releases {
      release_name
      release_version
    }
  }
}
```

**Graph Traversal:**

```mermaid
flowchart TB
    Endpoint["Endpoint"] --> Sync["Sync Records"]
    Sync --> Release["Release"]
    Release --> SBOM["SBOM"]
    SBOM -->|SBOM2PURL<br/>with version| PURL["PURL"]
    PURL --> CVE["CVE<br/>(aggregate by<br/>severity_rating)"]
    
    style Endpoint fill:#cc5de8
    style Sync fill:#fff3bf
    style Release fill:#fff0e0
    style SBOM fill:#69db7c
    style PURL fill:#4dabf7
    style CVE fill:#ff6b6b
```

**AQL Query (Optimized with Direct Endpoint Start):**

```aql
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
```

**Response:**

```json
{
  "data": {
    "syncedEndpoints": [
      {
        "endpoint_name": "prod-k8s-us-east",
        "endpoint_url": "prod-k8s-us-east",
        "endpoint_type": "cluster",
        "environment": "production",
        "status": "active",
        "last_sync": "2024-01-20T14:22:00Z",
        "release_count": 12,
        "total_vulnerabilities": {
          "critical": 2,
          "high": 8,
          "medium": 15,
          "low": 23
        },
        "releases": [
          {
            "release_name": "api-service",
            "release_version": "2.1.0"
          }
        ]
      }
    ]
  }
}
```

#### Query Affected Endpoints for a Release

**GraphQL Query:**

```graphql
query GetAffectedEndpoints($name: String!, $version: String!) {
  affectedEndpoints(name: $name, version: $version) {
    endpoint_name
    endpoint_url
    endpoint_type
    environment
    last_sync
    status
  }
}
```

**AQL Query (Optimized with Direct Indexed Lookup):**

```aql
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
```

**Performance Benefits:**

- Direct indexed lookup on composite `sync.release_name + release_version`
- No unnecessary graph traversals
- O(log N) complexity instead of O(N)
- Typical response time: <50ms for 100K sync records

#### Query All Vulnerabilities (Mitigations View)

**GraphQL Query:**

```graphql
query GetVulnerabilities($limit: Int) {
  vulnerabilities(limit: $limit) {
    cve_id
    summary
    severity_score
    severity_rating
    package
    affected_version
    full_purl
    fixed_in
    affected_releases
    affected_endpoints
  }
}
```

**AQL Query (Optimized with Proper Aggregation):**

```aql
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
```

**Key Optimizations:**

- **COLLECT/AGGREGATE pattern**: Groups vulnerabilities by CVE + package + version
- **SORT/LIMIT outside loops**: Ensures proper ordering and pagination
- **Deduplication**: Removes duplicate entries from multiple paths
- **Version validation in Go**: Final filtering done post-query for accuracy

### 5. Severity-Based Impact Analysis

**Query Releases by Severity:**

```bash
GET /api/v1/graphql
```

**GraphQL Query:**

```graphql
query GetAffectedReleases($severity: Severity!, $limit: Int) {
  affectedReleases(severity: $severity, limit: $limit) {
    cve_id
    severity_score
    severity_rating
    package
    affected_version
    release_name
    release_version
    content_sha
    project_type
  }
}
```

**Response:**

```json
{
  "data": {
    "affectedReleases": [
      {
        "cve_id": "CVE-2024-1234",
        "severity_score": 9.8,
        "severity_rating": "CRITICAL",
        "package": "pkg:npm/lodash",
        "affected_version": "4.17.20",
        "release_name": "api-service",
        "release_version": "2.1.0",
        "content_sha": "abc123def456",
        "project_type": "application"
      }
    ]
  }
}
```

**Query Endpoints by Severity:**

```graphql
query GetSyncedEndpoints($limit: Int) {
  syncedEndpoints(limit: $limit) {
    endpoint_name
    total_vulnerabilities {
      critical
      high
      medium
      low
    }
  }
}
```

**Response:**

```json
{
  "data": {
    "syncedEndpoints": [
      {
        "endpoint_name": "prod-us-east-1",
        "total_vulnerabilities": {
          "critical": 2,
          "high": 8,
          "medium": 15,
          "low": 23
        }
      }
    ]
  }
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
          CRITICAL_VULNS=$(curl -s ${{ secrets.CVE_TRACKER_URL }}/api/v1/graphql \
            -H "Content-Type: application/json" \
            -d '{"query": "query { release(name: \"'${{ github.event.repository.name }}'\", version: \"'${{ github.sha }}'\") 
            { vulnerabilities { severity_rating } } }"}' | \
            jq '[.data.release.vulnerabilities[] | select(.severity_rating == "CRITICAL")] | length')
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
    
    # Check for high severity vulnerabilities
    HIGH_VULNS=$(curl -s ${CVE_TRACKER_URL}/api/v1/graphql \
      -H "Content-Type: application/json" \
      -d '{"query": "query { syncedEndpoints(limit: 1000) { endpoint_name total_vulnerabilities { high } } }"}' | \
      jq ".data.syncedEndpoints[] | select(.endpoint_name == \"${ARGOCD_APP_NAME}\") | .total_vulnerabilities.high")
    
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
- API endpoint response times (target: <3s)

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
      
      - alert: SlowAPIResponseTime
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 3
        annotations:
          summary: "API response time exceeding 3 second SLA"
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

### Rolling Update Strategy

The system supports zero-downtime deployments through rolling updates:

**Deployment Process:**

```mermaid
flowchart LR
    Step1["1. New version deployed<br/>alongside existing"] --> Step2
    Step2["2. Health checks verify<br/>new instances ready"] --> Step3
    Step3["3. Traffic gradually shifted<br/>to new instances"] --> Step4
    Step4["4. Old instances drained<br/>and terminated"] --> Step5
    Step5["5. Database migrations<br/>run automatically"]
    
    style Step1 fill:#e3f2fd
    style Step2 fill:#fff3bf
    style Step3 fill:#ffd43b
    style Step4 fill:#69db7c
    style Step5 fill:#51cf66
```

**Benefits:**

- No maintenance window required
- Continuous service availability during updates
- Automatic rollback capability if health checks fail
- Gradual traffic migration minimizes risk

**Kubernetes Example:**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cve-tracker-api
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  template:
    spec:
      containers:
      - name: api
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
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
ARANGO_HOST=localhost
ARANGO_PORT=8529
ARANGO_USER=root
ARANGO_PASS=password
ARANGO_URL=http://localhost:8529

# MITRE ATT&CK (optional)
MITRE_MAPPING_URL=https://your-mitre-service/api/map

# Performance
MAX_CONCURRENT_REQUESTS=100
REQUEST_TIMEOUT=3s
```

## Conclusion

This Post-Deployment Vulnerability Remediation system provides comprehensive visibility into software vulnerabilities across the entire deployment lifecycle. By connecting CVE data with releases, SBOMs, and actual deployment endpoints, security teams can quickly answer the critical questions: "Where is this vulnerability running?" and "How do I fix it?"

The hub-and-spoke architecture ensures scalability and performance, while the sync tracking mechanism provides the crucial link between code and production systems. The addition of pre-calculated CVSS scores and severity ratings enables efficient, real-time severity-based filtering and prioritization, with all API operations completing within 3 seconds to ensure optimal end-user experience. The rolling update deployment strategy ensures continuous availability, eliminating the need for maintenance windows while maintaining service quality.

**Key Benefits:**

```mermaid
mindmap
  root((Post-Deployment<br/>Vulnerability<br/>Remediation))
    Performance
      All API responses <3s
      Indexed severity ratings
      Optimized AQL queries
      Millions of CVEs efficiently
    Accuracy
      Official CVSS specification
      Validated library
      Complete CVE coverage
    Scalability
      Linear edge growth
      Hub-and-spoke architecture
      Optimized queries
      COLLECT/AGGREGATE patterns
    Availability
      Rolling updates
      99.9% uptime
      Zero downtime deployments
    Reliability
      All CVEs have severity
      Even missing data handled
      Comprehensive tracking
```

- **Performance**: All API responses <3 seconds for optimal user experience
- **Accuracy**: Uses official CVSS specification via validated library
- **Completeness**: All CVEs have severity ratings, even those with missing data
- **Scalability**: Indexed severity ratings support millions of CVEs efficiently
- **Availability**: Rolling updates ensure zero-downtime deployments
- **Reliability**: 99.9% uptime with no maintenance windows required
- **Query Optimization**: COLLECT/AGGREGATE/SORT patterns ensure efficient data processing