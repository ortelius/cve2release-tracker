# SCEC-DB

SCEC Database API and CLI for managing software releases and SBOMs.

## Project Structure

```text
scec-db/
├── cmd/          # CLI commands
├── cli/          # CLI entry point
├── database/     # ArangoDB connection
├── model/        # Data models
├── util/         # Utilities
└── main.go       # API server
```

## Building

### API Server

```bash
go build -o scec-server main.go
./scec-server
```

### CLI Client

```bash
go build -o scec-cli ./cli
./scec-cli upload --sbom sbom.json
```

## Environment Variables

- `ARANGO_HOST` - ArangoDB host (default: localhost)
- `ARANGO_PORT` - ArangoDB port (default: 8529)
- `ARANGO_USER` - ArangoDB username (default: root)
- `ARANGO_PASS` - ArangoDB password
- `PORT` - API server port (default: 3000)

## API Endpoints

- `POST /api/v1/releases` - Create release with SBOM
- `GET /api/v1/releases` - List all releases
- `GET /api/v1/releases/:name/:version` - Get specific release

## CLI Commands

```bash
# Upload a release with SBOM
scec-cli upload --sbom sbom.json --type application

# List all releases
scec-cli list

# Get a specific release
scec-cli get myapp 1.0.0

# Get only the SBOM
scec-cli get myapp 1.0.0 --sbom-only --output sbom.json
```

## Install with Docker-Compose

1. Install docker https://docs.docker.com/get-started/get-docker/

2. Clone frontend application 
```bash
git clone https://github.com/ortelius/pdvd-frontend
```

3. Clone backend application 
```bash
https://github.com/ortelius/pdvd-backend
```

4. Run docker-compose
```bash
docker-compose up
```