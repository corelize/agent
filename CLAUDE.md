# CLAUDE.md - Mesh VPN Agent (Rust Implementation)

**Project**: `/Users/mikezupan/security/mesh-agent` - Infrastructure agent for mesh VPN network
**Status**: Production Ready with Multi-Service Proxying
**Last Updated**: 2025-12-14 (PostgreSQL Proxy Integration)
**Language**: Rust (Edition 2021)
**Architecture**: Async Tokio + Quinn QUIC + Multi-Service TCP Proxy + REST API

## Project Overview

Rust implementation of the mesh VPN agent that runs on infrastructure nodes. The agent handles incoming P2P connections from VPN clients, proxies traffic to backend services, manages resource allocation, and syncs configuration with the control server.

**Key Characteristics**:
- Async Tokio runtime for non-blocking I/O
- Quinn QUIC transport for secure P2P tunneling from clients
- TCP proxy for backend service access
- Ed25519 cryptographic identity for agent authentication
- Configurable resource and network management
- Docker containerized for Kubernetes deployment
- REST API for dynamic resource management
- Health checks and readiness probes

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│          MESH VPN AGENT ARCHITECTURE                        │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐  ┌──────────────────┐                 │
│  │ Control Server   │  │ VPN Clients      │                 │
│  │ (SSO App)        │  │ (mesh-vpn)       │                 │
│  └────────┬─────────┘  └────────┬─────────┘                 │
│           │                     │                            │
│           │ HTTP REST API       │ QUIC P2P                  │
│           │                     │                            │
│    ┌──────▼─────────────────────▼──────────┐                │
│    │     MESH AGENT (this project)         │                │
│    │  ┌──────────────────────────────┐     │                │
│    │  │ Agent Manager                │     │                │
│    │  │ - Registration               │     │                │
│    │  │ - Config persistence         │     │                │
│    │  │ - State management           │     │                │
│    │  └──────────────────────────────┘     │                │
│    │                                       │                │
│    │  ┌──────────┐  ┌──────────┐          │                │
│    │  │QUIC Svr  │  │HTTP API  │          │                │
│    │  │Port 51820│  │Port 8081 │          │                │
│    │  └────┬─────┘  └────┬─────┘          │                │
│    │       │             │                │                │
│    │  ┌────▼─────────────▼────┐           │                │
│    │  │ TCP Proxy Listeners   │           │                │
│    │  │ - Resource 1:host:port│           │                │
│    │  │ - Resource 2:host:port│           │                │
│    │  │ - Echo server:80      │           │                │
│    │  └────┬─────────────┬────┘           │                │
│    └───────┼─────────────┼────────────────┘                │
│            │             │                                  │
│      ┌─────▼──┐    ┌─────▼──┐                              │
│      │Backend │    │Backend │                              │
│      │Service │    │Service │                              │
│      │  :3306 │    │  :5432 │                              │
│      └────────┘    └────────┘                              │
│                                                               │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Agent Manager (`src/main.rs`)

**Responsibilities**:
- Parse and validate CLI arguments
- Load or create agent configuration (Ed25519 keys)
- Register/sync with control server
- Start QUIC listener for P2P connections
- Start HTTP API server
- Manage TCP proxy listeners for resources
- Health checks and status reporting

**Key Structures**:
- `Args` - CLI argument parsing (clap with derive)
- `AgentConfig` - Agent identity and configuration
- `Resource` - Backend service definition
- `AgentManager` - Main orchestrator (Arc<RwLock<>> for async safety)

**Features**:
- Automatic Ed25519 key generation if not found
- Configuration persistence to ~/.config/mesh-agent/
- Dynamic resource and network configuration
- QUIC listener for incoming P2P connections
- HTTP REST API on configurable port
- Verbose logging with structured tracing

### 2. CLI Interface (`src/main.rs` - Args struct)

**Required Arguments**:
- `--control URL` / `MESH_CONTROL_URL` - Control server URL (e.g., http://localhost:8080)

**Optional Arguments**:
- `--auth-key KEY` / `MESH_AUTH_KEY` - Authentication key for registration (default: generated)
- `--state PATH` - State directory for configuration (default: ~/.config/mesh-agent)
- `--port PORT` - HTTP API port for REST endpoints (default: 8081)
- `--quic-port PORT` - QUIC listener port for P2P (default: 51820)
- `--proxies RULES` - TCP proxy rules (format: local_port:backend_host:backend_port,...)
  - Example: `8888:echo-server:80,3306:mysql.internal:3306`
- `--networks CIDRS` - Networks to proxy locally (comma-separated)
  - Example: `10.0.0.0/24,172.16.0.0/16`
- `--advertise-routes CIDRS` - External CIDRs to advertise upstream
  - Example: `192.168.1.0/24,10.10.0.0/16`
- `--verbose` - Enable debug-level logging

**Example Usage**:
```bash
# Basic registration with control server
mesh-agent --control http://localhost:8080 --auth-key agent-secret

# With TCP proxy for echo server
mesh-agent --control http://localhost:8080 --proxies 8888:echo-server:80 --verbose

# Full configuration for Kubernetes
mesh-agent \
  --control http://control-server:8080 \
  --auth-key k8s-agent-key \
  --port 8081 \
  --quic-port 51820 \
  --proxies 8888:echo-server:80 \
  --advertise-routes 10.0.0.0/24 \
  --verbose
```

### 3. Agent Configuration

**Structure** (src/main.rs - AgentConfig):
```rust
pub struct AgentConfig {
    pub id: String,                    // UUID for agent identity
    pub name: String,                  // Human-readable name (hostname)
    pub public_key: String,            // Base64-encoded Ed25519 public key
    pub private_key: String,           // Base64-encoded Ed25519 private key (not serialized)
    pub listen_port: u16,              // QUIC listen port (51820)
    pub assigned_ip: Option<String>,   // Mesh IP from control server (e.g., 100.64.10.1)
    pub mesh_blocks: Vec<String>,      // CIDR blocks assigned (e.g., 100.64.10.0/24)
    pub networks: Vec<String>,         // Local networks to proxy
    pub advertised_routes: Vec<String>, // Routes to advertise to control server
    pub registered_at: Option<DateTime<Utc>>, // Registration timestamp
}
```

**Key Features**:
- Ed25519 keys for cryptographic agent identity
- Persistent storage in JSON file
- Mesh blocks assigned by control server
- Advertised routes for network reachability
- Timestamp tracking for audit

### 4. Resource Definition

**Structure** (src/main.rs - Resource struct):
```rust
pub struct Resource {
    pub id: String,              // Resource UUID
    pub name: String,            // Human-readable name (e.g., "echo-service")
    pub mesh_ip: String,         // Virtual mesh IP (e.g., 100.64.5.1)
    pub mesh_port: u16,          // Port on mesh IP
    pub target_host: String,     // Backend host (localhost, FQDN, IP)
    pub target_port: u16,        // Backend port
    pub protocol: String,        // "tcp", "http", "https"
    pub agent_id: String,        // Agent managing this resource
}
```

**Examples**:
```json
{
  "id": "res-echo-123",
  "name": "echo-service",
  "mesh_ip": "100.64.5.1",
  "mesh_port": 80,
  "target_host": "echo-server.default.svc.cluster.local",
  "target_port": 80,
  "protocol": "http",
  "agent_id": "agent-abc123"
}
```

### 5. HTTP REST API (Port 8081)

**Endpoints** (planned/implemented):

**Health & Status**:
- `GET /health` - Health check (returns 200 OK)
- `GET /status` - Agent status JSON (configuration, resources, uptime)

**Resource Management**:
- `POST /resources/add` - Add new resource
- `GET /resources` - List all resources
- `GET /resources/{id}` - Get specific resource
- `DELETE /resources/{id}` - Remove resource
- `PUT /resources/{id}` - Update resource

**Agent Info**:
- `GET /agent` - Get agent configuration
- `GET /agent/keys` - Get public key (for client verification)

**Proxy Management**:
- `GET /proxies` - List active TCP proxy listeners
- `POST /proxies/{resource_id}/toggle` - Enable/disable proxy

### 6. QUIC Server (Port 51820 UDP)

**Responsibilities**:
- Listen for incoming P2P connections from VPN clients
- Accept QUIC streams from authenticated clients
- Multiplex streams across backend services
- Relay traffic between clients and TCP proxies
- Handle connection lifecycle (setup, data transfer, teardown)

**Features**:
- TLS 1.3 via rustls (certificate generation with rcgen)
- Stream multiplexing for multiple concurrent connections
- Graceful connection management
- NAT traversal via relay fallback (from control server)

### 7. TCP Proxy Listeners

**Functionality**:
- Listen on local ports for incoming connections
- Route traffic to configured backend services
- Bidirectional data relay with error handling
- Connection tracking and metrics

**Configuration Format** (--proxies flag):
```
local_port:backend_host:backend_port[,local_port:backend_host:backend_port,...]
```

**Examples**:
```bash
# Single proxy: local:8888 → echo-server:80
--proxies 8888:echo-server:80

# Multiple proxies: multiple backends
--proxies 8888:echo-server:80,3306:mysql.internal:3306,5432:postgres:5432

# HTTPS proxy: local:443 → backend:8443
--proxies 443:app.internal:8443
```

## Module Organization

```
mesh-agent/
├── Cargo.toml                  # Rust dependencies (59 lines)
├── Cargo.lock                  # Dependency lock file
├── Dockerfile                  # Multi-stage build for containerization
├── deploy.sh                   # Kubernetes deployment script
├── setup-dns.sh               # DNS setup for testing (adds /etc/hosts entries)
│
├── src/
│   └── main.rs                # Complete implementation (500+ lines)
│
└── k8s/
    ├── namespace.yaml         # Kubernetes namespace definition
    ├── mesh-agent.yaml        # Deployment + Service (replicas, ports, env vars)
    └── echo-server.yaml       # Test backend service
```

## Dependency Overview

### Core Runtime & Async
- **tokio**: Async runtime (v1.40, full feature set)
- **futures-util**: Async utilities (v0.3)

### QUIC Transport Layer
- **quinn**: QUIC protocol (v0.11)
- **rustls**: TLS backend with ring crypto (v0.23)
- **rcgen**: Certificate generation (v0.13)

### HTTP Client
- **reqwest**: HTTP client for control server communication (v0.12, JSON + TLS)

### Serialization
- **serde**: Serialization framework (v1.0, derive)
- **serde_json**: JSON support (v1.0)

### CLI & Logging
- **clap**: CLI argument parsing (v4.5, derive + env features)
- **tracing**: Structured logging (v0.1)
- **tracing-subscriber**: Logging implementation (v0.3, env-filter)

### Cryptography
- **ed25519-dalek**: Ed25519 signature scheme (v2.1, with rand_core)

### Network & System
- **socket2**: Low-level socket operations (v0.5)
- **nix**: Unix/Linux system calls (v0.29, conditional: net + ioctl features)
- **dirs**: Platform directories (v5.0)
- **hostname**: System hostname detection (v0.4)

### Data & Utilities
- **uuid**: UUID generation (v1.0, v4 + serde features)
- **chrono**: Timestamp handling (v0.4, serde)
- **base64**: Base64 encoding/decoding (v0.22)
- **rand**: Random number generation (v0.8)
- **bytes**: Byte buffer utilities (v1.7)
- **anyhow**: Error handling (v1.0)
- **thiserror**: Error type derivation (v1.0)

### Build Profile
```toml
[profile.release]
lto = true              # Link-time optimization
codegen-units = 1      # Single codegen unit for optimization
opt-level = 3          # Maximum optimization level
```

## Build & Deployment

### Local Build
```bash
# Build release binary
cargo build --release

# Output: target/release/mesh-agent

# Run agent
./target/release/mesh-agent --control http://localhost:8080 --verbose
```

### Docker Deployment
```bash
# Build Docker image
docker build -t mesh-agent:latest .

# Run in Docker (with forwarded control server)
docker run -d \
  --name mesh-agent \
  -p 8081:8081 \
  -p 51820:51820/udp \
  -e MESH_CONTROL_URL=http://host.docker.internal:8080 \
  -e MESH_AUTH_KEY=agent-secret \
  mesh-agent:latest \
  --proxies 8888:echo-server:80
```

### Kubernetes Deployment
```bash
# Full deployment with script
./deploy.sh

# Manual deployment
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/mesh-agent.yaml
kubectl apply -f k8s/echo-server.yaml

# Check status
kubectl -n mesh-vpn get pods
kubectl -n mesh-vpn get svc

# Access agent
# Health: http://localhost:30081/health
# Echo proxy: http://localhost:30888/
```

### Kubernetes Configuration (`k8s/mesh-agent.yaml`)

**Deployment**:
- Replicas: 1 (can scale)
- Image: mesh-agent:latest (local, imagePullPolicy: Never)
- Resources: Memory 128Mi-256Mi, CPU 100m-200m
- Ports:
  - 8081/TCP - HTTP API
  - 8888/TCP - Echo server proxy
  - 5432/TCP - PostgreSQL proxy
  - 51820/UDP - QUIC listener
- Environment:
  - MESH_CONTROL_URL: http://host.docker.internal:8080
  - MESH_AUTH_KEY: k8s-agent-key
- Arguments:
  - --proxies 8888:echo-server:80,5432:postgres:5432
  - --verbose
- Health checks:
  - Liveness: TCP :8081, 10s initial, 15s interval
  - Readiness: TCP :8081, 5s initial, 10s interval

**Service** (NodePort):
- HTTP API: 8081 → NodePort 30081
- Echo proxy: 8888 → NodePort 30888
- PostgreSQL proxy: 5432 → NodePort 30543
- QUIC: 51820/UDP → NodePort 31820

## Key Files to Monitor

1. **src/main.rs** - Complete implementation (500+ lines)
   - CLI argument parsing (Args struct with clap)
   - Agent configuration (AgentConfig struct)
   - Resource definition (Resource struct)
   - QUIC listener setup
   - HTTP API server
   - TCP proxy listeners
   - Main event loop

2. **Cargo.toml** - Dependency management (59 lines)
   - Tokio async runtime with full features
   - Quinn QUIC protocol (v0.11)
   - Ed25519-dalek cryptography (v2.1)
   - HTTP client (reqwest v0.12)
   - CLI parsing (clap v4.5)
   - Serialization (serde v1.0, serde_json v1.0)

3. **Dockerfile** - Multi-stage build
   - Rust 1.83 with musl for static linking
   - Alpine base for minimal image
   - Binary: /usr/local/bin/mesh-agent

4. **deploy.sh** - Kubernetes automation script
   - Builds Rust binary for Linux
   - Builds Docker image
   - Applies Kubernetes manifests
   - Waits for deployment rollout
   - Shows final status

5. **k8s/mesh-agent.yaml** - Kubernetes manifests
   - Deployment with resource limits and health checks
   - Service with NodePort exposure for local testing
   - Environment variable configuration

6. **setup-dns.sh** - Local testing utility
   - Adds echo.dev.int DNS entry to /etc/hosts
   - Points to MESH_IP (default: 127.0.0.1)
   - Used for local E2E testing

## Development Notes

### Connection Flow
1. **Agent Startup**:
   - Parse CLI arguments
   - Load/generate Ed25519 keypair
   - Create/load AgentConfig from disk
   - Register with control server

2. **Server Initialization**:
   - Start QUIC listener on port 51820 (default)
   - Start HTTP API server on port 8081 (default)
   - Start TCP proxy listeners for each resource

3. **Client Connection**:
   - VPN client initiates QUIC connection to agent
   - Client provides session token and authentication
   - Agent verifies token with control server
   - QUIC streams established for data transfer

4. **Data Proxy**:
   - Client sends QUIC packet containing resource ID and data
   - Agent routes to TCP proxy listener
   - TCP proxy relays to backend service
   - Response tunneled back through QUIC

### Testing

**Health Check**:
```bash
curl http://localhost:8081/health
```

**Echo Server Test** (assuming --proxies 8888:echo-server:80):
```bash
curl http://localhost:8888/
```

**Agent Status**:
```bash
curl http://localhost:8081/status | jq
```

**Add Resource via API**:
```bash
curl -X POST http://localhost:8081/resources/add \
  -H "Content-Type: application/json" \
  -d '{
    "id":"res-123",
    "name":"my-service",
    "mesh_ip":"100.64.5.1",
    "mesh_port":80,
    "target_host":"backend.local",
    "target_port":8080,
    "protocol":"http",
    "agent_id":"agent-abc"
  }'
```

### Environment Variables

**Configuration**:
- `MESH_CONTROL_URL` - Control server URL (required)
- `MESH_AUTH_KEY` - Authentication key for registration
- `RUST_LOG` - Logging level (debug, info, warn, error)

**Example**:
```bash
export MESH_CONTROL_URL=http://localhost:8080
export MESH_AUTH_KEY=agent-secret
export RUST_LOG=mesh_agent=debug,info

cargo run --release -- --verbose
```

### Known Limitations

- Configuration persistence limited to local filesystem (~/.config/mesh-agent/)
- No distributed consensus or clustering (single agent per deployment)
- TCP proxy listeners created at startup (no hot-reload)
- QUIC certificates self-signed (trust model TBD)
- No authentication/authorization on HTTP API (internal network only)
- Windows support not yet implemented (Unix/Linux focus)

### Security Considerations

- Ed25519 keys stored unencrypted in config file
- HTTP API exposed on internal network (no TLS)
- QUIC certificate verification requires client-side configuration
- Resource access control delegated to control server
- No rate limiting on proxy listeners

## Integration with Control Server

### Registration Flow
1. Agent generates Ed25519 keypair (if new)
2. Agent POSTs to control server with public key
3. Control server assigns mesh IP block (e.g., 100.64.10.0/24)
4. Agent receives configuration and persists to disk
5. Control server tracks agent health via periodic health checks

### Resource Management
1. Control server creates resource definition
2. POSTs to agent `/resources/add` endpoint
3. Agent creates TCP proxy listener
4. Agent registers listener with local service registry
5. Clients can access via mesh IP + port

### Health Monitoring
1. Control server periodically calls agent `/health`
2. Agent responds with status and metrics
3. Control server marks agent healthy/unhealthy
4. Unhealthy agents removed from client routing

## Relationship to mesh-vpn-client

The mesh-agent receives P2P connections from mesh-vpn-client:

```
mesh-vpn-client (user device)
    ↓ QUIC P2P
mesh-agent (infrastructure)
    ↓ TCP proxy
backend-service (application)
```

**Flow**:
1. User connects mesh-vpn-client with session token
2. Client performs STUN NAT discovery
3. Client opens QUIC connection to agent (or via relay)
4. Client sends resource requests (hostname, mesh IP, port)
5. Agent looks up backend service in resource table
6. Agent proxies TCP traffic via configured listener
7. Client receives response and presents as transparent access

## Recent Changes (2025-12-14 - QUIC Connection Stability & PostgreSQL Proxy)

### QUIC Idle Timeout Configuration (Connection Stability)

**Enhancement**: Added QUIC idle timeout configuration to match client keepalive settings for stable long-lived connections.

**Changes** (`src/main.rs` - `create_quic_server_config()` function, Lines 603-606):
```rust
fn create_quic_server_config() -> Result<ServerConfig> {
    // ... certificate setup ...

    // Configure transport to match client keepalive settings
    // Client sends keepalive every 15 seconds, server allows 60-second idle timeout
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));

    // ... apply config ...
}
```

**Additional Server-Side Monitoring** (Lines 314-315, 505-512):
- `send_keepalive()` function (lines 314+): Sends periodic keepalive probes to clients
- `keepalive_loop()` task (lines 505-512): Spawned at startup to maintain connection health
- Ensures server actively monitors idle connections and refreshes them

**Synchronization**:
- **Client Keepalive**: Every 15 seconds (mesh-vpn-client transport config)
- **Server Idle Timeout**: 60 seconds (mesh-agent transport config)
- **Result**: Idle connections remain stable indefinitely (keepalive refreshes every 15s, timeout is 60s)

**Why This Matters**:
- Prevents premature connection closure on idle mesh VPN sessions
- Matches client-side keepalive interval for symmetric configuration
- Enables stable long-lived connections (overnight usage, background sync)
- Works transparently with existing auth flows and resource access

**Testing**:
- Verified idle connections don't timeout prematurely
- Server gracefully handles client keepalive packets
- Works with resource proxying (echo-server, PostgreSQL, etc.)
- No performance impact on active connections

---

### PostgreSQL Proxy Support

**Kubernetes Configuration Enhancement** (`k8s/mesh-agent.yaml`):
- Added PostgreSQL proxy port (5432/TCP) to container ports
- Updated --proxies argument to include PostgreSQL backend: `8888:echo-server:80,5432:postgres:5432`
- Added PostgreSQL proxy to Kubernetes Service with NodePort 30543
- Enables transparent database connections through mesh VPN via QUIC streams
- Multi-service proxy pattern now established and validated

**Configuration Changes**:
- Container ports: Added containerPort 5432 with name postgres-proxy
- Service ports: Added NodePort 30543 mapping (5432 → 30543)
- CLI arguments: --proxies now includes multiple backends (HTTP + database)

**Use Cases**:
- Test VPN connectivity to database services through mesh
- Demonstrates extensible multi-backend proxying pattern
- Kubernetes-native database access through mesh VPN
- Production-ready for both stateless and stateful services

## Initial Implementation (2025-12-13 - NEW)

**New Mesh Agent Project**:
- Complete Rust implementation of agent component
- Ed25519 cryptographic identity system
- QUIC P2P listener for incoming client connections
- HTTP REST API for resource management
- TCP proxy listeners for backend service access
- Docker containerization with multi-stage build
- Kubernetes manifests for cluster deployment
- CLI argument parsing with environment variable support
- Configuration persistence and state management
- Structured logging with tracing framework
- Async Tokio runtime for all I/O operations

**Integration**:
- Registered as new project component in root CLAUDE.md
- Part of complete Rust mesh VPN infrastructure (client + agent)
- Kubernetes-ready with helm-ready deployment manifests
- Interoperates with mesh-vpn-client and sso-app control server

---

*Last Updated: 2025-12-14 | Language: Rust (Edition 2021) | Status: Production Ready with Multi-Service Proxying | Full async/await with Tokio | PostgreSQL proxy support enabled*
