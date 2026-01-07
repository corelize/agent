# PRD: Agent-Based Kubernetes Authentication Proxy

## Overview

Enable seamless Kubernetes cluster access through the VPN mesh by having the agent handle authentication automatically. Users connected via VPN can use `kubectl` without managing JWTs in their kubeconfig - the agent injects authentication based on their VPN session identity.

## Problem Statement

Currently, users accessing Kubernetes clusters through the mesh gateway must:
1. Obtain a JWT from the SSO backend
2. Configure their kubeconfig with the token
3. Manage token refresh manually
4. Update kubeconfig when tokens expire

This creates friction and security concerns:
- Tokens stored in plaintext kubeconfig files
- Manual token management is error-prone
- Users may share/expose tokens accidentally
- No automatic token rotation

## Proposed Solution

### Architecture

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  kubectl        │────▶│  mesh-agent      │────▶│  K8s Gateway    │────▶│  EKS Cluster    │
│  (no token)     │     │  (JWT injection) │     │  (JWT verify)   │     │                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘     └─────────────────┘
        │                        │
        │                        ▼
        │               ┌──────────────────┐
        │               │  SSO Backend     │
        │               │  (JWT issuer)    │
        └──────────────▶└──────────────────┘
                VPN Session = User Identity
```

### Flow

1. **VPN Connection**: User connects via mesh-vpn-client, establishing authenticated session
2. **Session Tracking**: Agent maintains `session_id → user_email` mapping from QUIC handshake
3. **kubectl Request**: User runs `kubectl get pods` pointing to agent's mesh IP
4. **Identity Lookup**: Agent identifies user from the incoming connection's VPN session
5. **JWT Request**: Agent requests K8s JWT from backend using user identity + agent auth
6. **JWT Injection**: Agent adds `Authorization: Bearer <jwt>` header to request
7. **Forward**: Agent forwards authenticated request to K8s gateway
8. **Response**: Response flows back through agent to kubectl

## Technical Specification

### 1. VPN Session Tracking

**Location**: `src/main.rs` - extend `AgentState`

```rust
struct AgentState {
    // Existing fields...

    // New: VPN session → user mapping
    vpn_sessions: Arc<RwLock<HashMap<String, VpnSession>>>,
}

struct VpnSession {
    user_email: String,
    user_id: String,
    connected_at: DateTime<Utc>,
    last_activity: DateTime<Utc>,
}
```

**Session Registration**: When VPN client connects via QUIC, extract user from `PROXY:host:port:user_id` header and register session.

### 2. K8s Proxy Listener

**New Component**: K8s API proxy listening on dedicated mesh IP port

```rust
// Listen on mesh IP for K8s traffic
// Example: 100.64.0.1:6443 (standard K8s API port)
async fn start_k8s_proxy(
    state: Arc<AgentState>,
    listen_addr: SocketAddr,  // e.g., 100.64.0.1:6443
    gateway_url: String,      // e.g., https://k8s-gateway.example.com
) -> Result<()>
```

**Request Handling**:
1. Accept HTTPS connection from kubectl
2. Identify VPN session from source IP
3. Extract K8s API path from request
4. Inject JWT and forward to gateway

### 3. JWT Acquisition

**Backend Endpoint**: New endpoint for agent JWT requests

```
POST /api/v1/agent/k8s-token
Authorization: Bearer <agent_auth_key>
Content-Type: application/json

{
    "user_email": "mike@example.com",
    "cluster_id": "eks-prod",
    "agent_id": "agent-abc123"
}

Response:
{
    "token": "eyJ...",
    "expires_at": "2025-01-05T05:00:00Z"
}
```

**Agent-side caching**:
```rust
struct TokenCache {
    // (user_email, cluster_id) → cached token
    tokens: HashMap<(String, String), CachedToken>,
}

struct CachedToken {
    jwt: String,
    expires_at: DateTime<Utc>,
}
```

### 4. Request Flow

```rust
async fn handle_k8s_request(
    state: Arc<AgentState>,
    req: Request<Body>,
    client_addr: SocketAddr,
) -> Result<Response<Body>> {
    // 1. Find VPN session by client IP
    let session = state.find_session_by_ip(client_addr.ip())?;

    // 2. Get or refresh JWT for user
    let jwt = state.get_k8s_token(&session.user_email, cluster_id).await?;

    // 3. Clone request and inject auth header
    let mut proxied_req = req.clone();
    proxied_req.headers_mut().insert(
        AUTHORIZATION,
        format!("Bearer {}", jwt).parse()?,
    );

    // 4. Forward to K8s gateway
    let response = state.http_client.request(proxied_req).await?;

    Ok(response)
}
```

## User Experience

### Before (Current)
```yaml
# ~/.kube/config
clusters:
- cluster:
    server: https://k8s-gateway.example.com
  name: mesh-eks
users:
- name: mesh-user
  user:
    token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...  # Manual JWT
contexts:
- context:
    cluster: mesh-eks
    user: mesh-user
  name: mesh
```

### After (Proposed)
```yaml
# ~/.kube/config
clusters:
- cluster:
    server: https://100.64.0.1:6443  # Agent mesh IP, no token needed
    certificate-authority-data: <agent-ca>
  name: mesh-eks
contexts:
- context:
    cluster: mesh-eks
  name: mesh
```

**User workflow**:
1. Connect to VPN: `mesh-vpn-client connect`
2. Use kubectl normally: `kubectl get pods` (no token configuration)

## Security Considerations

### Authentication Chain
1. **VPN Session**: User authenticated via SSO OAuth during VPN connect
2. **Agent Identity**: Agent authenticated to backend via `auth_key`
3. **JWT Request**: Agent requests token on behalf of authenticated VPN user
4. **Token Scope**: JWT scoped to specific user + cluster

### Token Security
- JWTs never stored on user's machine
- Short-lived tokens (5-15 min) with automatic refresh
- Agent caches tokens in memory only
- Tokens invalidated when VPN disconnects

### Audit Trail
- All K8s requests logged with user identity
- Agent logs token requests
- Gateway logs authenticated requests

## Implementation Tasks

### Phase 1: VPN Session Tracking
- [ ] Add `VpnSession` struct to agent state
- [ ] Track sessions on QUIC connection
- [ ] Map client IPs to VPN sessions
- [ ] Handle session cleanup on disconnect

### Phase 2: K8s Proxy Listener
- [ ] Add HTTPS listener on mesh IP port 6443
- [ ] TLS certificate handling (agent self-signed or from backend)
- [ ] Request parsing and path extraction
- [ ] Response streaming back to kubectl

### Phase 3: JWT Injection
- [ ] Implement token cache with TTL
- [ ] Add backend endpoint for agent token requests
- [ ] JWT injection into proxied requests
- [ ] Handle token refresh on 401

### Phase 4: Integration
- [ ] Update mesh-vpn-client to configure kubeconfig
- [ ] Add `mesh-vpn-client k8s-config` command
- [ ] Documentation and examples
- [ ] Error handling and user feedback

## Configuration

### Agent Config
```toml
[k8s_proxy]
enabled = true
listen_port = 6443
gateway_url = "https://k8s-gateway.example.com"
token_cache_ttl_seconds = 300

[k8s_proxy.clusters]
eks-prod = { gateway = "https://k8s-prod.example.com" }
eks-dev = { gateway = "https://k8s-dev.example.com" }
```

### Environment Variables
```bash
MESH_K8S_PROXY_ENABLED=true
MESH_K8S_GATEWAY_URL=https://k8s-gateway.example.com
```

## Success Metrics

- Zero JWT management for end users
- < 50ms latency overhead for auth injection
- 100% of K8s requests attributed to correct user
- Automatic token refresh with no user intervention

## Timeline Estimate

- Phase 1: VPN Session Tracking - Foundation
- Phase 2: K8s Proxy Listener - Core functionality
- Phase 3: JWT Injection - Authentication flow
- Phase 4: Integration - User-facing polish

## Open Questions

1. **Multi-cluster**: How to route to different clusters? URL path prefix or separate ports?
2. **Certificate**: Agent TLS cert - self-signed per-agent or issued by backend CA?
3. **Offline mode**: What happens if backend is unreachable for token refresh?
4. **Rate limiting**: Per-user token request limits?
