//! Mesh VPN Agent - Infrastructure node for mesh network
//!
//! This agent registers with a control server, receives mesh IP assignments,
//! and proxies traffic from VPN clients to backend services through QUIC tunnels.
//!
//! Architecture:
//! - Agent accepts QUIC connections from VPN clients (direct or via relay)
//! - Traffic flows through encrypted QUIC streams, NOT local TCP proxies
//! - Stream types: "PROXY:host:port" for direct proxy, "TUN:" for IP packets

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use rand::rngs::OsRng;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// =============================================================================
// Helper Functions
// =============================================================================

/// Detect the local IP address by connecting to a known external address
fn get_local_ip() -> Option<String> {
    // Use a UDP socket to detect the local IP that can reach external networks
    // We don't actually send anything, just get the local address
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let local_addr = socket.local_addr().ok()?;
    Some(local_addr.ip().to_string())
}

// =============================================================================
// CLI Arguments
// =============================================================================

#[derive(Parser, Debug)]
#[command(name = "mesh-agent")]
#[command(about = "Mesh VPN Agent - Infrastructure node for mesh network")]
struct Args {
    /// Control server URL (e.g., http://localhost:8080)
    #[arg(long, env = "MESH_SERVER_URL")]
    server: String,

    /// Authentication key for registration
    #[arg(long, env = "MESH_AUTH_KEY")]
    auth_key: Option<String>,

    /// State directory for agent configuration
    #[arg(long, default_value = "~/.config/mesh-agent")]
    state: String,

    /// HTTP API port
    #[arg(long, default_value = "8081")]
    port: u16,

    /// QUIC listen port (ignored when --relay-url is set)
    #[arg(long, default_value = "51820")]
    quic_port: u16,

    /// Relay server URL for NAT traversal (e.g., 1.2.3.4:8443)
    /// When set, agent connects OUTBOUND to relay instead of listening on quic_port
    #[arg(long, env = "MESH_RELAY_URL")]
    relay_url: Option<String>,

    /// Networks to proxy (comma-separated CIDR)
    #[arg(long)]
    networks: Option<String>,

    /// External CIDRs to advertise (comma-separated)
    #[arg(long)]
    advertise_routes: Option<String>,

    /// Network ID to bind this agent to (e.g., ntwk_abc123)
    #[arg(long, env = "MESH_NETWORK_ID")]
    network_id: Option<String>,

    /// Network name/slug to bind this agent to (resolved to network ID)
    #[arg(long, env = "MESH_NETWORK")]
    network: Option<String>,

    /// Agent name - used as unique identifier (required for multi-agent deployments)
    /// This name must be unique across all agents in your organization
    #[arg(long, env = "MESH_AGENT_NAME")]
    name: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Enable K8s API proxy for authenticated kubectl access
    /// When enabled, agent listens for K8s API requests and injects JWT auth
    #[arg(long, env = "MESH_K8S_PROXY_ENABLED")]
    k8s_proxy_enabled: bool,

    /// K8s proxy listen port (default: 6443)
    #[arg(long, env = "MESH_K8S_PROXY_PORT", default_value = "6443")]
    k8s_proxy_port: u16,

    /// K8s gateway URL to forward authenticated requests to
    /// (e.g., https://k8s-gateway.example.com)
    #[arg(long, env = "MESH_K8S_GATEWAY_URL")]
    k8s_gateway_url: Option<String>,
}

// =============================================================================
// Data Models
// =============================================================================

/// Port mode for resource access
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PortMode {
    /// All ports allowed
    All,
    /// Specific ports only
    Specific,
}

impl Default for PortMode {
    fn default() -> Self {
        PortMode::All
    }
}

/// Resource represents a backend service exposed via mesh
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    pub name: String,
    /// Internal DNS hostname (e.g., nginx.do.int)
    pub hostname: String,
    pub mesh_ip: String,
    pub mesh_port: u16,
    pub target_host: String,
    pub target_port: u16,
    pub protocol: String,
    pub agent_id: String,
    /// Port mode: all ports or specific
    #[serde(default)]
    pub port_mode: PortMode,
    /// Specific ports (comma-separated, e.g., "80/tcp, 443/tcp")
    pub ports: Option<String>,
}

/// Response from mesh resources list endpoint
#[derive(Debug, Deserialize)]
struct MeshResourceListResponse {
    pub total: usize,
    pub resources: Vec<MeshResourceResponse>,
}

/// Mesh resource from server (different field types)
#[derive(Debug, Deserialize)]
struct MeshResourceResponse {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub mesh_ip: String,
    pub mesh_port: i32,
    pub target_host: String,
    pub target_port: i32,
    pub protocol: String,
    pub agent_id: String,
    #[serde(default)]
    pub enabled: bool,
}

impl From<MeshResourceResponse> for Resource {
    fn from(r: MeshResourceResponse) -> Self {
        Resource {
            id: r.id,
            name: r.name,
            hostname: r.hostname,
            mesh_ip: r.mesh_ip,
            mesh_port: r.mesh_port as u16,
            target_host: r.target_host,
            target_port: r.target_port as u16,
            protocol: r.protocol,
            agent_id: r.agent_id,
            port_mode: PortMode::All, // Default to all ports for mesh resources
            ports: None,
        }
    }
}

/// Agent configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub id: String,
    pub name: String,
    pub public_key: String,
    #[serde(skip_serializing)]
    pub private_key: String,
    pub listen_port: u16,
    pub assigned_ip: Option<String>,
    pub mesh_blocks: Vec<String>,
    pub networks: Vec<String>,
    pub advertised_routes: Vec<String>,
    pub registered_at: Option<DateTime<Utc>>,
}

/// VPN session - tracks authenticated user sessions from VPN clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnSession {
    /// User email from authentication
    pub user_email: String,
    /// User ID (may be same as email or UUID)
    pub user_id: String,
    /// Client IP address (from QUIC connection)
    pub client_ip: String,
    /// When the session was established
    pub connected_at: DateTime<Utc>,
    /// Last activity timestamp
    pub last_activity: DateTime<Utc>,
    /// Session ID for tracking
    pub session_id: String,
}

impl VpnSession {
    fn new(user_id: String, client_ip: String) -> Self {
        let now = Utc::now();
        // Extract email from user_id if it looks like an email, otherwise use as-is
        let user_email = if user_id.contains('@') {
            user_id.clone()
        } else {
            format!("{}@unknown", user_id)
        };
        Self {
            user_email,
            user_id,
            client_ip,
            connected_at: now,
            last_activity: now,
            session_id: Uuid::new_v4().to_string(),
        }
    }

    fn touch(&mut self) {
        self.last_activity = Utc::now();
    }
}

/// Agent state
pub struct AgentState {
    pub config: AgentConfig,
    pub resources: HashMap<String, Resource>,
    pub control_url: String,
    /// Auth key for control server API calls
    pub auth_key: Option<String>,
    /// Agent ID assigned by the server (UUID format)
    pub server_agent_id: Option<String>,
    /// Token for authenticating with relay server
    pub relay_token: Option<String>,
    /// Network ID for re-registration
    pub network_id: Option<String>,
    /// VPN sessions - maps client IP to session info
    pub vpn_sessions: HashMap<String, VpnSession>,
}

/// Registration request
#[derive(Debug, Serialize)]
struct RegisterRequest {
    agent_id: String,
    name: String,
    public_key: String,
    listen_port: u16,
    private_ip: Option<String>,
    private_port: Option<u16>,
    networks: Vec<String>,
    advertised_routes: Vec<String>,
    auth_key: Option<String>,
    /// Network ID to bind this agent to (e.g., ntwk_abc123)
    network_id: Option<String>,
    agent_type: String,
    transport_type: String,
    version: Option<String>,
}

/// Registration response
#[derive(Debug, Deserialize)]
struct RegisterResponse {
    agent_id: String,
    mesh_ip: String,
    mesh_cidr: Option<String>,
    /// Token for authenticating with relay server
    relay_token: String,
}

/// Audit event types matching backend enum
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    ConnectionAllowed,
    ConnectionBlocked,
    PortBlocked,
    ResourceAccessed,
    ResourceDenied,
}

/// Audit status matching backend enum
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditStatus {
    Success,
    Denied,
    Warning,
    Info,
}

/// Request to create an audit event
#[derive(Debug, Serialize)]
struct AuditEventRequest {
    event_type: AuditEventType,
    status: AuditStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_port: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(default)]
    details: serde_json::Value,
}

// =============================================================================
// Session Recording Types
// =============================================================================

/// Generate a recording ID with rec_ prefix (matches backend format)
fn new_recording_id() -> String {
    const ALPHABET: [char; 36] = [
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
        'u', 'v', 'w', 'x', 'y', 'z',
    ];
    // Generate 16 random characters
    let mut id = String::with_capacity(16);
    for _ in 0..16 {
        let idx = rand::random::<usize>() % ALPHABET.len();
        id.push(ALPHABET[idx]);
    }
    format!("rec_{}", id)
}

/// Determine resource type from resource protocol or hostname
fn determine_resource_type(resource: &Resource) -> &'static str {
    let protocol = resource.protocol.to_lowercase();
    let hostname = resource.hostname.to_lowercase();
    let target = resource.target_host.to_lowercase();

    // Check protocol first
    if protocol == "postgresql" || protocol == "postgres" {
        return "postgresql";
    }
    if protocol == "mysql" {
        return "mysql";
    }
    if protocol == "ssh" {
        return "ssh";
    }
    if protocol == "http" || protocol == "https" {
        return "http";
    }

    // Infer from hostname patterns
    if hostname.contains("postgres") || hostname.contains("pg") || hostname.starts_with("db.") {
        return "postgresql";
    }
    if hostname.contains("mysql") || hostname.contains("maria") {
        return "mysql";
    }

    // Infer from target host
    if target.contains("postgres") {
        return "postgresql";
    }
    if target.contains("mysql") || target.contains("maria") {
        return "mysql";
    }

    // Infer from port
    match resource.target_port {
        5432 => "postgresql",
        3306 => "mysql",
        22 => "ssh",
        80 | 443 | 8080 | 8443 => "http",
        _ => "tcp",
    }
}

/// Check if a resource type should be recorded
fn should_record(resource_type: &str) -> bool {
    matches!(resource_type, "postgresql" | "mysql" | "ssh")
}

/// Direction of traffic flow
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    C2s, // Client to server
    S2c, // Server to client
}

impl Direction {
    fn as_str(&self) -> &'static str {
        match self {
            Direction::C2s => "c2s",
            Direction::S2c => "s2c",
        }
    }
}

/// A single recorded event
#[derive(Debug, Clone, Serialize)]
pub struct RecordingEvent {
    pub timestamp_ms: i64,
    pub direction: String,
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub affected_rows: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

/// Serialize Vec<u8> as base64
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde::{Serializer, Serialize};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        STANDARD.encode(bytes).serialize(serializer)
    }
}

/// Session recording state (held during proxy connection)
#[derive(Debug)]
pub struct SessionRecording {
    pub id: String,
    pub resource_id: String,
    pub resource_type: String,
    pub resource_name: String,
    pub target_host: String,
    pub target_port: u16,
    pub user_id: Option<String>,
    pub client_ip: String,
    pub started_at: Instant,
    pub events: Vec<RecordingEvent>,
    pub total_bytes_client: i64,
    pub total_bytes_server: i64,
}

impl SessionRecording {
    fn new(
        resource: &Resource,
        resource_type: &str,
        user_id: Option<String>,
        client_ip: String,
    ) -> Self {
        Self {
            id: new_recording_id(),
            resource_id: resource.id.clone(),
            resource_type: resource_type.to_string(),
            resource_name: resource.name.clone(),
            target_host: resource.target_host.clone(),
            target_port: resource.target_port,
            user_id,
            client_ip,
            started_at: Instant::now(),
            events: Vec::new(),
            total_bytes_client: 0,
            total_bytes_server: 0,
        }
    }

    fn add_event(&mut self, direction: Direction, data: Vec<u8>) {
        let timestamp_ms = self.started_at.elapsed().as_millis() as i64;
        let data_len = data.len() as i64;

        match direction {
            Direction::C2s => self.total_bytes_client += data_len,
            Direction::S2c => self.total_bytes_server += data_len,
        }

        // Try to parse PostgreSQL protocol for query extraction
        let (data_text, data_type, query_type) = if self.resource_type == "postgresql" {
            parse_postgresql_message(&data, &direction)
        } else {
            (None, None, None)
        };

        self.events.push(RecordingEvent {
            timestamp_ms,
            direction: direction.as_str().to_string(),
            data,
            data_text,
            data_type,
            query_type,
            affected_rows: None,
            error_code: None,
            error_message: None,
            metadata: None,
        });
    }
}

/// Parse PostgreSQL wire protocol messages for query extraction
fn parse_postgresql_message(
    data: &[u8],
    direction: &Direction,
) -> (Option<String>, Option<String>, Option<String>) {
    if data.is_empty() {
        return (None, None, None);
    }

    // PostgreSQL message format: 1 byte type + 4 bytes length + payload
    // For client messages (c2s):
    //   'Q' = Simple Query
    //   'P' = Parse (prepared statement)
    //   'E' = Execute
    // For server messages (s2c):
    //   'C' = CommandComplete
    //   'E' = ErrorResponse
    //   'T' = RowDescription
    //   'D' = DataRow

    let msg_type = data[0] as char;

    match direction {
        Direction::C2s => {
            match msg_type {
                'Q' => {
                    // Simple Query: Q + len(4) + query_string + \0
                    if data.len() > 5 {
                        let query_bytes = &data[5..];
                        if let Some(end) = query_bytes.iter().position(|&b| b == 0) {
                            if let Ok(query) = std::str::from_utf8(&query_bytes[..end]) {
                                let query_type = extract_query_type(query);
                                return (
                                    Some(query.to_string()),
                                    Some("query".to_string()),
                                    query_type,
                                );
                            }
                        }
                    }
                    (None, Some("query".to_string()), None)
                }
                'P' => {
                    // Parse (prepared statement): P + len(4) + name + \0 + query + \0 + ...
                    if data.len() > 5 {
                        let payload = &data[5..];
                        // Skip statement name
                        if let Some(name_end) = payload.iter().position(|&b| b == 0) {
                            let query_start = name_end + 1;
                            if query_start < payload.len() {
                                let query_bytes = &payload[query_start..];
                                if let Some(end) = query_bytes.iter().position(|&b| b == 0) {
                                    if let Ok(query) = std::str::from_utf8(&query_bytes[..end]) {
                                        let query_type = extract_query_type(query);
                                        return (
                                            Some(query.to_string()),
                                            Some("query".to_string()),
                                            query_type,
                                        );
                                    }
                                }
                            }
                        }
                    }
                    (None, Some("query".to_string()), None)
                }
                _ => (None, Some("raw".to_string()), None),
            }
        }
        Direction::S2c => {
            match msg_type {
                'C' => {
                    // CommandComplete: C + len(4) + tag + \0
                    if data.len() > 5 {
                        let tag_bytes = &data[5..];
                        if let Some(end) = tag_bytes.iter().position(|&b| b == 0) {
                            if let Ok(tag) = std::str::from_utf8(&tag_bytes[..end]) {
                                return (
                                    Some(tag.to_string()),
                                    Some("response".to_string()),
                                    None,
                                );
                            }
                        }
                    }
                    (None, Some("response".to_string()), None)
                }
                'E' => {
                    // ErrorResponse: E + len(4) + fields
                    // Each field: type(1) + value + \0, terminated by \0
                    if data.len() > 5 {
                        let mut error_msg = String::new();
                        let mut pos = 5;
                        while pos < data.len() && data[pos] != 0 {
                            let field_type = data[pos] as char;
                            pos += 1;
                            if let Some(end) = data[pos..].iter().position(|&b| b == 0) {
                                if let Ok(value) = std::str::from_utf8(&data[pos..pos + end]) {
                                    if field_type == 'M' {
                                        // Message
                                        error_msg = value.to_string();
                                    }
                                }
                                pos += end + 1;
                            } else {
                                break;
                            }
                        }
                        return (
                            Some(error_msg),
                            Some("error".to_string()),
                            None,
                        );
                    }
                    (None, Some("error".to_string()), None)
                }
                _ => (None, Some("raw".to_string()), None),
            }
        }
    }
}

/// Extract query type from SQL query string
fn extract_query_type(query: &str) -> Option<String> {
    let query = query.trim().to_uppercase();
    if query.starts_with("SELECT") {
        Some("SELECT".to_string())
    } else if query.starts_with("INSERT") {
        Some("INSERT".to_string())
    } else if query.starts_with("UPDATE") {
        Some("UPDATE".to_string())
    } else if query.starts_with("DELETE") {
        Some("DELETE".to_string())
    } else if query.starts_with("CREATE") {
        Some("CREATE".to_string())
    } else if query.starts_with("DROP") {
        Some("DROP".to_string())
    } else if query.starts_with("ALTER") {
        Some("ALTER".to_string())
    } else if query.starts_with("BEGIN") || query.starts_with("START") {
        Some("BEGIN".to_string())
    } else if query.starts_with("COMMIT") {
        Some("COMMIT".to_string())
    } else if query.starts_with("ROLLBACK") {
        Some("ROLLBACK".to_string())
    } else {
        None
    }
}

/// Request to create a recording on the backend
#[derive(Debug, Serialize)]
struct CreateRecordingRequest {
    resource_id: String,
    resource_type: String,
    resource_name: String,
    target_host: String,
    target_port: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    network_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<String>,
}

/// Response from creating a recording
#[derive(Debug, Deserialize)]
struct CreateRecordingResponse {
    id: String,
    status: String,
    #[serde(default)]
    started_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Request to add events to a recording
#[derive(Debug, Serialize)]
struct AddEventsRequest {
    events: Vec<RecordingEvent>,
}

/// Request to complete a recording
#[derive(Debug, Serialize)]
struct CompleteRecordingRequest {
    status: Option<String>,
}

// =============================================================================
// Agent Implementation
// =============================================================================

impl AgentConfig {
    /// Load or create agent configuration
    /// If agent_name is provided, it will be used as the unique agent ID
    pub fn load_or_create(state_dir: &str, agent_name: Option<&str>) -> Result<Self> {
        let state_path = expand_path(state_dir);
        std::fs::create_dir_all(&state_path)?;

        let config_file = state_path.join("agent.json");

        if config_file.exists() {
            let data = std::fs::read_to_string(&config_file)?;
            let mut config: AgentConfig = serde_json::from_str(&data)?;

            // If a name is provided and differs from stored ID, update the config
            if let Some(name) = agent_name {
                if config.id != name {
                    info!("Updating agent ID from {} to {}", config.id, name);
                    config.id = name.to_string();
                    config.name = name.to_string();
                    // Save updated config
                    let data = serde_json::to_string_pretty(&config)?;
                    std::fs::write(&config_file, data)?;
                }
            }

            info!("Loaded agent config: {}", config.id);
            return Ok(config);
        }

        // Generate new config with optional name as ID
        let config = Self::generate(agent_name)?;

        // Save config
        let data = serde_json::to_string_pretty(&config)?;
        std::fs::write(&config_file, data)?;

        info!("Generated new agent: {} ({})", config.name, config.id);
        Ok(config)
    }

    /// Generate new agent configuration with Ed25519 keypair
    /// If agent_name is provided, it will be used as both ID and name
    fn generate(agent_name: Option<&str>) -> Result<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = (&signing_key).into();

        let public_key = BASE64.encode(verifying_key.as_bytes());
        let private_key = BASE64.encode(signing_key.as_bytes());

        // Use provided name as ID, or generate UUID if not provided
        let (id, name) = if let Some(agent_name) = agent_name {
            (agent_name.to_string(), agent_name.to_string())
        } else {
            let hostname = hostname::get()
                .map(|h| h.to_string_lossy().to_string())
                .unwrap_or_else(|_| "agent".to_string());
            let id = Uuid::new_v4().to_string();
            (id, format!("{}-agent", hostname))
        };

        Ok(Self {
            id,
            name,
            public_key,
            private_key,
            listen_port: 51820,
            assigned_ip: None,
            mesh_blocks: vec![],
            networks: vec![],
            advertised_routes: vec![],
            registered_at: None,
        })
    }
}

impl AgentState {
    pub fn new(config: AgentConfig, control_url: String) -> Self {
        Self {
            config,
            resources: HashMap::new(),
            control_url,
            auth_key: None,
            server_agent_id: None,
            relay_token: None,
            network_id: None,
            vpn_sessions: HashMap::new(),
        }
    }

    /// Register or update a VPN session for a client
    pub fn register_session(&mut self, user_id: String, client_ip: String) -> VpnSession {
        let session = VpnSession::new(user_id, client_ip.clone());
        info!("Registered VPN session: {} -> {} (session: {})",
            session.user_email, client_ip, session.session_id);
        self.vpn_sessions.insert(client_ip, session.clone());
        session
    }

    /// Get session by client IP
    pub fn get_session_by_ip(&self, client_ip: &str) -> Option<&VpnSession> {
        self.vpn_sessions.get(client_ip)
    }

    /// Update session activity timestamp
    pub fn touch_session(&mut self, client_ip: &str) {
        if let Some(session) = self.vpn_sessions.get_mut(client_ip) {
            session.touch();
        }
    }

    /// Remove session by client IP
    pub fn remove_session(&mut self, client_ip: &str) -> Option<VpnSession> {
        if let Some(session) = self.vpn_sessions.remove(client_ip) {
            info!("Removed VPN session: {} -> {} (session: {})",
                session.user_email, client_ip, session.session_id);
            Some(session)
        } else {
            None
        }
    }

    /// Get all active sessions
    pub fn list_sessions(&self) -> Vec<&VpnSession> {
        self.vpn_sessions.values().collect()
    }
}

// =============================================================================
// Control Server Communication
// =============================================================================

/// Register agent with control server
async fn register_with_control(
    state: &Arc<RwLock<AgentState>>,
    auth_key: Option<String>,
    network_id: Option<String>,
) -> Result<()> {
    let (url, request, network_id) = {
        let state = state.read().await;
        let url = format!("{}/api/v1/agents/register", state.control_url.trim_end_matches('/'));

        // Detect local IP for client connectivity
        let local_ip = get_local_ip();
        if let Some(ref ip) = local_ip {
            info!("Detected local IP: {}", ip);
        } else {
            warn!("Could not detect local IP - clients may not be able to connect directly");
        }

        let request = RegisterRequest {
            agent_id: state.config.id.clone(),
            name: state.config.name.clone(),
            public_key: state.config.public_key.clone(),
            listen_port: state.config.listen_port,
            private_ip: local_ip,
            private_port: Some(state.config.listen_port),
            networks: state.config.networks.clone(),
            advertised_routes: state.config.advertised_routes.clone(),
            auth_key: auth_key.clone(),
            network_id: network_id.clone(),
            agent_type: "proxy".to_string(),
            transport_type: "quic".to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
        };
        (url, request, network_id)
    };

    info!("Registering with control server: {}", url);

    let client = reqwest::Client::new();
    let mut req_builder = client.post(&url).json(&request);

    // Add authorization header if auth_key is provided
    if let Some(ref key) = request.auth_key {
        req_builder = req_builder.header("Authorization", format!("Bearer {}", key));
    }

    let response = req_builder
        .send()
        .await
        .context("Failed to connect to control server")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();

        // Check for network_not_found error
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
            if json.get("error").and_then(|e| e.as_str()) == Some("network_not_found") {
                let message = json.get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Network not found");
                error!("FATAL: {}", message);
                error!("Please check your NETWORK_ID environment variable or --network-id argument");
                error!("Use --network <slug> to specify network by name, or verify the network exists in the control server");
                std::process::exit(1);
            }
        }

        anyhow::bail!("Registration failed ({}): {}", status, body);
    }

    let result: RegisterResponse = response.json().await?;

    // Update state
    {
        let mut state = state.write().await;
        state.config.assigned_ip = Some(result.mesh_ip.clone());
        if let Some(ref cidr) = result.mesh_cidr {
            state.config.mesh_blocks = vec![cidr.clone()];
        }
        state.config.registered_at = Some(Utc::now());
        // Store auth_key, network_id, and server-assigned agent_id for re-registration
        state.auth_key = auth_key.clone();
        state.network_id = network_id.clone();
        state.server_agent_id = Some(result.agent_id.clone());
        // Store relay token for relay server authentication
        state.relay_token = Some(result.relay_token.clone());
    }

    // Log both local agent ID (used for relay) and server-assigned ID
    {
        let s = state.read().await;
        info!("Registered - Assigned IP: {}, Local Agent ID: {}, Server Agent ID: {}",
              result.mesh_ip, s.config.id, result.agent_id);
    }
    info!("Relay token received for relay server authentication");
    if let Some(ref cidr) = result.mesh_cidr {
        info!("Mesh CIDR: {}", cidr);
    }

    Ok(())
}

/// Response from network lookup by slug
#[derive(Debug, Deserialize)]
struct NetworkLookupResponse {
    id: String,
    name: String,
    slug: String,
}

/// Resolve network slug to network ID via control server
async fn resolve_network_slug(server_url: &str, slug: &str, auth_key: Option<&str>) -> Result<String> {
    let url = format!("{}/api/v1/vpn/networks/by-slug/{}", server_url.trim_end_matches('/'), slug);

    info!("Resolving network slug '{}' to ID", slug);

    let client = reqwest::Client::new();
    let mut req_builder = client.get(&url);

    if let Some(key) = auth_key {
        req_builder = req_builder.header("Authorization", format!("Bearer {}", key));
    }

    let response = req_builder
        .send()
        .await
        .context("Failed to connect to control server for network lookup")?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Network lookup failed ({}): {}", status, body);
    }

    let result: NetworkLookupResponse = response.json().await
        .context("Failed to parse network lookup response")?;

    info!("Resolved network '{}' (slug: {}) to ID: {}", result.name, result.slug, result.id);

    Ok(result.id)
}

/// Send heartbeat to control server
async fn send_keepalive(state: &Arc<RwLock<AgentState>>) -> Result<()> {
    let (url, auth_key, version, agent_id) = {
        let state = state.read().await;
        // Use the server-assigned agent_id for the heartbeat body
        let server_agent_id = match &state.server_agent_id {
            Some(id) => id.clone(),
            None => {
                debug!("No server_agent_id yet, skipping heartbeat");
                return Ok(());
            }
        };
        let url = format!(
            "{}/api/v1/agents/heartbeat",
            state.control_url.trim_end_matches('/')
        );
        (url, state.auth_key.clone(), env!("CARGO_PKG_VERSION").to_string(), server_agent_id)
    };

    // Body matches AgentHeartbeatRequest structure expected by backend
    let body = serde_json::json!({
        "agent_id": agent_id,
        "status": "online",
        "version": version,
    });

    let client = reqwest::Client::new();
    let mut req_builder = client.post(&url).json(&body);

    // Add X-Agent-Key header for authentication
    if let Some(ref key) = auth_key {
        req_builder = req_builder.header("X-Agent-Key", key);
    }

    match req_builder.send().await {
        Ok(response) => {
            if response.status().is_success() {
                debug!("Heartbeat sent successfully");
            } else {
                debug!("Heartbeat failed with status: {}", response.status());
            }
        }
        Err(e) => {
            debug!("Heartbeat request failed: {}", e);
        }
    }

    Ok(())
}

/// Post an audit event to the control server (fire-and-forget)
/// Used for connection logging (allowed, blocked, port denied)
/// This is non-blocking - failures are logged but don't affect the main request
async fn post_audit_event(
    control_url: &str,
    auth_key: Option<&str>,
    _agent_id: Option<&str>,
    event: AuditEventRequest,
) {
    let url = format!("{}/api/v1/audit/events", control_url.trim_end_matches('/'));

    // Use a client with a short timeout to avoid blocking
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create HTTP client for audit: {}", e);
            return;
        }
    };

    let mut req_builder = client.post(&url).json(&event);

    // Add X-Agent-Key header for authentication
    if let Some(key) = auth_key {
        req_builder = req_builder.header("X-Agent-Key", key);
    }

    match req_builder.send().await {
        Ok(response) => {
            if response.status().is_success() {
                debug!("Audit event posted: {:?}", event.event_type);
            } else {
                warn!("Audit event failed with status: {}", response.status());
            }
        }
        Err(e) => {
            // Log but don't fail - audit is best-effort
            warn!("Audit event request failed: {}", e);
        }
    }
}

/// Upload a completed session recording to the backend (batch upload)
/// Called when a proxy connection closes
async fn upload_recording(
    control_url: &str,
    auth_key: Option<&str>,
    network_id: Option<&str>,
    agent_id: Option<&str>,
    user_id: Option<&str>,
    recording: SessionRecording,
) {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to create HTTP client for recording upload: {}", e);
            return;
        }
    };

    // Step 1: Create the recording
    let create_url = format!("{}/api/v1/recordings", control_url.trim_end_matches('/'));
    let create_req = CreateRecordingRequest {
        resource_id: recording.resource_id.clone(),
        resource_type: recording.resource_type.clone(),
        resource_name: recording.resource_name.clone(),
        target_host: recording.target_host.clone(),
        target_port: recording.target_port as i32,
        network_id: network_id.map(|s| s.to_string()),
        agent_id: agent_id.map(|s| s.to_string()),
        device_id: None,
        client_ip: Some(recording.client_ip.clone()),
        user_agent: Some("mesh-agent".to_string()),
    };

    let mut req_builder = client.post(&create_url).json(&create_req);
    if let Some(key) = auth_key {
        req_builder = req_builder.header("X-Agent-Key", key);
    }
    if let Some(uid) = user_id {
        req_builder = req_builder.header("X-User-Id", uid);
    }

    let recording_id = match req_builder.send().await {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<CreateRecordingResponse>().await {
                    Ok(resp) => {
                        info!("Created recording {} for resource {}", resp.id, recording.resource_name);
                        resp.id
                    }
                    Err(e) => {
                        warn!("Failed to parse create recording response: {}", e);
                        return;
                    }
                }
            } else {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                warn!("Failed to create recording ({}): {}", status, body);
                return;
            }
        }
        Err(e) => {
            warn!("Failed to create recording: {}", e);
            return;
        }
    };

    // Step 2: Add events (in batches if there are many)
    if !recording.events.is_empty() {
        let events_url = format!("{}/api/v1/recordings/{}/events", control_url.trim_end_matches('/'), recording_id);

        // Batch events in chunks of 100 to avoid oversized requests
        for chunk in recording.events.chunks(100) {
            let events_req = AddEventsRequest {
                events: chunk.to_vec(),
            };

            let mut req_builder = client.post(&events_url).json(&events_req);
            if let Some(key) = auth_key {
                req_builder = req_builder.header("X-Agent-Key", key);
            }

            match req_builder.send().await {
                Ok(response) => {
                    if !response.status().is_success() {
                        let status = response.status();
                        let body = response.text().await.unwrap_or_default();
                        warn!("Failed to add recording events ({}): {}", status, body);
                    }
                }
                Err(e) => {
                    warn!("Failed to add recording events: {}", e);
                }
            }
        }

        debug!("Uploaded {} events for recording {}", recording.events.len(), recording_id);
    }

    // Step 3: Complete the recording
    let complete_url = format!("{}/api/v1/recordings/{}/complete", control_url.trim_end_matches('/'), recording_id);
    let complete_req = CompleteRecordingRequest {
        status: Some("completed".to_string()),
    };

    let mut req_builder = client.post(&complete_url).json(&complete_req);
    if let Some(key) = auth_key {
        req_builder = req_builder.header("X-Agent-Key", key);
    }

    match req_builder.send().await {
        Ok(response) => {
            if response.status().is_success() {
                let duration_ms = recording.started_at.elapsed().as_millis();
                info!(
                    "Completed recording {} ({} events, {} c2s bytes, {} s2c bytes, {}ms)",
                    recording_id,
                    recording.events.len(),
                    recording.total_bytes_client,
                    recording.total_bytes_server,
                    duration_ms
                );
            } else {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                warn!("Failed to complete recording ({}): {}", status, body);
            }
        }
        Err(e) => {
            warn!("Failed to complete recording: {}", e);
        }
    }
}

/// Fetch and update resources from control server
/// Resources are used for routing QUIC streams - no local TCP proxies needed
async fn sync_resources(state: &Arc<RwLock<AgentState>>) -> Result<()> {
    let (url, auth_key, agent_name) = {
        let state = state.read().await;
        // Use the agents/resources endpoint which filters by agent via X-Agent-Key + X-Agent-Name
        let url = format!("{}/api/v1/agents/resources", state.control_url.trim_end_matches('/'));
        (url, state.auth_key.clone(), state.config.name.clone())
    };

    let client = reqwest::Client::new();
    let mut req_builder = client.get(&url);

    // Add X-Agent-Key header for authentication
    if let Some(ref key) = auth_key {
        req_builder = req_builder.header("X-Agent-Key", key);
    }

    // Add X-Agent-Name header for agent identification (allows sharing auth keys)
    req_builder = req_builder.header("X-Agent-Name", &agent_name);

    let response = req_builder.send().await?;

    if !response.status().is_success() {
        debug!("Resource sync returned status: {}", response.status());
        return Ok(());
    }

    // Server returns resources already filtered for this agent
    let list_response: MeshResourceListResponse = response.json().await?;

    // Convert to HashMap<id, Resource>
    let my_resources: HashMap<String, Resource> = list_response.resources
        .into_iter()
        .map(|r| {
            let id = r.id.clone();
            (id, Resource::from(r))
        })
        .collect();

    // Check if resources changed
    let resources_changed = {
        let state = state.read().await;
        let len_changed = state.resources.len() != my_resources.len();

        if len_changed {
            debug!("Resource count changed: {} -> {}", state.resources.len(), my_resources.len());
        }

        let content_changed = my_resources.iter().any(|(id, new_res)| {
            match state.resources.get(id) {
                None => {
                    debug!("New resource ID not in state: {}", id);
                    true
                }
                Some(old_res) => {
                    let changed = old_res.mesh_port != new_res.mesh_port
                        || old_res.target_host != new_res.target_host
                        || old_res.target_port != new_res.target_port;
                    if changed {
                        debug!("Resource {} changed: port {}->{}  host {}->{}  target_port {}->{}",
                            id, old_res.mesh_port, new_res.mesh_port,
                            old_res.target_host, new_res.target_host,
                            old_res.target_port, new_res.target_port);
                    }
                    changed
                }
            }
        });

        len_changed || content_changed
    };

    if resources_changed {
        info!("Resource configuration updated - {} resources available for QUIC routing", my_resources.len());

        // Log each resource for visibility
        for (_id, resource) in &my_resources {
            if resource.port_mode == PortMode::Specific {
                if let Some(ref ports) = resource.ports {
                    info!("  → {} → {} ({})", resource.hostname, resource.target_host, ports);
                } else {
                    info!("  → {} → {}", resource.hostname, resource.target_host);
                }
            } else {
                info!("  → {} → {}", resource.hostname, resource.target_host);
            }
        }

        let mut state = state.write().await;
        state.resources = my_resources;
    }

    Ok(())
}

// =============================================================================
// Backend Proxy (via QUIC streams only, no local TCP listeners)
// =============================================================================

/// Proxy data between QUIC stream and backend TCP connection
/// Called when a QUIC stream requests "PROXY:host:port"
/// Optionally records traffic if recording is provided
async fn proxy_to_backend(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    target_host: &str,
    target_port: u16,
    recording: Option<&mut SessionRecording>,
) -> Result<()> {
    let target_addr = format!("{}:{}", target_host, target_port);
    let mut backend = TcpStream::connect(&target_addr).await
        .context(format!("Failed to connect to backend: {}", target_addr))?;

    if recording.is_some() {
        info!("QUIC → TCP proxy established (RECORDING): {}", target_addr);
    } else {
        info!("QUIC → TCP proxy established: {}", target_addr);
    }

    let (mut backend_read, mut backend_write) = backend.split();

    // Use channels to collect recorded data
    let (c2s_tx, mut c2s_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    let (s2c_tx, mut s2c_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);

    let is_recording = recording.is_some();

    // QUIC recv → TCP backend (with optional recording)
    let quic_to_tcp = async {
        let mut buf = vec![0u8; 8192];
        loop {
            match recv.read(&mut buf).await? {
                Some(n) if n > 0 => {
                    if is_recording {
                        // Send copy to recording channel
                        let _ = c2s_tx.send(buf[..n].to_vec()).await;
                    }
                    backend_write.write_all(&buf[..n]).await?;
                }
                _ => break,
            }
        }
        drop(c2s_tx); // Close channel when done
        Ok::<_, anyhow::Error>(())
    };

    // TCP backend → QUIC send (with optional recording)
    let tcp_to_quic = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = backend_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if is_recording {
                // Send copy to recording channel
                let _ = s2c_tx.send(buf[..n].to_vec()).await;
            }
            send.write_all(&buf[..n]).await?;
        }
        drop(s2c_tx); // Close channel when done
        Ok::<_, anyhow::Error>(())
    };

    // Collect recorded events from channels
    let record_collector = async {
        if let Some(rec) = recording {
            loop {
                tokio::select! {
                    biased;
                    Some(data) = c2s_rx.recv() => {
                        rec.add_event(Direction::C2s, data);
                    }
                    Some(data) = s2c_rx.recv() => {
                        rec.add_event(Direction::S2c, data);
                    }
                    else => break,
                }
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    // Run all three tasks concurrently
    tokio::select! {
        r = quic_to_tcp => { r?; }
        r = tcp_to_quic => { r?; }
        r = record_collector => { r?; }
    }

    Ok(())
}

/// Proxy without recording (simpler version for non-recordable resources)
async fn proxy_to_backend_simple(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    target_host: &str,
    target_port: u16,
) -> Result<()> {
    let target_addr = format!("{}:{}", target_host, target_port);
    let mut backend = TcpStream::connect(&target_addr).await
        .context(format!("Failed to connect to backend: {}", target_addr))?;

    info!("QUIC → TCP proxy established: {}", target_addr);

    let (mut backend_read, mut backend_write) = backend.split();

    // QUIC recv → TCP backend
    let quic_to_tcp = async {
        let mut buf = vec![0u8; 8192];
        loop {
            match recv.read(&mut buf).await? {
                Some(n) if n > 0 => {
                    backend_write.write_all(&buf[..n]).await?;
                }
                _ => break,
            }
        }
        Ok::<_, anyhow::Error>(())
    };

    // TCP backend → QUIC send
    let tcp_to_quic = async {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = backend_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            send.write_all(&buf[..n]).await?;
        }
        Ok::<_, anyhow::Error>(())
    };

    tokio::select! {
        r = quic_to_tcp => { r?; }
        r = tcp_to_quic => { r?; }
    }

    Ok(())
}

// =============================================================================
// Health Check Server
// =============================================================================

/// Run simple HTTP health check server
async fn run_health_server(state: Arc<RwLock<AgentState>>, port: u16) -> Result<()> {
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
    info!("Health server listening on port {}", port);

    loop {
        let (mut socket, _) = listener.accept().await?;
        let state = state.clone();

        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            if socket.read(&mut buf).await.is_ok() {
                let state = state.read().await;
                let response = serde_json::json!({
                    "status": "healthy",
                    "agent_id": state.config.id,
                    "assigned_ip": state.config.assigned_ip,
                    "resources": state.resources.len(),
                });

                let body = serde_json::to_string(&response).unwrap();
                let http_response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );

                let _ = socket.write_all(http_response.as_bytes()).await;
            }
        });
    }
}

// =============================================================================
// Background Tasks
// =============================================================================

/// Run keepalive loop
async fn keepalive_loop(state: Arc<RwLock<AgentState>>) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));

    loop {
        interval.tick().await;
        if let Err(e) = send_keepalive(&state).await {
            warn!("Keepalive failed: {}", e);
        }
    }
}

/// Run resource sync loop
async fn resource_sync_loop(state: Arc<RwLock<AgentState>>) {
    // Sync immediately on first load
    info!("Loading resources from control server...");
    if let Err(e) = sync_resources(&state).await {
        warn!("Initial resource sync failed: {}", e);
    } else {
        let state = state.read().await;
        if state.resources.is_empty() {
            info!("No resources assigned to this agent yet");
        } else {
            info!("Initial resource load complete - {} resources ready", state.resources.len());
        }
    }

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

    loop {
        interval.tick().await;
        if let Err(e) = sync_resources(&state).await {
            warn!("Resource sync failed: {}", e);
        }
    }
}

/// Run periodic re-registration loop to refresh relay token
/// Re-registers every 10 minutes to ensure relay token stays valid
async fn reregistration_loop(state: Arc<RwLock<AgentState>>) {
    // Wait 10 minutes before first re-registration (initial registration already done)
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(600));
    interval.tick().await; // Skip the first immediate tick

    loop {
        interval.tick().await;

        // Get auth_key and network_id from state for re-registration
        let (auth_key, network_id) = {
            let s = state.read().await;
            (s.auth_key.clone(), s.network_id.clone())
        };

        info!("Re-registering with control server to refresh relay token...");

        match register_with_control(&state, auth_key, network_id).await {
            Ok(()) => {
                info!("Re-registration successful - relay token refreshed");
            }
            Err(e) => {
                warn!("Re-registration failed: {} - will retry in 10 minutes", e);
            }
        }
    }
}

// =============================================================================
// Utilities
// =============================================================================

/// Expand ~ in path
fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

/// Parse networks from CLI
fn parse_networks(networks: Option<String>) -> Vec<String> {
    networks
        .map(|n| n.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_default()
}

// =============================================================================
// QUIC Server
// =============================================================================

/// Generate self-signed certificate for QUIC server
fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = generate_simple_self_signed(vec!["mesh-agent".to_string()])
        .context("Failed to generate self-signed certificate")?;

    let key = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());

    Ok((vec![cert_der], PrivateKeyDer::Pkcs8(key)))
}

/// Create QUIC server configuration
fn create_quic_server_config() -> Result<ServerConfig> {
    let (certs, key) = generate_self_signed_cert()?;

    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create rustls config")?;

    server_crypto.alpn_protocols = vec![b"mesh-vpn".to_vec()];

    let mut server_config = ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .context("Failed to create QUIC server config")?
    ));

    // Configure transport to match client keepalive settings
    // Increase max idle timeout to 60 seconds to handle slow clients
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(60).try_into().unwrap()));
    server_config.transport_config(Arc::new(transport_config));

    Ok(server_config)
}

/// Run QUIC server to accept VPN client connections
async fn run_quic_server(state: Arc<RwLock<AgentState>>, quic_port: u16) -> Result<()> {
    // Install rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok(); // Ignore if already installed

    let server_config = create_quic_server_config()?;

    let bind_addr: SocketAddr = format!("0.0.0.0:{}", quic_port).parse()?;
    let endpoint = Endpoint::server(server_config, bind_addr)
        .context("Failed to create QUIC endpoint")?;

    info!("QUIC server listening on {}", bind_addr);

    loop {
        match endpoint.accept().await {
            Some(connecting) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_quic_connection(connecting, state).await {
                        warn!("QUIC connection error: {}", e);
                    }
                });
            }
            None => {
                error!("QUIC endpoint closed");
                break;
            }
        }
    }

    Ok(())
}

// =============================================================================
// Relay Client (for NAT traversal)
// =============================================================================

/// Skip server certificate verification for relay connections (development)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

/// Create QUIC client config for relay connections
fn create_relay_client_config() -> Result<ClientConfig> {
    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    // Match the relay server's ALPN protocol
    crypto.alpn_protocols = vec![b"mesh-relay".to_vec()];

    let mut client_config = ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .context("Failed to create QUIC client config")?,
    ));

    // Configure transport for long-lived connection
    // Agent sends QUIC-level PINGs every 15s, timeout after 5 minutes of no activity
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    transport_config.max_idle_timeout(Some(
        std::time::Duration::from_secs(300)  // 5 minutes - matches relay
            .try_into()
            .unwrap(),
    ));
    client_config.transport_config(Arc::new(transport_config));

    Ok(client_config)
}

/// Connect to relay server and handle forwarded streams
async fn run_relay_client(
    state: Arc<RwLock<AgentState>>,
    relay_addr: SocketAddr,
    agent_id: String,
    relay_token: String,
) -> Result<()> {
    // Install rustls crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    let client_config = create_relay_client_config()?;

    info!("Connecting to relay server: {}", relay_addr);

    // Create client endpoint
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)
        .context("Failed to create QUIC client endpoint")?;
    endpoint.set_default_client_config(client_config);

    // Connect to relay
    let connection = endpoint
        .connect(relay_addr, "mesh-relay")?
        .await
        .context("Failed to connect to relay server")?;

    info!("Connected to relay server: {}", relay_addr);

    // Register with relay by sending RELAY:AGENT:agent_id:relay_token header
    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .context("Failed to open registration stream")?;

    let registration = format!("RELAY:AGENT:{}:{}\n", agent_id, relay_token);
    send.write_all(registration.as_bytes()).await?;
    send.flush().await?;

    // Wait for acknowledgment
    let mut ack_buf = vec![0u8; 64];
    let mut ack_len = 0;
    loop {
        match recv.read(&mut ack_buf[ack_len..]).await? {
            Some(n) => {
                ack_len += n;
                if ack_buf[..ack_len].contains(&b'\n') {
                    break;
                }
            }
            None => anyhow::bail!("Connection closed before acknowledgment"),
        }
    }

    let ack = String::from_utf8_lossy(&ack_buf[..ack_len]);
    let ack_trimmed = ack.trim();
    if ack_trimmed != "OK" {
        if ack_trimmed.starts_with("ERROR:") {
            let error_msg = ack_trimmed.trim_start_matches("ERROR:");
            anyhow::bail!("Relay authentication failed: {}", error_msg);
        }
        anyhow::bail!("Relay registration failed: {}", ack_trimmed);
    }

    info!("Authenticated with relay as agent: {}", agent_id);
    info!("Relay mode active - accepting forwarded streams from clients");

    // Accept forwarded streams from relay AND send periodic keepalives
    // The relay opens bi-streams to us when clients request routing
    let mut keepalive_interval = tokio::time::interval(std::time::Duration::from_secs(20));
    keepalive_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            // Accept incoming streams from relay (client forwarding)
            result = connection.accept_bi() => {
                match result {
                    Ok((send, recv)) => {
                        let state = state.clone();
                        let remote_addr = connection.remote_address();
                        tokio::spawn(async move {
                            if let Err(e) = handle_quic_stream(send, recv, state, remote_addr).await {
                                debug!("Relay stream error: {}", e);
                            }
                        });
                    }
                    Err(quinn::ConnectionError::ApplicationClosed(reason)) => {
                        info!("Relay connection closed: {:?}", reason);
                        break;
                    }
                    Err(quinn::ConnectionError::TimedOut) => {
                        warn!("Relay connection timed out - reconnecting...");
                        break;
                    }
                    Err(e) => {
                        warn!("Relay accept_bi error: {}", e);
                        break;
                    }
                }
            }

            // Send periodic application-level keepalives to relay
            _ = keepalive_interval.tick() => {
                match connection.open_bi().await {
                    Ok((mut send, mut recv)) => {
                        if let Err(e) = send.write_all(b"KEEPALIVE\n").await {
                            warn!("Failed to send keepalive: {}", e);
                            break;
                        }
                        if let Err(e) = send.flush().await {
                            warn!("Failed to flush keepalive: {}", e);
                            break;
                        }
                        // Wait for OK response - if this fails, connection is dead
                        let mut buf = [0u8; 16];
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(5),
                            recv.read(&mut buf)
                        ).await {
                            Ok(Ok(Some(_))) => {
                                debug!("Relay keepalive OK");
                            }
                            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => {
                                warn!("Keepalive response failed - reconnecting");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to open keepalive stream: {}", e);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Run relay client with automatic reconnection
async fn run_relay_client_loop(
    state: Arc<RwLock<AgentState>>,
    relay_url: String,
) -> Result<()> {
    // Try parsing as SocketAddr first (IP:port), otherwise resolve as hostname:port
    let relay_addr: SocketAddr = match relay_url.parse() {
        Ok(addr) => addr,
        Err(_) => {
            // Resolve hostname:port format
            use tokio::net::lookup_host;
            let addrs: Vec<SocketAddr> = lookup_host(&relay_url)
                .await
                .context(format!("Failed to resolve relay URL: {}", relay_url))?
                .collect();
            addrs.into_iter().next()
                .ok_or_else(|| anyhow::anyhow!("No addresses found for relay URL: {}", relay_url))?
        }
    };

    // Get agent_id and relay_token from state
    // Always use the local config.id (persisted UUID) for relay registration
    // This ensures each agent instance has a unique identity even with shared auth keys
    let (agent_id, relay_token) = {
        let s = state.read().await;
        let id = s.config.id.clone();
        let token = s.relay_token.clone().ok_or_else(|| {
            anyhow::anyhow!("No relay token available - agent may not be registered")
        })?;
        (id, token)
    };

    loop {
        match run_relay_client(state.clone(), relay_addr, agent_id.clone(), relay_token.clone()).await {
            Ok(()) => {
                info!("Relay connection closed gracefully");
            }
            Err(e) => {
                error!("Relay connection error: {}", e);
            }
        }

        // Wait before reconnecting
        info!("Reconnecting to relay in 5 seconds...");
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}

/// Handle incoming QUIC connection
async fn handle_quic_connection(
    connecting: quinn::Incoming,
    state: Arc<RwLock<AgentState>>,
) -> Result<()> {
    let connection = connecting.await?;
    let remote_addr = connection.remote_address();
    info!("QUIC connection from: {}", remote_addr);

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let state = state.clone();
                let addr = remote_addr;
                tokio::spawn(async move {
                    if let Err(e) = handle_quic_stream(send, recv, state, addr).await {
                        debug!("QUIC stream error: {}", e);
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                info!("QUIC connection closed by client: {}", remote_addr);
                break;
            }
            Err(e) => {
                warn!("QUIC accept_bi error: {}", e);
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single QUIC bidirectional stream
/// protocol:
///   - "PROXY:host:port\n" → TCP proxy to host:port
///   - "TUN:\n" → IP packet tunneling (parse IP headers)
async fn handle_quic_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    state: Arc<RwLock<AgentState>>,
    remote_addr: SocketAddr,
) -> Result<()> {
    // Read header line (format: "PROXY:host:port\n" or "TUN:\n")
    let mut header_buf = Vec::with_capacity(256);
    let mut byte = [0u8; 1];

    loop {
        match recv.read(&mut byte).await? {
            Some(1) => {
                if byte[0] == b'\n' {
                    break;
                }
                header_buf.push(byte[0]);
                if header_buf.len() > 256 {
                    anyhow::bail!("Header too long");
                }
            }
            _ => anyhow::bail!("Connection closed before header"),
        }
    }

    let header = String::from_utf8_lossy(&header_buf);
    debug!("QUIC stream header: {}", header);

    if header.starts_with("PROXY:") {
        // Format: "PROXY:host:port:user_id" (user_id may be empty)
        // Or with relay-forwarded mesh_ip: "PROXY:host:port:user_id::mesh_ip"
        // The "::" delimiter separates the proxy part from the forwarded mesh IP
        let target = header.trim_start_matches("PROXY:");

        // Check if relay forwarded client's mesh IP (indicated by "::" delimiter)
        let (proxy_part, forwarded_mesh_ip) = if let Some(delimiter_pos) = target.find("::") {
            let (proxy, mesh_ip_part) = target.split_at(delimiter_pos);
            let mesh_ip = mesh_ip_part.trim_start_matches("::");
            (proxy, if mesh_ip.is_empty() { None } else { Some(mesh_ip.to_string()) })
        } else {
            (target, None)
        };

        // Split from right: user_id, port, host (host may contain colons for IPv6)
        let parts: Vec<&str> = proxy_part.rsplitn(3, ':').collect();

        // Handle both old format (host:port) and new format (host:port:user_id)
        let (host, port, user_id): (&str, u16, Option<String>) = if parts.len() == 3 {
            // New format: [user_id, port, host]
            let user_id_str = parts[0];
            let port: u16 = parts[1].parse()
                .context(format!("Invalid port in PROXY header: {}", parts[1]))?;
            let host = parts[2];
            let user_id = if user_id_str.is_empty() { None } else { Some(user_id_str.to_string()) };
            (host, port, user_id)
        } else if parts.len() == 2 {
            // Old format: [port, host] - for backwards compatibility
            let port: u16 = parts[0].parse()
                .context(format!("Invalid port in PROXY header: {}", parts[0]))?;
            let host = parts[1];
            (host, port, None)
        } else {
            anyhow::bail!("Invalid PROXY header format: {}", header);
        };

        // Determine effective client IP for audit logging:
        // - Use forwarded mesh_ip if provided by relay (client's actual mesh IP)
        // - Otherwise fall back to remote_addr (direct connection or relay's IP)
        let effective_client_ip = forwarded_mesh_ip.as_ref()
            .map(|s| s.as_str())
            .unwrap_or_else(|| "");
        let effective_client_ip = if effective_client_ip.is_empty() {
            remote_addr.ip().to_string()
        } else {
            effective_client_ip.to_string()
        };

        info!("PROXY request: {}:{} (user: {:?}, client_ip: {})", host, port, user_id, effective_client_ip);

        // Register/update VPN session if user_id is provided
        if let Some(ref uid) = user_id {
            let mut state = state.write().await;
            state.register_session(uid.clone(), effective_client_ip.clone());
        }

        // Look up resource by hostname or mesh_ip to find actual backend (synced from network)
        // Port enforcement: if mesh_port is set (non-zero), only that port is allowed
        // Returns: Ok((target_host, target_port, resource_id, Option<Resource>)) or Err((message, resource_id, resource_name, allowed_port, target_host))
        let backend: Result<Option<(String, u16, Option<String>, Option<Resource>)>, (String, Option<String>, Option<String>, Option<u16>, Option<String>)> = {
            let state = state.read().await;

            // Helper: determine effective target port
            // If resource.target_port is 0, use the request port (passthrough mode)
            let effective_port = |resource: &Resource, request_port: u16| -> u16 {
                if resource.target_port == 0 {
                    request_port  // Passthrough: use port from request
                } else {
                    resource.target_port  // Fixed port: use configured port
                }
            };

            // Helper: check if request port is allowed for this resource
            // If mesh_port is 0 (any port) or matches request port, it's allowed
            let port_allowed = |resource: &Resource, request_port: u16| -> bool {
                resource.mesh_port == 0 || resource.mesh_port == request_port
            };

            // First try to find resource by hostname (e.g., echo.dev.int)
            if let Some(resource) = state.resources.values()
                .find(|r| r.hostname == host)
            {
                // Enforce port restriction
                if !port_allowed(resource, port) {
                    warn!("Port {} not allowed for resource '{}' (allowed port: {})",
                        port, resource.name, resource.mesh_port);
                    // Return detailed error with resource info for audit logging
                    Err((
                        format!("Port {} not allowed for {} (allowed: {})", port, resource.name, resource.mesh_port),
                        Some(resource.id.clone()),
                        Some(resource.name.clone()),
                        Some(resource.mesh_port),
                        Some(resource.target_host.clone()),
                    ))
                } else {
                    let target_port = effective_port(resource, port);
                    info!("Found resource '{}' for hostname {} -> {}:{} (mesh_port: {}, target_port: {})",
                        resource.name, host, resource.target_host, target_port, resource.mesh_port, resource.target_port);
                    Ok(Some((resource.target_host.clone(), target_port, Some(resource.id.clone()), Some(resource.clone()))))
                }
            }
            // Then try to find resource by mesh_ip and port
            else if let Some(resource) = state.resources.values()
                .find(|r| r.mesh_ip == host && r.mesh_port == port)
            {
                let target_port = effective_port(resource, port);
                info!("Found resource '{}' for {}:{} -> {}:{} (configured port: {})",
                    resource.name, host, port, resource.target_host, target_port, resource.target_port);
                Ok(Some((resource.target_host.clone(), target_port, Some(resource.id.clone()), Some(resource.clone()))))
            }
            // Also try matching just mesh_ip with any port
            else if let Some(resource) = state.resources.values()
                .find(|r| r.mesh_ip == host)
            {
                // Enforce port restriction for mesh_ip matches too
                if !port_allowed(resource, port) {
                    warn!("Port {} not allowed for resource '{}' at {} (allowed port: {})",
                        port, resource.name, host, resource.mesh_port);
                    // Return detailed error with resource info for audit logging
                    Err((
                        format!("Port {} not allowed for {} (allowed: {})", port, resource.name, resource.mesh_port),
                        Some(resource.id.clone()),
                        Some(resource.name.clone()),
                        Some(resource.mesh_port),
                        Some(resource.target_host.clone()),
                    ))
                } else {
                    let target_port = effective_port(resource, port);
                    info!("Found resource '{}' by IP only for {} -> {}:{} (mesh_port: {}, target_port: {})",
                        resource.name, host, resource.target_host, target_port, resource.mesh_port, resource.target_port);
                    Ok(Some((resource.target_host.clone(), target_port, Some(resource.id.clone()), Some(resource.clone()))))
                }
            }
            // For mesh IPs with no resource match, log warning
            else if host.starts_with("100.64.") {
                warn!("No resource found for mesh IP {}:{}", host, port);
                Ok(None)
            } else {
                // Not a mesh IP or known hostname, allow direct hostname forwarding
                Ok(None)
            }
        };

        // Handle port rejection - post audit event for blocked ports
        let backend = match backend {
            Ok(b) => b,
            Err((msg, err_resource_id, err_resource_name, allowed_port, err_target_host)) => {
                // Post audit event for port blocked with detailed info
                let (control_url, auth_key, network_id) = {
                    let state = state.read().await;
                    (
                        state.control_url.clone(),
                        state.auth_key.clone(),
                        state.network_id.clone(),
                    )
                };
                let event = AuditEventRequest {
                    event_type: AuditEventType::PortBlocked,
                    status: AuditStatus::Denied,
                    user_id: user_id.clone(),
                    network_id,
                    resource_id: err_resource_id,
                    agent_id: None, // Agent identified via X-Agent-Key header
                    source_ip: Some(effective_client_ip.clone()),
                    target_host: err_target_host, // Use resource's target_host for proper frontend matching
                    target_port: Some(port as i32),
                    message: Some(msg.clone()),
                    details: serde_json::json!({
                        "requested_port": port,
                        "allowed_port": allowed_port,
                        "resource_name": err_resource_name,
                    }),
                };
                tokio::spawn(async move {
                    post_audit_event(&control_url, auth_key.as_deref(), None, event).await;
                });

                send.write_all(format!("ERROR:{}\n", msg).as_bytes()).await?;
                send.finish().ok();
                return Ok(());
            }
        };

        let (backend_host, backend_port, resource_id, resource) = backend
            .map(|(h, p, rid, res)| (h, p, rid, res))
            .unwrap_or_else(|| {
                debug!("Using host:port from PROXY header directly: {}:{}", host, port);
                (host.to_string(), port, None, None)
            });

        // Determine if we should record this session
        let resource_type = resource.as_ref().map(|r| determine_resource_type(r));
        let should_record_session = resource_type.as_ref().map(|t| should_record(t)).unwrap_or(false);

        // Capture state info for recording before dropping the lock
        let (control_url, auth_key, network_id, agent_id) = {
            let state = state.read().await;
            (
                state.control_url.clone(),
                state.auth_key.clone(),
                state.network_id.clone(),
                state.server_agent_id.clone(),
            )
        };

        // Post audit event for connection allowed
        {
            let target_host_clone = backend_host.clone();
            let ctrl_url = control_url.clone();
            let auth = auth_key.clone();
            let net_id = network_id.clone();
            let user_id_clone = user_id.clone();
            let res_id = resource_id.clone();
            let event = AuditEventRequest {
                event_type: AuditEventType::ConnectionAllowed,
                status: AuditStatus::Success,
                user_id: user_id_clone,
                network_id: net_id,
                resource_id: res_id,
                agent_id: None, // Agent identified via X-Agent-Key header
                source_ip: Some(effective_client_ip.clone()),
                target_host: Some(target_host_clone),
                target_port: Some(backend_port as i32),
                message: Some(format!("Proxying to {}:{}", backend_host, backend_port)),
                details: serde_json::json!({}),
            };
            tokio::spawn(async move {
                post_audit_event(&ctrl_url, auth.as_deref(), None, event).await;
            });
        }

        // Proxy with optional session recording
        if should_record_session {
            if let (Some(res), Some(res_type)) = (resource.as_ref(), resource_type.as_ref()) {
                info!("Proxying to backend (RECORDING {}): {}:{}", res_type, backend_host, backend_port);

                // Create session recording
                let mut recording = SessionRecording::new(
                    res,
                    res_type,
                    user_id.clone(),
                    effective_client_ip.clone(),
                );
                let recording_id = recording.id.clone();
                info!("Started session recording {} for {} ({})", recording_id, res.name, res_type);

                // Run proxy with recording
                let proxy_result = proxy_to_backend(send, recv, &backend_host, backend_port, Some(&mut recording)).await;

                // Upload recording (async, fire-and-forget)
                let ctrl_url = control_url.clone();
                let auth = auth_key.clone();
                let net_id = network_id.clone();
                let agent = agent_id.clone();
                let uid = user_id.clone();
                tokio::spawn(async move {
                    upload_recording(
                        &ctrl_url,
                        auth.as_deref(),
                        net_id.as_deref(),
                        agent.as_deref(),
                        uid.as_deref(),
                        recording,
                    ).await;
                });

                proxy_result?;
            } else {
                // Fallback to simple proxy if resource info is missing
                info!("Proxying to backend: {}:{}", backend_host, backend_port);
                proxy_to_backend_simple(send, recv, &backend_host, backend_port).await?;
            }
        } else {
            // Non-recordable resource - use simple proxy
            info!("Proxying to backend: {}:{}", backend_host, backend_port);
            proxy_to_backend_simple(send, recv, &backend_host, backend_port).await?;
        }

    } else if header.starts_with("HEALTH:") {
        // Health check from VPN client - respond with OK
        debug!("Health check received");
        send.write_all(b"OK\n").await?;
        send.finish().ok();
        return Ok(());

    } else if header.starts_with("TUN:") {
        // TUN packet mode - for future IP packet handling
        info!("TUN stream requested");
        handle_tun_stream(send, recv, state).await?;

    } else {
        // Legacy: try to find resource by mesh_ip
        let target = {
            let state = state.read().await;
            // Check if header looks like "mesh_ip:port"
            if let Some(pos) = header.rfind(':') {
                let (ip, port_str) = header.split_at(pos);
                let port: u16 = port_str[1..].parse().unwrap_or(0);

                state.resources.values()
                    .find(|r| r.mesh_ip == ip && r.mesh_port == port)
                    .map(|r| (r.target_host.clone(), r.target_port))
            } else {
                None
            }
        };

        if let Some((host, port)) = target {
            info!("Legacy QUIC request → {}:{}", host, port);
            proxy_to_backend(send, recv, &host, port, None).await?;
        } else {
            anyhow::bail!("Unknown stream header and no matching resource: {}", header);
        }
    }

    Ok(())
}

/// Handle TUN packet stream - parse IP packets and forward to backends
async fn handle_tun_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    state: Arc<RwLock<AgentState>>,
) -> Result<()> {
    // TUN packets: [2-byte length][IP packet data]
    // Parse IP header to get destination, then forward appropriately

    loop {
        // Read packet length (2 bytes, big-endian)
        let mut len_buf = [0u8; 2];
        match recv.read_exact(&mut len_buf).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::FinishedEarly(_)) => break,
            Err(quinn::ReadExactError::ReadError(e)) => return Err(e.into()),
        }
        let pkt_len = u16::from_be_bytes(len_buf) as usize;

        if pkt_len == 0 || pkt_len > 65535 {
            warn!("Invalid TUN packet length: {}", pkt_len);
            continue;
        }

        // Read the IP packet
        let mut pkt = vec![0u8; pkt_len];
        match recv.read_exact(&mut pkt).await {
            Ok(()) => {}
            Err(quinn::ReadExactError::FinishedEarly(_)) => break,
            Err(quinn::ReadExactError::ReadError(e)) => return Err(e.into()),
        }

        // Parse IPv4 header (first 20+ bytes)
        if pkt.len() < 20 {
            warn!("Packet too short for IP header");
            continue;
        }

        let version = (pkt[0] >> 4) & 0x0F;
        if version != 4 {
            debug!("Non-IPv4 packet (version {}), skipping", version);
            continue;
        }

        let ihl = (pkt[0] & 0x0F) as usize * 4; // header length in bytes
        let protocol = pkt[9];
        let dst_ip = format!("{}.{}.{}.{}", pkt[16], pkt[17], pkt[18], pkt[19]);

        debug!("TUN packet: proto={} dst={} len={}", protocol, dst_ip, pkt_len);

        // Find resource by destination IP
        let target = {
            let state = state.read().await;
            state.resources.values()
                .find(|r| r.mesh_ip == dst_ip)
                .map(|r| (r.target_host.clone(), r.target_port, r.name.clone()))
        };

        if let Some((host, port, name)) = target {
            // For TCP (protocol 6), we need to extract the port from the TCP header
            if protocol == 6 && pkt.len() >= ihl + 4 {
                let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
                debug!("TCP packet to {}:{} → backend {}:{}", dst_ip, dst_port, host, port);

                // TODO: Full TCP state machine would be complex
                // For now, we rely on PROXY: streams for actual connections
            }

            info!("TUN packet for resource '{}' ({}:{})", name, host, port);
        } else {
            debug!("No resource for destination IP: {}", dst_ip);
        }

        // Echo back acknowledgment (simplified)
        let ack = [0u8; 2]; // Empty ack
        send.write_all(&ack).await?;
    }

    Ok(())
}

// =============================================================================
// K8s API Proxy (for authenticated kubectl access)
// =============================================================================

/// Cached JWT token for K8s authentication
#[derive(Debug, Clone)]
struct CachedK8sToken {
    jwt: String,
    user_email: String,
    expires_at: DateTime<Utc>,
}

impl CachedK8sToken {
    fn is_expired(&self) -> bool {
        // Consider expired if less than 30 seconds remaining
        Utc::now() + chrono::Duration::seconds(30) > self.expires_at
    }
}

/// K8s proxy state - holds token cache and configuration
struct K8sProxyState {
    /// JWT token cache: user_email -> CachedK8sToken
    token_cache: HashMap<String, CachedK8sToken>,
    /// K8s gateway URL to forward requests to
    gateway_url: String,
    /// Backend control URL for JWT requests
    control_url: String,
    /// Agent auth key for requesting JWTs
    auth_key: Option<String>,
    /// Network ID for token requests
    network_id: Option<String>,
}

impl K8sProxyState {
    fn new(gateway_url: String, control_url: String, auth_key: Option<String>, network_id: Option<String>) -> Self {
        Self {
            token_cache: HashMap::new(),
            gateway_url,
            control_url,
            auth_key,
            network_id,
        }
    }

    /// Get or refresh JWT for a user
    async fn get_token(&mut self, user_email: &str) -> Result<String> {
        // Check cache first
        if let Some(cached) = self.token_cache.get(user_email) {
            if !cached.is_expired() {
                debug!("Using cached K8s token for {}", user_email);
                return Ok(cached.jwt.clone());
            }
        }

        // Request new token from backend
        info!("Requesting K8s token for {} from backend", user_email);
        let token = self.request_token_from_backend(user_email).await?;

        // Cache it (assume 15 minute expiry if not specified)
        let cached = CachedK8sToken {
            jwt: token.clone(),
            user_email: user_email.to_string(),
            expires_at: Utc::now() + chrono::Duration::minutes(15),
        };
        self.token_cache.insert(user_email.to_string(), cached);

        Ok(token)
    }

    /// Request JWT from backend control server
    async fn request_token_from_backend(&self, user_email: &str) -> Result<String> {
        let url = format!("{}/api/v1/agent/k8s-token", self.control_url.trim_end_matches('/'));

        let body = serde_json::json!({
            "user_email": user_email,
            "network_id": self.network_id,
        });

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .context("Failed to create HTTP client")?;

        let mut req_builder = client.post(&url).json(&body);

        if let Some(ref key) = self.auth_key {
            req_builder = req_builder.header("X-Agent-Key", key);
        }

        let response = req_builder.send().await
            .context("Failed to request K8s token from backend")?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Failed to get K8s token ({}): {}", status, body);
        }

        #[derive(Deserialize)]
        struct TokenResponse {
            token: String,
            #[serde(default)]
            expires_at: Option<String>,
        }

        let token_resp: TokenResponse = response.json().await
            .context("Failed to parse K8s token response")?;

        Ok(token_resp.token)
    }
}

/// Run K8s API proxy server
/// Listens on specified port, intercepts kubectl requests, injects JWT, forwards to gateway
async fn run_k8s_proxy(
    agent_state: Arc<RwLock<AgentState>>,
    k8s_state: Arc<RwLock<K8sProxyState>>,
    listen_port: u16,
) -> Result<()> {
    // Generate self-signed certificate for HTTPS
    let (certs, key) = generate_self_signed_cert()?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .context("Failed to create TLS config")?;
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let bind_addr = format!("0.0.0.0:{}", listen_port);
    let listener = TcpListener::bind(&bind_addr).await
        .context(format!("Failed to bind K8s proxy on {}", bind_addr))?;

    info!("K8s API proxy listening on https://{}", bind_addr);
    info!("Configure kubectl with: kubectl config set-cluster mesh --server=https://127.0.0.1:{}", listen_port);

    loop {
        let (tcp_stream, peer_addr) = listener.accept().await?;
        let agent_state = agent_state.clone();
        let k8s_state = k8s_state.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            match tls_acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    if let Err(e) = handle_k8s_request(agent_state, k8s_state, tls_stream, peer_addr).await {
                        warn!("K8s proxy request error from {}: {}", peer_addr, e);
                    }
                }
                Err(e) => {
                    debug!("TLS handshake failed from {}: {}", peer_addr, e);
                }
            }
        });
    }
}

/// Handle a single K8s API request
async fn handle_k8s_request(
    agent_state: Arc<RwLock<AgentState>>,
    k8s_state: Arc<RwLock<K8sProxyState>>,
    mut tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
    peer_addr: SocketAddr,
) -> Result<()> {
    // Read HTTP request
    let mut buf = vec![0u8; 8192];
    let n = tls_stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    let request_data = &buf[..n];
    let request_str = String::from_utf8_lossy(request_data);

    // Parse basic HTTP request info (method, path)
    let first_line = request_str.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        anyhow::bail!("Invalid HTTP request: {}", first_line);
    }
    let method = parts[0];
    let path = parts[1];

    debug!("K8s proxy: {} {} from {}", method, path, peer_addr);

    // Look up VPN session by client IP to get user identity
    let client_ip = peer_addr.ip().to_string();
    let user_email = {
        let state = agent_state.read().await;
        state.get_session_by_ip(&client_ip)
            .map(|s| s.user_email.clone())
    };

    let user_email = match user_email {
        Some(email) => email,
        None => {
            // No VPN session found - reject request
            warn!("K8s proxy: No VPN session for client {}", client_ip);
            let response = "HTTP/1.1 401 Unauthorized\r\n\
                Content-Type: application/json\r\n\
                Content-Length: 68\r\n\r\n\
                {\"error\":\"unauthorized\",\"message\":\"No VPN session for this client\"}";
            tls_stream.write_all(response.as_bytes()).await?;
            return Ok(());
        }
    };

    info!("K8s proxy: {} {} from {} (user: {})", method, path, client_ip, user_email);

    // Get JWT token for user
    let jwt = {
        let mut k8s = k8s_state.write().await;
        match k8s.get_token(&user_email).await {
            Ok(token) => token,
            Err(e) => {
                warn!("K8s proxy: Failed to get token for {}: {}", user_email, e);
                let response = format!(
                    "HTTP/1.1 500 Internal Server Error\r\n\
                    Content-Type: application/json\r\n\
                    Content-Length: {}\r\n\r\n\
                    {{\"error\":\"token_error\",\"message\":\"{}\"}}",
                    47 + e.to_string().len(),
                    e
                );
                tls_stream.write_all(response.as_bytes()).await?;
                return Ok(());
            }
        }
    };

    // Get gateway URL
    let gateway_url = {
        let k8s = k8s_state.read().await;
        k8s.gateway_url.clone()
    };

    // Forward request to K8s gateway with JWT
    let forwarded_url = format!("{}{}", gateway_url.trim_end_matches('/'), path);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // Accept self-signed gateway certs
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("Failed to create HTTP client for K8s gateway")?;

    // Build forwarded request
    let req_builder = match method {
        "GET" => client.get(&forwarded_url),
        "POST" => client.post(&forwarded_url),
        "PUT" => client.put(&forwarded_url),
        "PATCH" => client.patch(&forwarded_url),
        "DELETE" => client.delete(&forwarded_url),
        _ => client.request(reqwest::Method::from_bytes(method.as_bytes())?, &forwarded_url),
    };

    // Extract request body if present (for POST/PUT/PATCH)
    let body_start = request_str.find("\r\n\r\n").map(|i| i + 4);
    let body = body_start.and_then(|start| {
        if start < request_data.len() {
            Some(request_data[start..].to_vec())
        } else {
            None
        }
    });

    let mut req_builder = req_builder
        .header("Authorization", format!("Bearer {}", jwt))
        .header("X-Forwarded-For", &client_ip)
        .header("X-Forwarded-User", &user_email);

    // Copy relevant headers from original request
    for line in request_str.lines().skip(1) {
        if line.is_empty() || line == "\r" {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim();
            // Forward content-type and accept headers
            if key == "content-type" || key == "accept" {
                req_builder = req_builder.header(&key, value);
            }
        }
    }

    if let Some(body_data) = body {
        req_builder = req_builder.body(body_data);
    }

    // Send request to gateway
    let response = req_builder.send().await
        .context("Failed to forward request to K8s gateway")?;

    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await?;

    // Build HTTP response
    let mut response_str = format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status.canonical_reason().unwrap_or(""));

    // Copy headers
    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            response_str.push_str(&format!("{}: {}\r\n", key, v));
        }
    }
    response_str.push_str("\r\n");

    // Send response back to client
    tls_stream.write_all(response_str.as_bytes()).await?;
    tls_stream.write_all(&body).await?;

    debug!("K8s proxy: {} {} -> {} ({} bytes)", method, path, status, body.len());

    Ok(())
}

// =============================================================================
// Main Entry Point
// =============================================================================

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    info!("Starting Mesh VPN Agent");
    info!("Control server: {}", args.server);

    // Load or create agent config (name is used as unique ID if provided)
    let mut config = AgentConfig::load_or_create(&args.state, args.name.as_deref())?;
    config.listen_port = args.quic_port;
    config.networks = parse_networks(args.networks.clone());
    config.advertised_routes = parse_networks(args.advertise_routes);

    info!("Agent ID: {}", config.id);

    // Create agent state (resources synced from network, no static proxies)
    let state = Arc::new(RwLock::new(AgentState::new(config, args.server.clone())));

    // Resolve network: prefer --network-id, otherwise resolve --network slug
    let network_id = match (args.network_id, args.network) {
        (Some(id), _) => {
            info!("Using network ID: {}", id);
            Some(id)
        }
        (None, Some(slug)) => {
            let id = resolve_network_slug(&args.server, &slug, args.auth_key.as_deref()).await?;
            Some(id)
        }
        (None, None) => None,
    };

    // Register with control server
    if let Some(ref nid) = network_id {
        info!("Binding agent to network: {}", nid);
    }
    register_with_control(&state, args.auth_key.clone(), network_id).await?;

    info!("Agent registered successfully");
    info!("HTTP API: http://localhost:{}", args.port);

    // Start background tasks
    let state_clone = state.clone();
    tokio::spawn(keepalive_loop(state_clone));

    let state_clone = state.clone();
    tokio::spawn(resource_sync_loop(state_clone));

    // Re-registration loop to refresh relay token every 10 minutes
    let state_clone = state.clone();
    tokio::spawn(reregistration_loop(state_clone));

    // NOTE: No TCP proxy listeners started - all traffic flows through QUIC streams
    // Clients send "PROXY:host:port\n" header to request proxy connections

    // Choose between relay mode (outbound connection) or direct QUIC server
    if let Some(relay_url) = args.relay_url {
        // Relay mode: connect OUTBOUND to relay server
        // No port exposure required - works behind NAT
        info!("Relay mode enabled - connecting to: {}", relay_url);
        info!("No port exposure required (NAT-friendly)");

        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_relay_client_loop(state_clone, relay_url).await {
                error!("Relay client error: {}", e);
            }
        });
    } else {
        // Direct mode: listen on QUIC port for incoming connections
        // Requires port exposure (firewall/NAT traversal)
        let quic_port = args.quic_port;
        let state_clone = state.clone();
        tokio::spawn(async move {
            if let Err(e) = run_quic_server(state_clone, quic_port).await {
                error!("QUIC server error: {}", e);
            }
        });

        info!("QUIC server: udp://0.0.0.0:{}", quic_port);
        info!("Direct mode - port {} must be accessible to clients", quic_port);
    }

    // Start K8s API proxy if enabled
    if args.k8s_proxy_enabled {
        if let Some(ref gateway_url) = args.k8s_gateway_url {
            let k8s_state = {
                let agent = state.read().await;
                K8sProxyState::new(
                    gateway_url.clone(),
                    agent.control_url.clone(),
                    agent.auth_key.clone(),
                    agent.network_id.clone(),
                )
            };
            let k8s_state = Arc::new(RwLock::new(k8s_state));
            let state_clone = state.clone();
            let k8s_port = args.k8s_proxy_port;

            tokio::spawn(async move {
                if let Err(e) = run_k8s_proxy(state_clone, k8s_state, k8s_port).await {
                    error!("K8s proxy error: {}", e);
                }
            });

            info!("K8s proxy: https://0.0.0.0:{} -> {}", args.k8s_proxy_port, gateway_url);
        } else {
            warn!("K8s proxy enabled but --k8s-gateway-url not set, skipping");
        }
    }

    // Run health server (blocks until shutdown)
    run_health_server(state, args.port).await?;

    Ok(())
}
