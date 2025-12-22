//! Mesh VPN Agent - Infrastructure node for mesh network
//!
//! This agent registers with a control server, receives mesh IP assignments,
//! and proxies traffic from VPN clients to backend services through QUIC tunnels.
//!
//! Architecture (Twingate-style):
//! - Agent accepts QUIC connections from VPN clients (direct or via relay)
//! - Traffic flows through encrypted QUIC streams, NOT local TCP proxies
//! - Stream types: "PROXY:host:port" for direct proxy, "TUN:" for IP packets

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use clap::Parser;
use ed25519_dalek::{SigningKey, VerifyingKey};
use quinn::{Endpoint, ServerConfig};
use rand::rngs::OsRng;
use rcgen::generate_simple_self_signed;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

// =============================================================================
// CLI Arguments
// =============================================================================

#[derive(Parser, Debug)]
#[command(name = "mesh-agent")]
#[command(about = "Mesh VPN Agent - Infrastructure node for mesh network")]
struct Args {
    /// Control server URL (e.g., http://localhost:8080)
    #[arg(long, env = "MESH_CONTROL_URL")]
    control: String,

    /// Authentication key for registration
    #[arg(long, env = "MESH_AUTH_KEY")]
    auth_key: Option<String>,

    /// State directory for agent configuration
    #[arg(long, default_value = "~/.config/mesh-agent")]
    state: String,

    /// HTTP API port
    #[arg(long, default_value = "8081")]
    port: u16,

    /// QUIC listen port
    #[arg(long, default_value = "51820")]
    quic_port: u16,

    /// Public IP address to advertise (for clients to connect)
    #[arg(long, env = "MESH_PUBLIC_IP")]
    public_ip: Option<String>,

    /// Public port to advertise (for clients to connect)
    #[arg(long, env = "MESH_PUBLIC_PORT")]
    public_port: Option<u16>,

    /// Proxy rules (format: port:host:port,port:host:port)
    #[arg(long)]
    proxies: Option<String>,

    /// Networks to proxy (comma-separated CIDR)
    #[arg(long)]
    networks: Option<String>,

    /// External CIDRs to advertise (comma-separated)
    #[arg(long)]
    advertise_routes: Option<String>,

    /// Network ID to bind this agent to (e.g., ntwk_abc123)
    #[arg(long, env = "MESH_NETWORK_ID")]
    network_id: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
}

// =============================================================================
// Data Models
// =============================================================================

/// Resource represents a backend service exposed via mesh
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Resource {
    pub id: String,
    pub name: String,
    pub mesh_ip: String,
    pub mesh_port: u16,
    pub target_host: String,
    pub target_port: u16,
    pub protocol: String,
    pub agent_id: String,
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

/// Agent state
pub struct AgentState {
    pub config: AgentConfig,
    pub resources: HashMap<String, Resource>,
    pub control_url: String,
    /// Default backend for traffic (e.g., "echo-server:80")
    pub default_backend: Option<String>,
    /// Port-based proxy routing table: port -> (host, port)
    pub proxy_backends: HashMap<u16, (String, u16)>,
    /// Auth key for control server API calls
    pub auth_key: Option<String>,
    /// Agent ID assigned by the server (UUID format)
    pub server_agent_id: Option<String>,
}

/// Registration request
#[derive(Debug, Serialize)]
struct RegisterRequest {
    agent_id: String,
    name: String,
    public_key: String,
    listen_port: u16,
    public_ip: Option<String>,
    public_port: Option<u16>,
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
}

// =============================================================================
// Agent Implementation
// =============================================================================

impl AgentConfig {
    /// Load or create agent configuration
    pub fn load_or_create(state_dir: &str) -> Result<Self> {
        let state_path = expand_path(state_dir);
        std::fs::create_dir_all(&state_path)?;

        let config_file = state_path.join("agent.json");

        if config_file.exists() {
            let data = std::fs::read_to_string(&config_file)?;
            let config: AgentConfig = serde_json::from_str(&data)?;
            info!("Loaded agent config: {}", config.id);
            return Ok(config);
        }

        // Generate new config
        let config = Self::generate()?;

        // Save config
        let data = serde_json::to_string_pretty(&config)?;
        std::fs::write(&config_file, data)?;

        info!("Generated new agent: {} ({})", config.name, config.id);
        Ok(config)
    }

    /// Generate new agent configuration with Ed25519 keypair
    fn generate() -> Result<Self> {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key: VerifyingKey = (&signing_key).into();

        let public_key = BASE64.encode(verifying_key.as_bytes());
        let private_key = BASE64.encode(signing_key.as_bytes());

        let id = Uuid::new_v4().to_string()[..8].to_string();
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "agent".to_string());

        Ok(Self {
            id,
            name: format!("{}-agent", hostname),
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
    pub fn new(config: AgentConfig, control_url: String, default_backend: Option<String>, proxy_backends: HashMap<u16, (String, u16)>) -> Self {
        Self {
            config,
            resources: HashMap::new(),
            control_url,
            default_backend,
            proxy_backends,
            auth_key: None,
            server_agent_id: None,
        }
    }
}

// =============================================================================
// Control Server Communication
// =============================================================================

/// Register agent with control server
async fn register_with_control(
    state: &Arc<RwLock<AgentState>>,
    auth_key: Option<String>,
    public_ip: Option<String>,
    public_port: Option<u16>,
    network_id: Option<String>,
) -> Result<()> {
    let (url, request) = {
        let state = state.read().await;
        let url = format!("{}/api/v1/agents/register", state.control_url.trim_end_matches('/'));

        let request = RegisterRequest {
            agent_id: state.config.id.clone(),
            name: state.config.name.clone(),
            public_key: state.config.public_key.clone(),
            listen_port: state.config.listen_port,
            public_ip,
            public_port,
            private_ip: None,
            private_port: Some(state.config.listen_port),
            networks: state.config.networks.clone(),
            advertised_routes: state.config.advertised_routes.clone(),
            auth_key: auth_key.clone(),
            network_id,
            agent_type: "proxy".to_string(),
            transport_type: "quic".to_string(),
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
        };
        (url, request)
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
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Registration failed: {}", body);
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
        // Store auth_key and server-assigned agent_id for heartbeats
        state.auth_key = auth_key.clone();
        state.server_agent_id = Some(result.agent_id.clone());
    }

    info!("Registered - Assigned IP: {}, Agent ID: {}", result.mesh_ip, result.agent_id);
    if let Some(ref cidr) = result.mesh_cidr {
        info!("Mesh CIDR: {}", cidr);
    }

    Ok(())
}

/// Send heartbeat to control server
async fn send_keepalive(state: &Arc<RwLock<AgentState>>) -> Result<()> {
    let (url, auth_key, version) = {
        let state = state.read().await;
        // Use the server-assigned agent_id for the heartbeat endpoint
        let server_agent_id = match &state.server_agent_id {
            Some(id) => id.clone(),
            None => {
                debug!("No server_agent_id yet, skipping heartbeat");
                return Ok(());
            }
        };
        let url = format!(
            "{}/api/v1/agents/{}/heartbeat",
            state.control_url.trim_end_matches('/'),
            server_agent_id
        );
        (url, state.auth_key.clone(), env!("CARGO_PKG_VERSION").to_string())
    };

    // Body matches AgentHeartbeatRequest structure expected by backend
    let body = serde_json::json!({
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

/// Fetch and update resources from control server
/// Resources are used for routing QUIC streams - no local TCP proxies needed
async fn sync_resources(state: &Arc<RwLock<AgentState>>) -> Result<()> {
    let (url, agent_id) = {
        let state = state.read().await;
        let url = format!("{}/api/v1/resources", state.control_url.trim_end_matches('/'));
        (url, state.config.id.clone())
    };

    let client = reqwest::Client::new();
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        return Ok(());
    }

    let all_resources: HashMap<String, Resource> = response.json().await?;

    // Filter resources for this agent
    let my_resources: HashMap<String, Resource> = all_resources
        .into_iter()
        .filter(|(_, r)| r.agent_id == agent_id)
        .collect();

    // Check if resources changed
    let resources_changed = {
        let state = state.read().await;
        state.resources.len() != my_resources.len()
            || my_resources.iter().any(|(id, new_res)| {
                state.resources.get(id).map_or(true, |old_res| {
                    old_res.mesh_port != new_res.mesh_port
                        || old_res.target_host != new_res.target_host
                        || old_res.target_port != new_res.target_port
                })
            })
    };

    if resources_changed {
        info!("Resource configuration updated - {} resources available for QUIC routing", my_resources.len());
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
async fn proxy_to_backend(
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
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));

    loop {
        interval.tick().await;
        if let Err(e) = sync_resources(&state).await {
            warn!("Resource sync failed: {}", e);
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

/// Parse default backend from proxies arg
/// Accepts formats: "host:port" or "port:host:port" (uses first entry as default)
fn parse_default_backend(proxies: Option<String>) -> Option<String> {
    proxies.and_then(|p| {
        // Take first entry if comma-separated
        let first = p.split(',').next()?;
        let parts: Vec<&str> = first.split(':').collect();

        match parts.len() {
            2 => {
                // Format: "host:port"
                Some(format!("{}:{}", parts[0], parts[1]))
            }
            3 => {
                // Format: "local_port:host:target_port" - use host:target_port
                Some(format!("{}:{}", parts[1], parts[2]))
            }
            _ => None,
        }
    })
}

/// Parse all proxy backends from proxies arg into port-based routing table
/// Accepts format: "port:host:target_port,port:host:target_port,..."
/// Returns HashMap<local_port, (backend_host, backend_port)>
fn parse_proxy_backends(proxies: Option<String>) -> HashMap<u16, (String, u16)> {
    let mut backends = HashMap::new();

    if let Some(p) = proxies {
        for entry in p.split(',') {
            let parts: Vec<&str> = entry.trim().split(':').collect();

            if parts.len() == 3 {
                // Format: "local_port:host:target_port"
                if let (Ok(local_port), Ok(target_port)) = (parts[0].parse::<u16>(), parts[2].parse::<u16>()) {
                    let host = parts[1].to_string();
                    info!("Registered proxy route: port {} -> {}:{}", local_port, host, target_port);
                    backends.insert(local_port, (host, target_port));
                }
            } else if parts.len() == 2 {
                // Format: "host:port" - use port 80 as local port
                if let Ok(target_port) = parts[1].parse::<u16>() {
                    let host = parts[0].to_string();
                    info!("Registered proxy route: port 80 -> {}:{}", host, target_port);
                    backends.insert(80, (host, target_port));
                }
            }
        }
    }

    backends
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
                tokio::spawn(async move {
                    if let Err(e) = handle_quic_stream(send, recv, state).await {
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
/// Twingate-style protocol:
///   - "PROXY:host:port\n" → TCP proxy to host:port
///   - "TUN:\n" → IP packet tunneling (parse IP headers)
async fn handle_quic_stream(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    state: Arc<RwLock<AgentState>>,
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
        // Format: "PROXY:host:port"
        let target = header.trim_start_matches("PROXY:");
        let parts: Vec<&str> = target.rsplitn(2, ':').collect();

        if parts.len() != 2 {
            anyhow::bail!("Invalid PROXY header format: {}", header);
        }

        let port: u16 = parts[0].parse()
            .context(format!("Invalid port in PROXY header: {}", parts[0]))?;
        let host = parts[1];

        info!("PROXY request: {}:{}", host, port);

        // Look up resource by mesh_ip to find actual backend
        let backend = {
            let state = state.read().await;

            // First try to find resource by mesh_ip
            if let Some(resource) = state.resources.values()
                .find(|r| r.mesh_ip == host && r.mesh_port == port)
            {
                info!("Found resource '{}' for {}:{} -> {}:{}",
                    resource.name, host, port, resource.target_host, resource.target_port);
                Some((resource.target_host.clone(), resource.target_port))
            }
            // Also try matching just mesh_ip with any port
            else if let Some(resource) = state.resources.values()
                .find(|r| r.mesh_ip == host)
            {
                info!("Found resource '{}' by IP only for {} -> {}:{}",
                    resource.name, host, resource.target_host, resource.target_port);
                Some((resource.target_host.clone(), resource.target_port))
            }
            // Try port-based routing from proxy_backends table
            else if host.starts_with("100.64.") {
                if let Some((backend_host, backend_port)) = state.proxy_backends.get(&port) {
                    info!("Port-based routing: {}:{} -> {}:{}", host, port, backend_host, backend_port);
                    Some((backend_host.clone(), *backend_port))
                }
                // Fall back to default_backend if no port-based route
                else if let Some(ref backend) = state.default_backend {
                    let backend_parts: Vec<&str> = backend.rsplitn(2, ':').collect();
                    if backend_parts.len() == 2 {
                        if let Ok(backend_port) = backend_parts[0].parse::<u16>() {
                            info!("No port match for {}:{}, using default backend: {}", host, port, backend);
                            Some((backend_parts[1].to_string(), backend_port))
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    warn!("No proxy route found for mesh IP {}:{}", host, port);
                    None
                }
            } else {
                // Not a mesh IP, use as-is (hostname forwarding)
                None
            }
        };

        let (backend_host, backend_port) = backend.unwrap_or_else(|| {
            debug!("Using host:port from PROXY header directly: {}:{}", host, port);
            (host.to_string(), port)
        });

        info!("Proxying to backend: {}:{}", backend_host, backend_port);
        proxy_to_backend(send, recv, &backend_host, backend_port).await?;

    } else if header.starts_with("TUN:") {
        // TUN packet mode - for future IP packet handling
        info!("TUN stream requested");
        handle_tun_stream(send, recv, state).await?;

    } else {
        // Legacy: try to find resource by mesh_ip or use default backend
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
                // Use default backend if set
                state.default_backend.as_ref().and_then(|backend| {
                    let parts: Vec<&str> = backend.rsplitn(2, ':').collect();
                    if parts.len() == 2 {
                        parts[0].parse::<u16>().ok().map(|p| (parts[1].to_string(), p))
                    } else {
                        None
                    }
                })
            }
        };

        if let Some((host, port)) = target {
            info!("Legacy QUIC request → {}:{}", host, port);
            proxy_to_backend(send, recv, &host, port).await?;
        } else {
            anyhow::bail!("Unknown stream header and no default backend: {}", header);
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
    info!("Control server: {}", args.control);

    // Load or create agent config
    let mut config = AgentConfig::load_or_create(&args.state)?;
    config.listen_port = args.quic_port;
    config.networks = parse_networks(args.networks.clone());
    config.advertised_routes = parse_networks(args.advertise_routes);

    // Parse default backend from proxies arg (format: "host:port" or "port:host:port")
    // This is used as fallback when no PROXY: header is provided
    let default_backend = parse_default_backend(args.proxies.clone());
    if let Some(ref backend) = default_backend {
        info!("Default backend for QUIC streams: {}", backend);
    }

    // Parse all proxy backends into port-based routing table
    let proxy_backends = parse_proxy_backends(args.proxies.clone());
    if !proxy_backends.is_empty() {
        info!("Port-based proxy routing: {} entries", proxy_backends.len());
    }

    // Create agent state (no TCP listeners - Twingate-style architecture)
    let state = Arc::new(RwLock::new(AgentState::new(config, args.control.clone(), default_backend, proxy_backends)));

    // Register with control server
    if let Some(ref nid) = args.network_id {
        info!("Binding agent to network: {}", nid);
    }
    register_with_control(&state, args.auth_key, args.public_ip, args.public_port, args.network_id).await?;

    info!("Agent registered successfully");
    info!("HTTP API: http://localhost:{}", args.port);
    info!("Architecture: Twingate-style (QUIC streams only, no local TCP proxies)");

    // Start background tasks
    let state_clone = state.clone();
    tokio::spawn(keepalive_loop(state_clone));

    let state_clone = state.clone();
    tokio::spawn(resource_sync_loop(state_clone));

    // NOTE: No TCP proxy listeners started - all traffic flows through QUIC streams
    // Clients send "PROXY:host:port\n" header to request proxy connections

    // Start QUIC server for VPN clients
    let quic_port = args.quic_port;
    let state_clone = state.clone();
    tokio::spawn(async move {
        if let Err(e) = run_quic_server(state_clone, quic_port).await {
            error!("QUIC server error: {}", e);
        }
    });

    info!("QUIC server: udp://0.0.0.0:{}", quic_port);

    // Run health server (blocks until shutdown)
    run_health_server(state, args.port).await?;

    Ok(())
}
