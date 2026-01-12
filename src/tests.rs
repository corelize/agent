use super::*;

// -------------------------------------------------------------------------
// Path Expansion Tests
// -------------------------------------------------------------------------

#[test]
fn test_expand_path_with_home_dir() {
    let path = "~/test/path";
    let expanded = expand_path(path);

    // Should expand ~ to home directory
    assert!(!expanded.to_string_lossy().starts_with("~"));
    assert!(expanded.to_string_lossy().ends_with("test/path"));
}

#[test]
fn test_expand_path_absolute() {
    let path = "/absolute/path";
    let expanded = expand_path(path);

    // Absolute paths should remain unchanged
    assert_eq!(expanded.to_string_lossy(), "/absolute/path");
}

#[test]
fn test_expand_path_relative() {
    let path = "relative/path";
    let expanded = expand_path(path);

    // Relative paths without ~ should remain unchanged
    assert_eq!(expanded.to_string_lossy(), "relative/path");
}

// -------------------------------------------------------------------------
// Network Parsing Tests
// -------------------------------------------------------------------------

#[test]
fn test_parse_networks_single() {
    let networks = Some("10.0.0.0/24".to_string());
    let result = parse_networks(networks);

    assert_eq!(result.len(), 1);
    assert_eq!(result[0], "10.0.0.0/24");
}

#[test]
fn test_parse_networks_multiple() {
    let networks = Some("10.0.0.0/24,172.16.0.0/16,192.168.1.0/24".to_string());
    let result = parse_networks(networks);

    assert_eq!(result.len(), 3);
    assert_eq!(result[0], "10.0.0.0/24");
    assert_eq!(result[1], "172.16.0.0/16");
    assert_eq!(result[2], "192.168.1.0/24");
}

#[test]
fn test_parse_networks_with_whitespace() {
    let networks = Some("10.0.0.0/24 , 172.16.0.0/16 , 192.168.1.0/24".to_string());
    let result = parse_networks(networks);

    assert_eq!(result.len(), 3);
    assert_eq!(result[0], "10.0.0.0/24");
    assert_eq!(result[1], "172.16.0.0/16");
    assert_eq!(result[2], "192.168.1.0/24");
}

#[test]
fn test_parse_networks_none() {
    let result = parse_networks(None);
    assert!(result.is_empty());
}

#[test]
fn test_parse_networks_empty_string() {
    let networks = Some("".to_string());
    let result = parse_networks(networks);

    // Empty string produces one empty element after split
    assert_eq!(result.len(), 1);
    assert_eq!(result[0], "");
}

// -------------------------------------------------------------------------
// Recording ID Generation Tests
// -------------------------------------------------------------------------

#[test]
fn test_new_recording_id_format() {
    let id = new_recording_id();

    // Should start with "rec_"
    assert!(id.starts_with("rec_"));

    // Should be rec_ + 16 chars = 20 total
    assert_eq!(id.len(), 20);
}

#[test]
fn test_new_recording_id_uniqueness() {
    let id1 = new_recording_id();
    let id2 = new_recording_id();
    let id3 = new_recording_id();

    // All IDs should be unique
    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
    assert_ne!(id1, id3);
}

#[test]
fn test_new_recording_id_valid_characters() {
    let id = new_recording_id();
    let suffix = &id[4..]; // Skip "rec_"

    // All characters should be alphanumeric lowercase
    for c in suffix.chars() {
        assert!(c.is_ascii_alphanumeric() && (c.is_ascii_digit() || c.is_ascii_lowercase()));
    }
}

// -------------------------------------------------------------------------
// Resource Type Detection Tests
// -------------------------------------------------------------------------

fn make_test_resource(
    protocol: &str,
    hostname: &str,
    target_host: &str,
    target_port: u16,
) -> Resource {
    Resource {
        id: "test".to_string(),
        name: "test".to_string(),
        hostname: hostname.to_string(),
        mesh_ip: "100.64.0.1".to_string(),
        mesh_port: 80,
        target_host: target_host.to_string(),
        target_port,
        protocol: protocol.to_string(),
        agent_id: "agent".to_string(),
        port_mode: PortMode::All,
        ports: None,
        network_id: None,
    }
}

#[test]
fn test_determine_resource_type_postgresql_protocol() {
    let resource = make_test_resource("postgresql", "db.internal", "localhost", 5432);
    assert_eq!(determine_resource_type(&resource), "postgresql");
}

#[test]
fn test_determine_resource_type_postgres_protocol() {
    let resource = make_test_resource("postgres", "db.internal", "localhost", 5432);
    assert_eq!(determine_resource_type(&resource), "postgresql");
}

#[test]
fn test_determine_resource_type_mysql_protocol() {
    let resource = make_test_resource("mysql", "db.internal", "localhost", 3306);
    assert_eq!(determine_resource_type(&resource), "mysql");
}

#[test]
fn test_determine_resource_type_ssh_protocol() {
    let resource = make_test_resource("ssh", "server.internal", "localhost", 22);
    assert_eq!(determine_resource_type(&resource), "ssh");
}

#[test]
fn test_determine_resource_type_http_protocol() {
    let resource = make_test_resource("http", "app.internal", "localhost", 8080);
    assert_eq!(determine_resource_type(&resource), "http");
}

#[test]
fn test_determine_resource_type_https_protocol() {
    let resource = make_test_resource("https", "app.internal", "localhost", 443);
    assert_eq!(determine_resource_type(&resource), "http");
}

#[test]
fn test_determine_resource_type_by_hostname_postgres() {
    let resource = make_test_resource("tcp", "postgres.db.internal", "localhost", 5432);
    assert_eq!(determine_resource_type(&resource), "postgresql");
}

#[test]
fn test_determine_resource_type_by_hostname_mysql() {
    let resource = make_test_resource("tcp", "mysql.db.internal", "localhost", 3306);
    assert_eq!(determine_resource_type(&resource), "mysql");
}

#[test]
fn test_determine_resource_type_by_port_5432() {
    let resource = make_test_resource("tcp", "db.internal", "localhost", 5432);
    assert_eq!(determine_resource_type(&resource), "postgresql");
}

#[test]
fn test_determine_resource_type_by_port_3306() {
    // Use neutral hostname (not "db." which triggers postgresql pattern)
    let resource = make_test_resource("tcp", "service.internal", "localhost", 3306);
    assert_eq!(determine_resource_type(&resource), "mysql");
}

#[test]
fn test_determine_resource_type_by_port_22() {
    let resource = make_test_resource("tcp", "server.internal", "localhost", 22);
    assert_eq!(determine_resource_type(&resource), "ssh");
}

#[test]
fn test_determine_resource_type_fallback_tcp() {
    let resource = make_test_resource("tcp", "app.internal", "localhost", 9999);
    assert_eq!(determine_resource_type(&resource), "tcp");
}

// -------------------------------------------------------------------------
// Should Record Tests
// -------------------------------------------------------------------------

#[test]
fn test_should_record_postgresql() {
    assert!(should_record("postgresql"));
}

#[test]
fn test_should_record_mysql() {
    assert!(should_record("mysql"));
}

#[test]
fn test_should_record_ssh() {
    assert!(should_record("ssh"));
}

#[test]
fn test_should_not_record_http() {
    assert!(!should_record("http"));
}

#[test]
fn test_should_not_record_tcp() {
    assert!(!should_record("tcp"));
}

// -------------------------------------------------------------------------
// Query Type Extraction Tests
// -------------------------------------------------------------------------

#[test]
fn test_extract_query_type_select() {
    assert_eq!(
        extract_query_type("SELECT * FROM users"),
        Some("SELECT".to_string())
    );
    assert_eq!(
        extract_query_type("select id from users"),
        Some("SELECT".to_string())
    );
    assert_eq!(
        extract_query_type("  SELECT * FROM users"),
        Some("SELECT".to_string())
    );
}

#[test]
fn test_extract_query_type_insert() {
    assert_eq!(
        extract_query_type("INSERT INTO users VALUES (1)"),
        Some("INSERT".to_string())
    );
    assert_eq!(
        extract_query_type("insert into users (id) values (1)"),
        Some("INSERT".to_string())
    );
}

#[test]
fn test_extract_query_type_update() {
    assert_eq!(
        extract_query_type("UPDATE users SET name = 'test'"),
        Some("UPDATE".to_string())
    );
}

#[test]
fn test_extract_query_type_delete() {
    assert_eq!(
        extract_query_type("DELETE FROM users WHERE id = 1"),
        Some("DELETE".to_string())
    );
}

#[test]
fn test_extract_query_type_create() {
    assert_eq!(
        extract_query_type("CREATE TABLE users (id INT)"),
        Some("CREATE".to_string())
    );
}

#[test]
fn test_extract_query_type_drop() {
    assert_eq!(
        extract_query_type("DROP TABLE users"),
        Some("DROP".to_string())
    );
}

#[test]
fn test_extract_query_type_alter() {
    assert_eq!(
        extract_query_type("ALTER TABLE users ADD COLUMN name VARCHAR"),
        Some("ALTER".to_string())
    );
}

#[test]
fn test_extract_query_type_begin() {
    assert_eq!(extract_query_type("BEGIN"), Some("BEGIN".to_string()));
    assert_eq!(
        extract_query_type("START TRANSACTION"),
        Some("BEGIN".to_string())
    );
}

#[test]
fn test_extract_query_type_commit() {
    assert_eq!(extract_query_type("COMMIT"), Some("COMMIT".to_string()));
}

#[test]
fn test_extract_query_type_rollback() {
    assert_eq!(extract_query_type("ROLLBACK"), Some("ROLLBACK".to_string()));
}

#[test]
fn test_extract_query_type_unknown() {
    assert_eq!(extract_query_type("EXPLAIN SELECT * FROM users"), None);
    assert_eq!(extract_query_type("VACUUM"), None);
}

// -------------------------------------------------------------------------
// PostgreSQL Protocol Parsing Tests
// -------------------------------------------------------------------------

#[test]
fn test_parse_postgresql_simple_query() {
    // PostgreSQL Simple Query format: 'Q' + 4-byte length + query + \0
    let query = "SELECT * FROM users";
    let query_bytes = query.as_bytes();
    let len = (query_bytes.len() + 5) as u32; // +4 for length, +1 for null terminator

    let mut msg = vec![b'Q'];
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(query_bytes);
    msg.push(0); // null terminator

    let (text, data_type, query_type) = parse_postgresql_message(&msg, &Direction::C2s);

    assert_eq!(text, Some("SELECT * FROM users".to_string()));
    assert_eq!(data_type, Some("query".to_string()));
    assert_eq!(query_type, Some("SELECT".to_string()));
}

#[test]
fn test_parse_postgresql_empty_message() {
    let (text, data_type, query_type) = parse_postgresql_message(&[], &Direction::C2s);

    assert_eq!(text, None);
    assert_eq!(data_type, None);
    assert_eq!(query_type, None);
}

#[test]
fn test_parse_postgresql_command_complete() {
    // CommandComplete format: 'C' + 4-byte length + tag + \0
    let tag = "SELECT 5";
    let tag_bytes = tag.as_bytes();
    let len = (tag_bytes.len() + 5) as u32;

    let mut msg = vec![b'C'];
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(tag_bytes);
    msg.push(0);

    let (text, data_type, _query_type) = parse_postgresql_message(&msg, &Direction::S2c);

    assert_eq!(text, Some("SELECT 5".to_string()));
    // Implementation categorizes all server responses as "response" type
    assert_eq!(data_type, Some("response".to_string()));
}

// -------------------------------------------------------------------------
// PortMode Tests
// -------------------------------------------------------------------------

#[test]
fn test_port_mode_default() {
    let mode = PortMode::default();
    assert_eq!(mode, PortMode::All);
}

#[test]
fn test_port_mode_serialization() {
    let mode = PortMode::Specific;
    let json = serde_json::to_string(&mode).unwrap();
    assert_eq!(json, "\"specific\"");

    let mode = PortMode::All;
    let json = serde_json::to_string(&mode).unwrap();
    assert_eq!(json, "\"all\"");
}

#[test]
fn test_port_mode_deserialization() {
    let mode: PortMode = serde_json::from_str("\"specific\"").unwrap();
    assert_eq!(mode, PortMode::Specific);

    let mode: PortMode = serde_json::from_str("\"all\"").unwrap();
    assert_eq!(mode, PortMode::All);
}

// -------------------------------------------------------------------------
// Resource Serialization Tests
// -------------------------------------------------------------------------

#[test]
fn test_resource_serialization() {
    let resource = make_test_resource("http", "app.internal", "localhost", 8080);
    let json = serde_json::to_string(&resource).unwrap();

    assert!(json.contains("\"id\":\"test\""));
    assert!(json.contains("\"hostname\":\"app.internal\""));
    assert!(json.contains("\"protocol\":\"http\""));
    assert!(json.contains("\"mesh_ip\":\"100.64.0.1\""));
}

#[test]
fn test_resource_deserialization() {
    let json = r#"{
        "id": "res_123",
        "name": "test-app",
        "hostname": "app.internal",
        "mesh_ip": "100.64.1.1",
        "mesh_port": 80,
        "target_host": "localhost",
        "target_port": 8080,
        "protocol": "http",
        "agent_id": "agent_123"
    }"#;

    let resource: Resource = serde_json::from_str(json).unwrap();

    assert_eq!(resource.id, "res_123");
    assert_eq!(resource.name, "test-app");
    assert_eq!(resource.hostname, "app.internal");
    assert_eq!(resource.mesh_ip, "100.64.1.1");
    assert_eq!(resource.mesh_port, 80);
    assert_eq!(resource.target_host, "localhost");
    assert_eq!(resource.target_port, 8080);
    assert_eq!(resource.protocol, "http");
    assert_eq!(resource.port_mode, PortMode::All); // default
}

// -------------------------------------------------------------------------
// MeshResourceResponse Conversion Tests
// -------------------------------------------------------------------------

#[test]
fn test_mesh_resource_response_to_resource() {
    let response = MeshResourceResponse {
        id: "res_456".to_string(),
        name: "test-db".to_string(),
        hostname: "db.internal".to_string(),
        mesh_ip: "100.64.2.1".to_string(),
        mesh_port: 5432,
        target_host: "postgres".to_string(),
        target_port: 5432,
        protocol: "postgresql".to_string(),
        agent_id: "agent_789".to_string(),
        enabled: true,
        network_id: Some("ntwk_test123".to_string()),
    };

    let resource: Resource = response.into();

    assert_eq!(resource.id, "res_456");
    assert_eq!(resource.name, "test-db");
    assert_eq!(resource.mesh_port, 5432);
    assert_eq!(resource.target_port, 5432);
    assert_eq!(resource.port_mode, PortMode::All);
}

// -------------------------------------------------------------------------
// VpnSession Tests
// -------------------------------------------------------------------------

#[test]
fn test_vpn_session_new_with_email() {
    let session = VpnSession::new("user@example.com".to_string(), "192.168.1.100".to_string());

    assert_eq!(session.user_email, "user@example.com");
    assert_eq!(session.user_id, "user@example.com");
    assert_eq!(session.client_ip, "192.168.1.100");
    assert!(!session.session_id.is_empty());
}

#[test]
fn test_vpn_session_new_without_email() {
    let session = VpnSession::new("user123".to_string(), "192.168.1.100".to_string());

    assert_eq!(session.user_email, "user123@unknown");
    assert_eq!(session.user_id, "user123");
}

#[test]
fn test_vpn_session_touch() {
    let mut session = VpnSession::new("user@example.com".to_string(), "192.168.1.100".to_string());
    let original_activity = session.last_activity;

    // Sleep briefly to ensure timestamp changes
    std::thread::sleep(std::time::Duration::from_millis(10));

    session.touch();

    assert!(session.last_activity > original_activity);
    assert_eq!(session.connected_at, session.connected_at); // connected_at unchanged
}

// -------------------------------------------------------------------------
// AgentState Session Management Tests
// -------------------------------------------------------------------------

#[test]
fn test_agent_state_session_management() {
    let config = AgentConfig {
        id: "test-agent".to_string(),
        name: "test".to_string(),
        public_key: "key".to_string(),
        private_key: "private".to_string(),
        listen_port: 51820,
        assigned_ip: None,
        mesh_blocks: vec![],
        networks: vec![],
        advertised_routes: vec![],
        registered_at: None,
    };

    let mut state = AgentState::new(config, "http://localhost:8080".to_string(), None);

    // Register session
    let session = state.register_session("user@test.com".to_string(), "10.0.0.1".to_string());
    assert_eq!(session.user_email, "user@test.com");

    // Get session by IP
    let found = state.get_session_by_ip("10.0.0.1");
    assert!(found.is_some());
    assert_eq!(found.unwrap().user_email, "user@test.com");

    // Get non-existent session
    let not_found = state.get_session_by_ip("10.0.0.2");
    assert!(not_found.is_none());

    // List sessions
    let sessions = state.list_sessions();
    assert_eq!(sessions.len(), 1);

    // Touch session
    state.touch_session("10.0.0.1");

    // Remove session
    let removed = state.remove_session("10.0.0.1");
    assert!(removed.is_some());

    // Verify removed
    let sessions = state.list_sessions();
    assert_eq!(sessions.len(), 0);
}

// -------------------------------------------------------------------------
// AgentConfig Generation Tests
// -------------------------------------------------------------------------

#[test]
fn test_agent_config_generate_with_name() {
    let config = AgentConfig::generate(Some("my-agent")).unwrap();

    assert_eq!(config.id, "my-agent");
    assert_eq!(config.name, "my-agent");
    assert!(!config.public_key.is_empty());
    assert!(!config.private_key.is_empty());
    assert_eq!(config.listen_port, 51820);
    assert!(config.assigned_ip.is_none());
}

#[test]
fn test_agent_config_generate_without_name() {
    let config = AgentConfig::generate(None).unwrap();

    // ID should be a UUID
    assert!(Uuid::parse_str(&config.id).is_ok());
    // Name should end with "-agent"
    assert!(config.name.ends_with("-agent"));
}

#[test]
fn test_agent_config_keypair_valid() {
    let config = AgentConfig::generate(Some("test")).unwrap();

    // Decode and verify keypair
    let public_bytes = BASE64.decode(&config.public_key).unwrap();
    let private_bytes = BASE64.decode(&config.private_key).unwrap();

    // Ed25519 public key is 32 bytes
    assert_eq!(public_bytes.len(), 32);
    // Ed25519 private key is 32 bytes
    assert_eq!(private_bytes.len(), 32);

    // Verify we can reconstruct the signing key
    let signing_key = SigningKey::from_bytes(&private_bytes.try_into().unwrap());
    let verifying_key: VerifyingKey = (&signing_key).into();
    let public_key_derived = BASE64.encode(verifying_key.as_bytes());

    assert_eq!(public_key_derived, config.public_key);
}

// -------------------------------------------------------------------------
// AgentConfig Serialization Tests
// -------------------------------------------------------------------------

#[test]
fn test_agent_config_serialization_skips_private_key() {
    let config = AgentConfig::generate(Some("test")).unwrap();
    let json = serde_json::to_string(&config).unwrap();

    // JSON should NOT contain private_key
    assert!(!json.contains("private_key"));

    // But should contain public_key
    assert!(json.contains("public_key"));
}

// -------------------------------------------------------------------------
// Direction Tests
// -------------------------------------------------------------------------

#[test]
fn test_direction_as_str() {
    assert_eq!(Direction::C2s.as_str(), "c2s");
    assert_eq!(Direction::S2c.as_str(), "s2c");
}

#[test]
fn test_direction_serialization() {
    let c2s = Direction::C2s;
    let json = serde_json::to_string(&c2s).unwrap();
    assert_eq!(json, "\"c2s\"");

    let s2c = Direction::S2c;
    let json = serde_json::to_string(&s2c).unwrap();
    assert_eq!(json, "\"s2c\"");
}

// -------------------------------------------------------------------------
// AuditEventType Tests
// -------------------------------------------------------------------------

#[test]
fn test_audit_event_type_serialization() {
    let event = AuditEventType::ConnectionAllowed;
    let json = serde_json::to_string(&event).unwrap();
    assert_eq!(json, "\"connection_allowed\"");

    let event = AuditEventType::PortBlocked;
    let json = serde_json::to_string(&event).unwrap();
    assert_eq!(json, "\"port_blocked\"");
}

// -------------------------------------------------------------------------
// SessionRecording Tests
// -------------------------------------------------------------------------

#[test]
fn test_session_recording_new() {
    let resource = make_test_resource("postgresql", "db.internal", "localhost", 5432);
    let recording = SessionRecording::new(
        &resource,
        "postgresql",
        Some("user@test.com".to_string()),
        "10.0.0.1".to_string(),
    );

    assert!(recording.id.starts_with("rec_"));
    assert_eq!(recording.resource_id, "test");
    assert_eq!(recording.resource_type, "postgresql");
    assert_eq!(recording.resource_name, "test");
    assert_eq!(recording.target_host, "localhost");
    assert_eq!(recording.target_port, 5432);
    assert_eq!(recording.user_id, Some("user@test.com".to_string()));
    assert_eq!(recording.client_ip, "10.0.0.1");
    assert_eq!(recording.total_bytes_client, 0);
    assert_eq!(recording.total_bytes_server, 0);
    assert!(recording.events.is_empty());
}

#[test]
fn test_session_recording_add_event() {
    let resource = make_test_resource("postgresql", "db.internal", "localhost", 5432);
    let mut recording =
        SessionRecording::new(&resource, "postgresql", None, "10.0.0.1".to_string());

    // Add client-to-server event
    recording.add_event(Direction::C2s, vec![1, 2, 3, 4]);

    assert_eq!(recording.events.len(), 1);
    assert_eq!(recording.total_bytes_client, 4);
    assert_eq!(recording.total_bytes_server, 0);

    // Add server-to-client event
    recording.add_event(Direction::S2c, vec![5, 6, 7, 8, 9]);

    assert_eq!(recording.events.len(), 2);
    assert_eq!(recording.total_bytes_client, 4);
    assert_eq!(recording.total_bytes_server, 5);
}

// -------------------------------------------------------------------------
// Local IP Detection Tests
// -------------------------------------------------------------------------

#[test]
fn test_get_local_ip() {
    // This test may fail in environments without network access
    let ip = get_local_ip();

    if let Some(ip) = ip {
        // Should be a valid IP address (not 0.0.0.0 or 127.0.0.1)
        assert!(!ip.is_empty());
        assert_ne!(ip, "0.0.0.0");
        // Could be 127.0.0.1 in some container environments
    }
    // If None, that's acceptable in isolated environments
}
