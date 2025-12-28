//! Signaling module for P2P connection establishment
//!
//! Enables Twingate-style direct connections:
//! 1. Client and Agent both connect outbound to relay
//! 2. They exchange ICE candidates via relay signaling
//! 3. They attempt direct P2P connection (hole punching)
//! 4. Data flows directly, relay only used as fallback

use serde::{Deserialize, Serialize};

/// ICE candidate representing a potential connection endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceCandidate {
    /// IP address (public or private)
    pub ip: String,
    /// Port number
    pub port: u16,
    /// Priority (lower = better). 0 = highest priority
    pub priority: u32,
    /// Type of candidate
    pub candidate_type: CandidateType,
}

/// Type of ICE candidate
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateType {
    /// Host candidate - direct local address
    Host,
    /// Server reflexive - public address discovered via STUN
    ServerReflexive,
    /// Peer reflexive - discovered during connectivity checks
    PeerReflexive,
    /// Relay candidate - through relay server (fallback)
    Relay,
}

/// NAT type detected via STUN
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NatType {
    /// No NAT / public IP
    Open,
    /// Full cone NAT - any external host can send packets
    FullCone,
    /// Restricted cone NAT - only hosts we've sent to can reply
    Restricted,
    /// Port restricted NAT - reply must come from same port
    PortRestricted,
    /// Symmetric NAT - different mapping per destination (P2P hardest)
    Symmetric,
    /// Unknown NAT type
    Unknown,
}

/// Signaling message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SignalMessage {
    /// ICE offer from client (forwarded by relay)
    IceOffer {
        /// Requesting client's session ID (for routing response)
        client_session_id: String,
        /// Client's ICE candidates
        candidates: Vec<IceCandidate>,
        /// Client's detected NAT type
        nat_type: NatType,
    },

    /// Agent responds with its ICE candidates
    IceAnswer {
        /// Requesting client's session ID (for routing response)
        client_session_id: String,
        /// Agent's ICE candidates
        candidates: Vec<IceCandidate>,
        /// Agent's detected NAT type
        nat_type: NatType,
    },

    /// Notify peer that P2P connection was established
    P2PConnected {
        /// The peer we connected to
        peer_id: String,
        /// Which candidate worked
        connected_candidate: IceCandidate,
    },

    /// Notify peer that P2P failed, will use relay
    P2PFailed {
        /// The peer we tried to connect to
        peer_id: String,
        /// Reason for failure
        reason: String,
    },

    /// Keepalive for signaling connection
    Ping,

    /// Keepalive response
    Pong,

    /// Error response
    Error {
        code: String,
        message: String,
    },

    /// Success acknowledgment
    Ok {
        /// Optional message
        message: Option<String>,
    },
}

/// ICE update message sent to relay on registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IceUpdateMessage {
    pub candidates: Vec<IceCandidate>,
    pub nat_type: NatType,
}

/// Check if two NAT types can establish direct P2P
pub fn can_p2p_connect(client_nat: &NatType, agent_nat: &NatType) -> P2PPossibility {
    match (client_nat, agent_nat) {
        // Open NAT can connect to anything
        (NatType::Open, _) | (_, NatType::Open) => P2PPossibility::Guaranteed,

        // Full cone can connect to anything except symmetric
        (NatType::FullCone, NatType::Symmetric) | (NatType::Symmetric, NatType::FullCone) => {
            P2PPossibility::Likely
        }
        (NatType::FullCone, _) | (_, NatType::FullCone) => P2PPossibility::Guaranteed,

        // Both symmetric = very unlikely
        (NatType::Symmetric, NatType::Symmetric) => P2PPossibility::Unlikely,

        // Symmetric with restricted = unlikely
        (NatType::Symmetric, _) | (_, NatType::Symmetric) => P2PPossibility::Unlikely,

        // Restricted NATs can often work with hole punching
        (NatType::Restricted, NatType::Restricted)
        | (NatType::Restricted, NatType::PortRestricted)
        | (NatType::PortRestricted, NatType::Restricted) => P2PPossibility::Likely,

        // Both port restricted - possible with simultaneous open
        (NatType::PortRestricted, NatType::PortRestricted) => P2PPossibility::Possible,

        // Unknown - try it
        (NatType::Unknown, _) | (_, NatType::Unknown) => P2PPossibility::Possible,
    }
}

/// Likelihood of P2P connection success
#[derive(Debug, Clone, PartialEq)]
pub enum P2PPossibility {
    /// Will definitely work
    Guaranteed,
    /// Should work in most cases
    Likely,
    /// Might work, worth trying
    Possible,
    /// Unlikely to work, but try anyway
    Unlikely,
}

impl P2PPossibility {
    /// Whether we should attempt P2P
    pub fn should_attempt(&self) -> bool {
        // Always attempt except when impossible
        true
    }

    /// Timeout for P2P attempt before falling back to relay
    pub fn timeout_secs(&self) -> u64 {
        match self {
            P2PPossibility::Guaranteed => 5,
            P2PPossibility::Likely => 3,
            P2PPossibility::Possible => 2,
            P2PPossibility::Unlikely => 1,
        }
    }
}

/// Build ICE candidates from STUN result and local addresses
pub fn build_candidates(
    public_ip: Option<&str>,
    public_port: Option<u16>,
    private_ip: Option<&str>,
    private_port: Option<u16>,
) -> Vec<IceCandidate> {
    let mut candidates = Vec::new();

    // Server reflexive (public address from STUN) - highest priority for WAN
    if let (Some(ip), Some(port)) = (public_ip, public_port) {
        candidates.push(IceCandidate {
            ip: ip.to_string(),
            port,
            priority: 10,
            candidate_type: CandidateType::ServerReflexive,
        });
    }

    // Host candidate (private address) - highest priority for LAN
    if let (Some(ip), Some(port)) = (private_ip, private_port) {
        candidates.push(IceCandidate {
            ip: ip.to_string(),
            port,
            priority: 5, // Lower number = higher priority for LAN
            candidate_type: CandidateType::Host,
        });
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p2p_possibility() {
        // Open NAT always works
        assert_eq!(
            can_p2p_connect(&NatType::Open, &NatType::Symmetric),
            P2PPossibility::Guaranteed
        );

        // Both symmetric = unlikely
        assert_eq!(
            can_p2p_connect(&NatType::Symmetric, &NatType::Symmetric),
            P2PPossibility::Unlikely
        );

        // Full cone works with most
        assert_eq!(
            can_p2p_connect(&NatType::FullCone, &NatType::Restricted),
            P2PPossibility::Guaranteed
        );
    }

    #[test]
    fn test_build_candidates() {
        let candidates = build_candidates(
            Some("1.2.3.4"),
            Some(8443),
            Some("192.168.1.100"),
            Some(51820),
        );

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].candidate_type, CandidateType::ServerReflexive);
        assert_eq!(candidates[1].candidate_type, CandidateType::Host);
    }
}
