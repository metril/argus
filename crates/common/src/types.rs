//! Common types used across crates

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// HTTP method
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Connect,
    Patch,
    Trace,
}

/// Connection information
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub client_addr: SocketAddr,
    pub target_host: String,
    pub target_port: u16,
}

/// Request statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestStats {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub allowed_requests: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

impl Default for RequestStats {
    fn default() -> Self {
        Self {
            total_requests: 0,
            blocked_requests: 0,
            allowed_requests: 0,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}
