//! Plain data of the traffic accounting snapshot, shared by the proxy (producer) and the web API
//! (consumer). Nothing here is persisted.

/// Bytes by how the proxy handled the connection they crossed (up plus down).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HandlingBytes {
    pub decrypted: u64,
    pub tunnelled: u64,
    pub plain: u64,
}

/// Cumulative and live figures of one device, one (device, host) pair or an "other hosts" bucket.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TrafficRow {
    /// Bytes received from the client (requests, uploads).
    pub up: u64,
    /// Bytes sent to the client (responses, downloads).
    pub down: u64,
    /// Smoothed rates in bytes per second.
    pub up_rate: f64,
    pub down_rate: f64,
    pub connections_total: u64,
    pub connections_active: u32,
    /// Requests answered by the proxy itself (blocked, synthetic, internal), and their body bytes
    /// (already included in `down`).
    pub local_requests: u64,
    pub local_bytes: u64,
    pub handling: HandlingBytes,
    /// Unix milliseconds of the last byte; `None`: never.
    pub last_active_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostTraffic {
    pub host: String,
    pub row: TrafficRow,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DeviceTraffic {
    /// Internal identity: `t:<token digest hex>`, `x:<extension session>` or `i:<client ip>`.
    pub key: String,
    /// Profile the device last resolved to.
    pub profile_id: u64,
    pub row: TrafficRow,
    pub hosts: Vec<HostTraffic>,
    /// Hosts evicted or retired from `hosts`; part of `row`, never lost from it.
    pub other: TrafficRow,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TrafficSnapshot {
    /// Server time, unix milliseconds.
    pub at_ms: u64,
    /// How often the live figures are refreshed.
    pub interval_ms: u64,
    /// Exact process-wide totals since start or the last reset.
    pub up_total: u64,
    pub down_total: u64,
    pub devices: Vec<DeviceTraffic>,
}
