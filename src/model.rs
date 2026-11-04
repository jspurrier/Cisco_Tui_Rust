use chrono::Local;

/// Represents the Cisco operating system family running on the connected router.
/// This determines the CLI syntax used for IP addressing, L2Transport, and whether
/// configuration changes require an explicit `commit` statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CiscoOs {
    /// Classic Cisco IOS and IOS-XE (changes apply immediately in config mode, exited with `end`).
    Ios,
    /// Cisco IOS-XR (two-stage configuration model requiring an explicit `commit` before `end`).
    IosXr,
}

impl CiscoOs {
    /// Returns a human-readable label for display in the UI header and modal titles.
    pub fn display_name(&self) -> &'static str {
        match self {
            CiscoOs::Ios => "Cisco IOS / IOS-XE",
            CiscoOs::IosXr => "Cisco IOS-XR",
        }
    }
}

/// Represents a single router interface row parsed from `show interfaces description`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InterfaceEntry {
    /// Interface identifier (for example `Gi0/0/0/6`, `TenGigE0/0/0/1.100`, or `Loopback0`).
    pub name: String,
    /// Physical/administrative layer state (`up`, `down`, or `admin down`).
    pub status: String,
    /// Line protocol state (`up` or `down`).
    pub protocol: String,
    /// Configured circuit or port description text.
    pub description: String,
}

/// Parameters required to establish an SSH session with a Cisco router.
#[derive(Clone, Debug)]
pub struct ConnectionConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub operating_system: CiscoOs,
    pub use_mock_router: bool,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            host: "192.0.2.1".to_string(),
            port: 22,
            username: "admin".to_string(),
            password: String::new(),
            operating_system: CiscoOs::IosXr,
            use_mock_router: false,
        }
    }
}

/// Severity level for entries in the session audit log.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
    Error,
}

/// A timestamped audit log entry recording commands sent to the router and their results.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ActionLog {
    pub timestamp: String,
    pub level: LogLevel,
    pub message: String,
    pub command: Option<String>,
    pub output: Option<String>,
}

impl ActionLog {
    /// Creates a basic log entry stamped with the current local time.
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        let current_timestamp = Local::now().format("%H:%M:%S").to_string();
        Self {
            timestamp: current_timestamp,
            level,
            message: message.into(),
            command: None,
            output: None,
        }
    }

    /// Creates a detailed log entry that includes the CLI command and router output.
    pub fn with_details(
        level: LogLevel,
        message: impl Into<String>,
        command: impl Into<String>,
        output: impl Into<String>,
    ) -> Self {
        let current_timestamp = Local::now().format("%H:%M:%S").to_string();
        Self {
            timestamp: current_timestamp,
            level,
            message: message.into(),
            command: Some(command.into()),
            output: Some(output.into()),
        }
    }
}

/// Column used for sorting the main interface table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortField {
    Name,
    Status,
    Protocol,
    Description,
}

/// Distinguishes between a point-to-point `xconnect group` (`p2p`) and a multipoint
/// `bridge group` (`bridge-domain`) under the Cisco IOS-XR `l2vpn` hierarchy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum L2vpnServiceType {
    /// Multipoint E-LAN / VPLS / BVI service (`l2vpn` -> `bridge group <G>` -> `bridge-domain <BD>`).
    #[default]
    BridgeDomain,
    /// Point-to-point E-Line pseudowire service (`l2vpn` -> `xconnect group <G>` -> `p2p <NAME>`).
    XconnectP2p,
}

impl L2vpnServiceType {
    pub fn short_label(&self) -> &'static str {
        match self {
            L2vpnServiceType::BridgeDomain => "BRIDGE-DOM",
            L2vpnServiceType::XconnectP2p => "XCONNECT",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            L2vpnServiceType::BridgeDomain => "Bridge-Domain",
            L2vpnServiceType::XconnectP2p => "Xconnect P2P",
        }
    }
}

/// Attachment circuit (`interface <subinterface>`) inside a `bridge-domain` or `p2p` xconnect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2vpnAttachmentInterface {
    /// Full interface name from `show running-config l2vpn` (for example `"Bundle-Ether10.100"` or `"GigabitEthernet0/0/0/1.100"`).
    pub interface_name: String,
    /// Whether `split-horizon group` is configured under this interface in a `bridge-domain`.
    pub split_horizon_group: bool,
}

/// Pseudowire neighbor (`neighbor [ipv4] <peer_ipv4> pw-id <pw_id>`) inside a `p2p` xconnect or `vfi`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2vpnPseudowireNeighbor {
    pub peer_ipv4: String,
    pub pw_id: String,
}

/// Complete `p2p` xconnect or `bridge-domain` service parsed from `show running-config l2vpn`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct L2vpnServiceEntry {
    pub service_type: L2vpnServiceType,
    /// Parent `xconnect group <group_name>` or `bridge group <group_name>`.
    pub group_name: String,
    /// Name of the `p2p <service_name>` or `bridge-domain <service_name>`.
    pub service_name: String,
    /// Optional `mtu <bytes>` configured under a `bridge-domain` (for example `"9100"`).
    pub mtu: String,
    /// Optional `routed interface BVI<id>` configured under a `bridge-domain` (for example `"BVI10"`).
    pub routed_bvi: String,
    /// Optional `vfi <vfi_name>` configured under a `bridge-domain`.
    pub vfi_name: String,
    /// Attached L2 subinterfaces (`interface <name>` with optional `split-horizon group`).
    pub interfaces: Vec<L2vpnAttachmentInterface>,
    /// Pseudowire neighbors (`neighbor [ipv4] <ip> pw-id <id>`).
    pub neighbors: Vec<L2vpnPseudowireNeighbor>,
    /// Raw CLI configuration stanza.
    pub raw_stanza: String,
}

/// Asynchronous requests sent from the TUI thread to the background SSH worker.
#[derive(Debug)]
pub enum SshRequest {
    Connect(ConnectionConfig),
    FetchInterfaces,
    FetchL2vpn,
    GetConfig {
        interface_name: String,
    },
    PushConfig {
        commands: Vec<String>,
        action_description: String,
    },
    RunCommand {
        command: String,
    },
    #[allow(dead_code)]
    Disconnect,
}

/// Asynchronous responses sent from the background SSH worker back to the TUI thread.
#[derive(Debug)]
pub enum SshResponse {
    Connected {
        host: String,
        operating_system: CiscoOs,
        banner: String,
    },
    Interfaces(Result<Vec<InterfaceEntry>, String>),
    L2vpnServices(Result<Vec<L2vpnServiceEntry>, String>),
    ConfigResult {
        interface_name: String,
        result: Result<String, String>,
    },
    PushResult {
        action_description: String,
        result: Result<String, String>,
    },
    CommandResult {
        command: String,
        result: Result<String, String>,
    },
    ConnectionError(String),
    Status(String),
}
