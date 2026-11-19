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
///
/// `Debug` is implemented by hand (below) so the password can never leak into logs,
/// panic messages, or debug output.
#[derive(Clone)]
pub struct ConnectionConfig {
    /// Router hostname or IP address (or `demo` for the offline simulator).
    pub host: String,
    /// SSH TCP port (normally 22).
    pub port: u16,
    /// SSH login username.
    pub username: String,
    /// SSH login password; held in memory only and never written to disk or logs.
    pub password: String,
    /// Cisco CLI dialect to assume until the router's real OS is detected.
    pub operating_system: CiscoOs,
    /// When `true`, no network connection is made and a built-in simulated router is used.
    pub use_mock_router: bool,
}

impl std::fmt::Debug for ConnectionConfig {
    /// Prints every field except the password, which is replaced with a placeholder.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConnectionConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .field("operating_system", &self.operating_system)
            .field("use_mock_router", &self.use_mock_router)
            .finish()
    }
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
    /// Routine progress messages.
    Info,
    /// An operation completed successfully.
    Success,
    /// Something was blocked or may need attention, but nothing failed.
    Warning,
    /// An operation failed.
    Error,
}

/// A timestamped audit log entry recording commands sent to the router and their results.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct ActionLog {
    /// Local wall-clock time the entry was created, formatted `HH:MM:SS`.
    pub timestamp: String,
    /// Severity, used to colour the entry in the log viewer.
    pub level: LogLevel,
    /// One-line human-readable summary of what happened.
    pub message: String,
    /// The CLI command or action this entry relates to, when there is one.
    pub command: Option<String>,
    /// Full router output (for example a configuration commit transcript), when there is any.
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
    /// Sort alphabetically by interface name.
    Name,
    /// Sort by physical/administrative status (`up`, `down`, `admin down`).
    Status,
    /// Sort by line-protocol state.
    Protocol,
    /// Sort alphabetically by interface description.
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
    /// Returns an upper-case label short enough for table cells and confirmation titles.
    pub fn short_label(&self) -> &'static str {
        match self {
            L2vpnServiceType::BridgeDomain => "BRIDGE-DOM",
            L2vpnServiceType::XconnectP2p => "XCONNECT",
        }
    }

    /// Returns the full human-readable name used in modal titles and status messages.
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
    /// IPv4 address of the remote router terminating the pseudowire.
    pub peer_ipv4: String,
    /// Pseudowire identifier (`pw-id`) that must match on both ends.
    pub pw_id: String,
}

/// Complete `p2p` xconnect or `bridge-domain` service parsed from `show running-config l2vpn`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct L2vpnServiceEntry {
    /// Whether this is a point-to-point xconnect or a multipoint bridge-domain.
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

/// Service forwarding binding inside a Cisco IOS-XE / ASR 900 `service instance <id> ethernet`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ServiceInstanceBinding {
    #[default]
    None,
    /// Point-to-point EoMPLS pseudowire (`xconnect <peer_ipv4> <pw_id> encapsulation mpls`).
    Xconnect,
    /// Multipoint bridge domain (`bridge-domain <bd_id>`).
    BridgeDomain,
}

/// Ethernet Service Instance (`service instance <id> ethernet`) parsed from an IOS-XE / ASR 900 interface.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ServiceInstanceEntry {
    /// Parent physical or Port-channel interface (for example `"TenGigabitEthernet0/0/0"`).
    pub parent_interface: String,
    /// Numeric service instance ID (for example `"100"`).
    pub service_instance_id: String,
    /// Optional description inside the service instance.
    pub description: String,
    /// Outer Dot1Q VLAN ID (or `"untagged"` / `"default"` if configured).
    pub vlan_id: String,
    /// Optional inner Dot1Q VLAN ID (`second-dot1q`).
    pub second_vlan_id: String,
    /// Number of VLAN tags popped on ingress (`0` = none, `1` = `pop 1 symmetric`, `2` = `pop 2 symmetric`).
    pub rewrite_ingress_pop: u8,
    /// Forwarding binding (`None`, `Xconnect`, or `BridgeDomain`).
    pub binding_type: ServiceInstanceBinding,
    /// Peer IPv4 address for `xconnect <peer_ipv4> <pw_id> encapsulation mpls`.
    pub xconnect_peer_ip: String,
    /// Pseudowire VC ID for `xconnect`.
    pub xconnect_pw_id: String,
    /// Bridge-domain ID for `bridge-domain <id>`.
    pub bridge_domain_id: String,
    /// Whether `split-horizon` is appended to `bridge-domain <id>`.
    pub split_horizon: bool,
}

/// Asynchronous requests sent from the TUI thread to the background SSH worker.
#[derive(Debug)]
pub enum SshRequest {
    /// Open a new session (closing any existing one) using the given settings.
    Connect(ConnectionConfig),
    /// Re-read the interface table (and the L2VPN table) from the router.
    FetchInterfaces,
    /// Re-read only the L2VPN services from the router.
    FetchL2vpn,
    /// Read `show running-config interface <interface_name>`.
    GetConfig {
        /// Interface whose configuration stanza is wanted.
        interface_name: String,
    },
    /// Send a configuration script to the router, one command at a time.
    PushConfig {
        /// Ordered CLI lines, starting with `configure terminal` and ending with `end`.
        commands: Vec<String>,
        /// Short description shown in status messages and logs.
        action_description: String,
    },
    /// Run one free-form CLI command typed by the operator.
    RunCommand {
        /// The command text exactly as typed.
        command: String,
    },
    /// Close the current session.
    #[allow(dead_code)]
    Disconnect,
}

/// Asynchronous responses sent from the background SSH worker back to the TUI thread.
#[derive(Debug)]
pub enum SshResponse {
    /// The session is open and the router's operating system has been detected.
    Connected {
        /// Name to show for the router in the header.
        host: String,
        /// Detected Cisco CLI dialect.
        operating_system: CiscoOs,
        /// Text the router printed on login.
        banner: String,
    },
    /// Result of an interface table poll (`Err` holds a readable reason).
    Interfaces(Result<Vec<InterfaceEntry>, String>),
    /// Result of an L2VPN poll (`Err` holds a readable reason).
    L2vpnServices(Result<Vec<L2vpnServiceEntry>, String>),
    /// Result of an IOS-XE / ASR 900 service instance poll (`Err` holds a readable reason).
    ServiceInstances(Result<Vec<ServiceInstanceEntry>, String>),
    /// Result of reading one interface's running-config.
    ConfigResult {
        /// Interface the result belongs to.
        interface_name: String,
        /// The configuration text, or a readable error.
        result: Result<String, String>,
    },
    /// Result of pushing a configuration script.
    PushResult {
        /// The description that was supplied with the request.
        action_description: String,
        /// Session transcript on success, or the router's error report on failure.
        result: Result<String, String>,
    },
    /// Result of a free-form command.
    CommandResult {
        /// The command that was run.
        command: String,
        /// The command output, or a readable error.
        result: Result<String, String>,
    },
    /// The router presented a host key not yet in `known_hosts`; the SSH worker is paused
    /// until the operator accepts or rejects it.
    HostKeyPrompt(HostKeyPromptDetails),
    /// The connection failed or was lost; the UI should return to the login screen.
    ConnectionError(String),
    /// A progress message to show in the status bar.
    Status(String),
}

/// What the operator needs to see to decide whether to trust a router's SSH host key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKeyPromptDetails {
    /// Hostname or IP address being connected to.
    pub host: String,
    /// TCP port being connected to.
    pub port: u16,
    /// Key algorithm, for example `ssh-ed25519`.
    pub key_type: String,
    /// SHA-256 fingerprint of the key, to compare against a trusted source.
    pub fingerprint: String,
}
