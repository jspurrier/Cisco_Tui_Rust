use crate::model::{
    CiscoOs, InterfaceEntry, L2vpnAttachmentInterface, L2vpnPseudowireNeighbor, L2vpnServiceEntry,
    L2vpnServiceType,
};

/// Parses the output of `show interfaces description` from Cisco IOS, IOS-XE, or IOS-XR.
///
/// Handles both single-word status values (`up`, `down`, `err-disabled`) and multi-word
/// status values (`admin down`, `administratively down`).
pub fn parse_show_interfaces_description(raw_output: &str) -> Vec<InterfaceEntry> {
    let mut interface_entries = Vec::new();

    for raw_line in raw_output.lines() {
        let trimmed_line = raw_line.trim();

        // Skip empty lines, table column headers, separator dashes, command echoes, and router prompts
        if trimmed_line.is_empty()
            || trimmed_line.starts_with("Interface")
            || trimmed_line.starts_with("---")
            || trimmed_line.starts_with("show ")
            || trimmed_line.starts_with("RP/")
            || trimmed_line.ends_with('#')
            || trimmed_line.ends_with('>')
        {
            continue;
        }

        let columns: Vec<&str> = trimmed_line.split_whitespace().collect();
        if columns.len() < 2 {
            continue;
        }

        let interface_name = columns[0].to_string();

        // Determine where the status and protocol columns end and where the description begins.
        // Cisco outputs "admin down" or "administratively down" as two separate words.
        let (physical_status, line_protocol, description_start_index) =
            if columns[1].eq_ignore_ascii_case("admin")
                || columns[1].eq_ignore_ascii_case("administratively")
            {
                let second_word_is_down = columns
                    .get(2)
                    .map_or(false, |word| word.eq_ignore_ascii_case("down"));
                if second_word_is_down {
                    let protocol = columns.get(3).unwrap_or(&"down").to_string();
                    ("admin down".to_string(), protocol, 4)
                } else {
                    let protocol = columns.get(2).unwrap_or(&"down").to_string();
                    ("admin down".to_string(), protocol, 3)
                }
            } else {
                let status = columns[1].to_string();
                let protocol = columns.get(2).unwrap_or(&"down").to_string();
                (status, protocol, 3)
            };

        let description = if columns.len() > description_start_index {
            columns[description_start_index..].join(" ")
        } else {
            String::new()
        };

        // Ignore any stray router prompt lines that might have been split
        if interface_name.contains('#') || interface_name.contains('>') {
            continue;
        }

        interface_entries.push(InterfaceEntry {
            name: interface_name,
            status: physical_status,
            protocol: line_protocol,
            description,
        });
    }

    interface_entries
}

/// Inspects parsed interface names to determine whether the router uses Cisco IOS-XR
/// naming conventions (such as 4-part rack/slot/module/port `Gi0/0/0/6`, `MgmtEth`, or `Bundle-Ether`).
pub fn has_ios_xr_interface_naming(interfaces: &[InterfaceEntry]) -> bool {
    interfaces.iter().any(|entry| {
        let base_interface_name = entry.name.split('.').next().unwrap_or(&entry.name);
        let slash_count = base_interface_name.matches('/').count();
        slash_count >= 3
            || base_interface_name.starts_with("MgmtEth")
            || base_interface_name.starts_with("Bundle-Ether")
            || base_interface_name.starts_with("TenGigE")
            || base_interface_name.starts_with("HundredGigE")
    })
}

/// Strips ANSI escape sequences, resolves embedded carriage returns (`\r`) and backspaces (`\x08`),
/// and removes non-printable terminal control characters from raw SSH PTY output.
///
/// This prevents embedded `\r` bytes from moving the terminal hardware cursor back to column 0
/// and overwriting TUI modal borders when rendered by Ratatui/Crossterm.
pub fn sanitize_pty_output(raw_output: &str) -> String {
    let without_ansi = strip_ansi_escape_codes(raw_output);
    let normalized_newlines = without_ansi.replace("\r\n", "\n");

    let mut sanitized_lines: Vec<String> = Vec::new();

    for raw_line in normalized_newlines.split('\n') {
        let non_empty_cr_segments: Vec<&str> = raw_line
            .split('\r')
            .filter(|segment| !segment.trim().is_empty())
            .collect();

        let reconstructed_line = if non_empty_cr_segments.is_empty() {
            String::new()
        } else if non_empty_cr_segments.len() == 1 {
            apply_backspaces_and_strip_controls(non_empty_cr_segments[0])
        } else {
            let first_segment = apply_backspaces_and_strip_controls(non_empty_cr_segments[0]);
            let last_segment = apply_backspaces_and_strip_controls(
                non_empty_cr_segments[non_empty_cr_segments.len() - 1],
            );

            // When a long command wraps at 80 columns, Cisco CLI redraws the line as "\r#<command>".
            // Re-attach the original router prompt prefix before '#' so the full line is preserved.
            if last_segment.starts_with('#') {
                if let Some((prompt_prefix, _)) = first_segment.split_once('#') {
                    format!("{}{}", prompt_prefix, last_segment)
                } else {
                    last_segment
                }
            } else {
                last_segment
            }
        };

        sanitized_lines.push(reconstructed_line);
    }

    sanitized_lines.join("\n")
}

/// Removes ANSI CSI (`ESC [ ...`) and OSC (`ESC ] ...`) escape sequences from a string.
fn strip_ansi_escape_codes(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let mut characters = input.chars().peekable();

    while let Some(character) = characters.next() {
        if character == '\x1b' {
            match characters.peek().copied() {
                Some('[') => {
                    let _ = characters.next();
                    for csi_char in characters.by_ref() {
                        if ('@'..='~').contains(&csi_char) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    let _ = characters.next();
                    while let Some(osc_char) = characters.next() {
                        if osc_char == '\x07' {
                            break;
                        }
                        if osc_char == '\x1b' && characters.peek() == Some(&'\\') {
                            let _ = characters.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    let _ = characters.next();
                }
                None => {}
            }
        } else {
            output.push(character);
        }
    }

    output
}

/// Applies ASCII backspace (`\x08`), expands tabs to spaces, and strips remaining control characters.
fn apply_backspaces_and_strip_controls(segment: &str) -> String {
    let mut characters: Vec<char> = Vec::with_capacity(segment.len());
    for character in segment.chars() {
        if character == '\x08' {
            let _ = characters.pop();
        } else if character == '\t' {
            characters.extend([' ', ' ', ' ', ' ']);
        } else if !character.is_control() {
            characters.push(character);
        }
    }
    characters.into_iter().collect()
}

/// Strips the echoed command line, carriage returns, and trailing router prompt
/// from raw SSH channel output so only the clean configuration or command text remains.
pub fn clean_cisco_output(raw_output: &str, executed_command: &str) -> String {
    let sanitized_output = sanitize_pty_output(raw_output);
    let mut cleaned_lines = Vec::new();
    let trimmed_command = executed_command.trim();

    for raw_line in sanitized_output.lines() {
        let trimmed_line = raw_line.trim();

        // Skip the echoed command at the top of the output (whether standalone or attached to a router prompt)
        if !trimmed_command.is_empty()
            && (trimmed_line == trimmed_command
                || trimmed_line.starts_with(trimmed_command)
                || trimmed_line.ends_with(trimmed_command))
        {
            continue;
        }

        // Skip trailing router prompts such as "Router#" or "RP/0/RSP0/CPU0:Router#"
        if (trimmed_line.ends_with('#') || trimmed_line.ends_with('>'))
            && (trimmed_line.contains("RP/") || trimmed_line.split_whitespace().count() <= 1)
        {
            continue;
        }

        cleaned_lines.push(raw_line);
    }

    cleaned_lines.join("\n").trim().to_string()
}

/// Builds the Cisco CLI command sequence to enable a port (`no shutdown`).
pub fn build_no_shutdown_script(interface_name: &str, operating_system: CiscoOs) -> Vec<String> {
    let mut command_list = vec![
        "configure terminal".to_string(),
        format!("interface {}", interface_name),
        "no shutdown".to_string(),
    ];
    if operating_system == CiscoOs::IosXr {
        command_list.push("commit".to_string());
    }
    command_list.push("end".to_string());
    command_list
}

/// Builds the Cisco CLI command sequence to administratively disable a port (`shutdown`).
pub fn build_shutdown_script(interface_name: &str, operating_system: CiscoOs) -> Vec<String> {
    let mut command_list = vec![
        "configure terminal".to_string(),
        format!("interface {}", interface_name),
        "shutdown".to_string(),
    ];
    if operating_system == CiscoOs::IosXr {
        command_list.push("commit".to_string());
    }
    command_list.push("end".to_string());
    command_list
}

#[allow(dead_code)]
/// Builds the Cisco CLI command sequence to update or remove an interface description.
pub fn build_description_script(
    interface_name: &str,
    new_description: &str,
    operating_system: CiscoOs,
) -> Vec<String> {
    let description_command = if new_description.trim().is_empty() {
        "no description".to_string()
    } else {
        format!("description {}", new_description.trim())
    };

    let mut command_list = vec![
        "configure terminal".to_string(),
        format!("interface {}", interface_name),
        description_command,
    ];
    if operating_system == CiscoOs::IosXr {
        command_list.push("commit".to_string());
    }
    command_list.push("end".to_string());
    command_list
}

#[allow(dead_code)]
/// Combines a base physical interface name and a subinterface number into `<base>.<subif>`.
pub fn format_subinterface_name(base_interface: &str, subinterface_id: &str) -> String {
    let trimmed_subinterface = subinterface_id.trim();
    if trimmed_subinterface.is_empty() {
        return base_interface.to_string();
    }
    let clean_subinterface_id = trimmed_subinterface.trim_start_matches('.');
    if let Some((parent_interface, _)) = base_interface.rsplit_once('.') {
        format!("{}.{}", parent_interface, clean_subinterface_id)
    } else {
        format!("{}.{}", base_interface, clean_subinterface_id)
    }
}

/// Returns `true` if `interface_name` is a subinterface (such as `Gi0/0/0/1.100` or
/// `Te0/1/0/1.10002000`) with a non-empty parent port and numeric subinterface ID.
///
/// Physical ports (`Gi0/0/0/1`, `Te0/1/0/1`), `Loopback0`, `Bundle-Ether1`, and `MgmtEth`
/// return `false` so they can never be deleted.
pub fn is_deletable_subinterface(interface_name: &str) -> bool {
    let trimmed_name = interface_name.trim();
    let Some((parent_port, subinterface_suffix)) = trimmed_name.rsplit_once('.') else {
        return false;
    };

    !parent_port.trim().is_empty()
        && !subinterface_suffix.trim().is_empty()
        && subinterface_suffix
            .trim()
            .chars()
            .all(|character| character.is_ascii_digit())
}

/// Builds the Cisco CLI command sequence to delete a subinterface (`no interface <subif>`).
/// Refuses with an `Err` if called on a physical or non-subinterface port.
#[cfg(test)]
pub fn build_delete_subinterface_script(
    interface_name: &str,
    operating_system: CiscoOs,
) -> Result<Vec<String>, String> {
    let trimmed_name = interface_name.trim();
    if !is_deletable_subinterface(trimmed_name) {
        return Err(format!(
            "Safety block: '{}' is not a subinterface and cannot be deleted.",
            trimmed_name
        ));
    }

    let mut command_list = vec![
        "configure terminal".to_string(),
        format!("no interface {}", trimmed_name),
    ];
    if operating_system == CiscoOs::IosXr {
        command_list.push("commit".to_string());
    }
    command_list.push("end".to_string());
    Ok(command_list)
}

#[allow(dead_code)]
/// Builds the Cisco CLI command sequence to provision an L2Transport subinterface.
pub fn build_l2transport_script(
    target_interface: &str,
    vlan_id: &str,
    description: &str,
    rewrite_ingress: bool,
    jumbo_mtu: Option<&str>,
    enable_port: bool,
    operating_system: CiscoOs,
) -> Vec<String> {
    let editor_form = InterfaceEditorForm {
        interface: target_interface.to_string(),
        description: description.to_string(),
        port_enabled: enable_port,
        omit_port_state: false,
        primary_ip: String::new(),
        secondary_ip: String::new(),
        l2transport: true,
        vlan_id: vlan_id.to_string(),
        second_vlan_id: String::new(),
        rewrite_ingress_pop: if rewrite_ingress { 1 } else { 0 },
        mtu: jumbo_mtu.unwrap_or("").to_string(),
        negotiation_auto: false,
        original_interface: String::new(),
        original_config: None,
        pending_l2vpn: None,
    };
    build_unified_interface_script(&editor_form, operating_system)
}

/// Extracts outer and optional inner 802.1Q VLAN IDs from a subinterface name suffix.
///
/// Examples:
/// - `"Gi0/0/0/1.100"` -> `("100", "")`
/// - `"Te0/1/0/1.10002000"` -> `("1000", "2000")` (8-digit QinQ concatenation where both 4-digit halves are 1..=4094)
pub fn extract_vlans_from_subinterface_name(interface_name: &str) -> (String, String) {
    let Some((_, raw_suffix)) = interface_name.rsplit_once('.') else {
        return (String::new(), String::new());
    };

    let trimmed_suffix = raw_suffix.trim();
    if trimmed_suffix.is_empty()
        || !trimmed_suffix
            .chars()
            .all(|character| character.is_ascii_digit())
    {
        return (String::new(), String::new());
    }

    if let Ok(numeric_value) = trimmed_suffix.parse::<u32>() {
        if (1..=4094).contains(&numeric_value) {
            return (trimmed_suffix.to_string(), String::new());
        }
    }

    // Check if an 8-digit suffix (like 10002000) is two concatenated 4-digit VLAN IDs
    if trimmed_suffix.len() == 8 {
        let (outer_part, inner_part) = trimmed_suffix.split_at(4);
        if let (Ok(outer_vlan), Ok(inner_vlan)) =
            (outer_part.parse::<u16>(), inner_part.parse::<u16>())
        {
            if (1..=4094).contains(&outer_vlan) && (1..=4094).contains(&inner_vlan) {
                return (outer_vlan.to_string(), inner_vlan.to_string());
            }
        }
    }

    (trimmed_suffix.to_string(), String::new())
}

/// Converts a CIDR prefix length (such as `24` or `30`) into a dotted-decimal subnet mask
/// (such as `255.255.255.0` or `255.255.255.252`).
pub fn cidr_to_netmask(prefix_length: u8) -> String {
    let clamped_prefix = prefix_length.min(32);
    let netmask_bits: u32 = if clamped_prefix == 0 {
        0
    } else {
        !0u32 << (32 - clamped_prefix)
    };
    format!(
        "{}.{}.{}.{}",
        (netmask_bits >> 24) & 0xFF,
        (netmask_bits >> 16) & 0xFF,
        (netmask_bits >> 8) & 0xFF,
        netmask_bits & 0xFF
    )
}

/// Converts a dotted-decimal subnet mask (such as `255.255.255.0`) into its CIDR prefix length (`24`).
pub fn netmask_to_cidr(netmask_text: &str) -> Option<u8> {
    let octets: Vec<&str> = netmask_text.trim().split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut netmask_bits: u32 = 0;
    for octet_text in octets {
        let octet_value: u8 = octet_text.parse().ok()?;
        netmask_bits = (netmask_bits << 8) | (octet_value as u32);
    }
    let leading_ones = netmask_bits.leading_ones();
    let trailing_zeros = netmask_bits.trailing_zeros();
    if leading_ones + trailing_zeros == 32 {
        Some(leading_ones as u8)
    } else {
        None
    }
}

/// Formats an `<ip> <netmask>` pair into compact `<ip>/<prefix>` notation for display in form fields.
pub fn format_ip_as_cidr_if_possible(ip_and_mask: &str) -> String {
    let trimmed_input = ip_and_mask.trim();
    if let Some((ip_address, subnet_mask)) = trimmed_input.split_once(' ') {
        if let Some(prefix_length) = netmask_to_cidr(subnet_mask) {
            return format!("{}/{}", ip_address.trim(), prefix_length);
        }
    }
    trimmed_input.to_string()
}

/// Splits a comma- or semicolon-separated string of IP specifications and converts any `/slash`
/// prefixes into full `<ip> <subnet_mask>` strings ready for Cisco CLI commands.
pub fn parse_multiple_ips(raw_ip_list: &str) -> Vec<String> {
    let mut normalized_ip_entries = Vec::new();
    for raw_entry in raw_ip_list.split([',', ';']) {
        let trimmed_entry = raw_entry.trim();
        if !trimmed_entry.is_empty() {
            let normalized_entry = normalize_ip_spec(trimmed_entry);
            if !normalized_entry.is_empty() {
                normalized_ip_entries.push(normalized_entry);
            }
        }
    }
    normalized_ip_entries
}

/// Normalizes a single IP entry so that either `10.0.0.1/24` or `10.0.0.1 255.255.255.0`
/// produces `"10.0.0.1 255.255.255.0"`.
pub fn normalize_ip_spec(raw_ip_input: &str) -> String {
    let trimmed_input = raw_ip_input.trim();
    if trimmed_input.is_empty() {
        return String::new();
    }

    if let Some((ip_address, prefix_text)) = trimmed_input.split_once('/') {
        if let Ok(prefix_length) = prefix_text.trim().parse::<u8>() {
            return format!("{} {}", ip_address.trim(), cidr_to_netmask(prefix_length));
        }
    }

    trimmed_input.to_string()
}

/// Structured fields extracted from an existing `show running-config interface` stanza.
#[derive(Clone, Debug, Default)]
pub struct ParsedInterfaceConfig {
    pub description: String,
    pub port_enabled: bool,
    pub has_explicit_shutdown_state: bool,
    pub primary_ip: String,
    pub secondary_ip: String,
    pub l2transport: bool,
    pub vlan_id: String,
    pub second_vlan_id: String,
    /// Number of VLAN tags popped on ingress (`0` = none, `1` = `pop 1 symmetric`, `2` = `pop 2 symmetric`).
    pub rewrite_ingress_pop: u8,
    pub mtu: String,
    /// Whether `negotiation auto` is configured on the port (`false` by default).
    pub negotiation_auto: bool,
}

/// Parses the output of `show running-config interface <name>` to pre-populate the port editor.
/// Supports both single-tagged (`encapsulation dot1q 100`) and double-tagged QinQ
/// (`encapsulation dot1q 1000 second-dot1q 2000` + `rewrite ingress tag pop 2 symmetric`) stanzas.
pub fn parse_interface_running_config(running_config_text: &str) -> ParsedInterfaceConfig {
    let mut parsed_config = ParsedInterfaceConfig {
        port_enabled: true,
        has_explicit_shutdown_state: false,
        ..Default::default()
    };

    let mut secondary_addresses: Vec<String> = Vec::new();

    for raw_line in running_config_text.lines() {
        let trimmed_line = raw_line.trim();

        if (trimmed_line.starts_with("interface ") && trimmed_line.contains("l2transport"))
            || trimmed_line == "l2transport"
        {
            parsed_config.l2transport = true;
        } else if trimmed_line == "shutdown" {
            parsed_config.port_enabled = false;
            parsed_config.has_explicit_shutdown_state = true;
        } else if trimmed_line == "no shutdown" {
            parsed_config.port_enabled = true;
            parsed_config.has_explicit_shutdown_state = true;
        } else if trimmed_line == "negotiation auto" {
            parsed_config.negotiation_auto = true;
        } else if trimmed_line == "no negotiation auto" {
            parsed_config.negotiation_auto = false;
        } else if let Some(description_text) = trimmed_line.strip_prefix("description ") {
            parsed_config.description = description_text.trim().to_string();
        } else if trimmed_line.starts_with("ipv4 address ")
            || trimmed_line.starts_with("ip address ")
        {
            let address_portion = if let Some(rest) = trimmed_line.strip_prefix("ipv4 address ") {
                rest.trim()
            } else if let Some(rest) = trimmed_line.strip_prefix("ip address ") {
                rest.trim()
            } else {
                ""
            };

            if address_portion.ends_with("secondary") {
                let without_secondary_keyword =
                    address_portion.trim_end_matches("secondary").trim();
                secondary_addresses.push(format_ip_as_cidr_if_possible(without_secondary_keyword));
            } else {
                parsed_config.primary_ip = format_ip_as_cidr_if_possible(address_portion);
            }
        } else if let Some(encapsulation_rest) = trimmed_line.strip_prefix("encapsulation dot1q ") {
            // Check for QinQ double tag: "encapsulation dot1q 1000 second-dot1q 2000"
            if let Some((outer_vlan, inner_vlan)) = encapsulation_rest.split_once("second-dot1q") {
                parsed_config.vlan_id = outer_vlan.trim().to_string();
                parsed_config.second_vlan_id = inner_vlan
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
            } else {
                parsed_config.vlan_id = encapsulation_rest
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
            }
        } else if trimmed_line.starts_with("rewrite ingress ") {
            if trimmed_line.contains("pop 2") {
                parsed_config.rewrite_ingress_pop = 2;
            } else {
                parsed_config.rewrite_ingress_pop = 1;
            }
        } else if let Some(mtu_text) = trimmed_line.strip_prefix("mtu ") {
            parsed_config.mtu = mtu_text.trim().to_string();
        }
    }

    parsed_config.secondary_ip = secondary_addresses.join(", ");
    parsed_config
}

/// Holds the editable values inside the Unified Port Configuration Modal,
/// along with the original parsed configuration so unchanged settings are not re-sent
/// and modified/removed settings emit proper `no ...` negation statements first.
#[derive(Clone, Debug, Default)]
pub struct InterfaceEditorForm {
    pub interface: String,
    pub description: String,
    pub port_enabled: bool,
    /// When `true` (the default for `.vlan` subinterfaces), neither `no shutdown` nor `shutdown`
    /// is written in the CLI commands so the subport inherits its state from the parent port.
    pub omit_port_state: bool,
    pub primary_ip: String,
    pub secondary_ip: String,
    pub l2transport: bool,
    pub vlan_id: String,
    pub second_vlan_id: String,
    /// Number of VLAN tags popped on ingress (`0` = none, `1` = `pop 1 symmetric`, `2` = `pop 2 symmetric`).
    pub rewrite_ingress_pop: u8,
    pub mtu: String,
    /// Whether `negotiation auto` is enabled (`false` by default; usually omitted unless needed).
    pub negotiation_auto: bool,
    /// Name of the interface when the editor was opened (used to detect if the user is editing in-place vs creating a new `.vlan` subinterface).
    pub original_interface: String,
    /// Snapshot of the existing running-config on `original_interface`.
    pub original_config: Option<ParsedInterfaceConfig>,
    /// Optional L2VPN attachment configured alongside this subinterface so both push in a single atomic commit.
    pub pending_l2vpn: Option<L2vpnEditorForm>,
}

/// Formats the `encapsulation dot1q ...` clause from outer and optional inner VLAN IDs.
fn format_dot1q_encapsulation_clause(outer_vlan: &str, second_vlan: &str) -> String {
    let trimmed_outer = outer_vlan.trim();
    let trimmed_second = second_vlan.trim();
    if trimmed_outer.is_empty() {
        String::new()
    } else if !trimmed_second.is_empty() {
        format!(
            "encapsulation dot1q {} second-dot1q {}",
            trimmed_outer, trimmed_second
        )
    } else {
        format!("encapsulation dot1q {}", trimmed_outer)
    }
}

/// Generates the Cisco CLI script from the current values in the Unified Port Editor.
///
/// - When editing an **existing** interface (`original_config` is `Some`), ONLY emits commands
///   for settings that actually changed (skipping any setting that already exists unchanged on the router),
///   and automatically emits `no <old_setting>` before applying a changed or removed setting.
/// - When creating a **new** subinterface (`original_config` is `None` or the interface name changed),
///   emits all configured fields for the new port.
pub fn build_unified_interface_script(
    editor_form: &InterfaceEditorForm,
    operating_system: CiscoOs,
) -> Vec<String> {
    let mut command_list = vec!["configure terminal".to_string()];

    let target_interface_name = editor_form.interface.trim();
    if editor_form.l2transport {
        command_list.push(format!("interface {} l2transport", target_interface_name));
    } else {
        command_list.push(format!("interface {}", target_interface_name));
    }

    let address_keyword = if operating_system == CiscoOs::IosXr {
        "ipv4 address"
    } else {
        "ip address"
    };

    // Check if we are modifying an existing interface whose running-config snapshot is known
    let previous_config_option = if !editor_form.original_interface.trim().is_empty()
        && editor_form.original_interface.trim() == target_interface_name
    {
        editor_form.original_config.as_ref()
    } else {
        None
    };

    if let Some(previous) = previous_config_option {
        // -------------------------------------------------------------------
        // Delta-Only Mode (Existing Interface):
        // Do NOT re-send settings that already exist unchanged on the router.
        // For any modified or removed setting, emit `no <old>` before `<new>`.
        // -------------------------------------------------------------------

        if previous.l2transport && !editor_form.l2transport {
            command_list.push(" no l2transport".to_string());
        }

        // 1. Description (only if changed)
        let old_description = previous.description.trim();
        let new_description = editor_form.description.trim();
        if old_description != new_description {
            if !old_description.is_empty() && new_description.is_empty() {
                command_list.push(" no description".to_string());
            } else if !new_description.is_empty() {
                command_list.push(format!(" description {}", new_description));
            }
        }

        // 2. Port State (omitted when `omit_port_state` is true; otherwise emitted if changed or explicitly requested)
        if !editor_form.omit_port_state {
            let was_previously_implicit_on_subport =
                editor_form.interface.contains('.') && !previous.has_explicit_shutdown_state;
            if editor_form.port_enabled != previous.port_enabled
                || was_previously_implicit_on_subport
            {
                if editor_form.port_enabled {
                    command_list.push(" no shutdown".to_string());
                } else {
                    command_list.push(" shutdown".to_string());
                }
            }
        }

        // 3. Dot1Q / QinQ Encapsulation (only if changed; negate old encapsulation first)
        let old_encapsulation =
            format_dot1q_encapsulation_clause(&previous.vlan_id, &previous.second_vlan_id);
        let new_encapsulation =
            format_dot1q_encapsulation_clause(&editor_form.vlan_id, &editor_form.second_vlan_id);
        if old_encapsulation != new_encapsulation {
            if !old_encapsulation.is_empty() {
                command_list.push(format!(" no {}", old_encapsulation));
            }
            if !new_encapsulation.is_empty() {
                command_list.push(format!(" {}", new_encapsulation));
            }
        }

        // 4. Rewrite Ingress Tag (only if changed; negate old rewrite tag first)
        let old_pop = if previous.l2transport {
            previous.rewrite_ingress_pop
        } else {
            0
        };
        let new_pop = if editor_form.l2transport {
            editor_form.rewrite_ingress_pop
        } else {
            0
        };
        if old_pop != new_pop {
            if old_pop > 0 {
                command_list.push(format!(
                    " no rewrite ingress tag pop {} symmetric",
                    old_pop
                ));
            }
            if new_pop > 0 {
                command_list.push(format!(
                    " rewrite ingress tag pop {} symmetric",
                    new_pop
                ));
            }
        }

        // 5. Primary IPv4 Address (only if changed; negate old primary IP first)
        let old_primary = if previous.l2transport {
            String::new()
        } else {
            normalize_ip_spec(&previous.primary_ip)
        };
        let new_primary = if editor_form.l2transport {
            String::new()
        } else {
            normalize_ip_spec(&editor_form.primary_ip)
        };
        if old_primary != new_primary {
            if !old_primary.is_empty() {
                command_list.push(format!(" no {} {}", address_keyword, old_primary));
            }
            if !new_primary.is_empty() {
                command_list.push(format!(" {} {}", address_keyword, new_primary));
            }
        }

        // 6. Secondary IPv4 Addresses (only negate removed ones and only add newly added ones)
        let old_secondaries = if previous.l2transport {
            Vec::new()
        } else {
            parse_multiple_ips(&previous.secondary_ip)
        };
        let new_secondaries = if editor_form.l2transport {
            Vec::new()
        } else {
            parse_multiple_ips(&editor_form.secondary_ip)
        };
        for old_secondary_ip in &old_secondaries {
            if !new_secondaries.contains(old_secondary_ip) {
                command_list.push(format!(
                    " no {} {} secondary",
                    address_keyword, old_secondary_ip
                ));
            }
        }
        for new_secondary_ip in &new_secondaries {
            if !old_secondaries.contains(new_secondary_ip) {
                command_list.push(format!(
                    " {} {} secondary",
                    address_keyword, new_secondary_ip
                ));
            }
        }

        // 7. Jumbo MTU (only if changed; negate old MTU if cleared)
        let old_mtu = previous.mtu.trim();
        let new_mtu = editor_form.mtu.trim();
        if old_mtu != new_mtu {
            if !old_mtu.is_empty() && new_mtu.is_empty() {
                command_list.push(format!(" no mtu {}", old_mtu));
            } else if !new_mtu.is_empty() {
                command_list.push(format!(" mtu {}", new_mtu));
            }
        }

        // 8. Auto-Negotiation (`negotiation auto` / `no negotiation auto`, only if changed)
        if editor_form.negotiation_auto != previous.negotiation_auto {
            if editor_form.negotiation_auto {
                command_list.push(" negotiation auto".to_string());
            } else {
                command_list.push(" no negotiation auto".to_string());
            }
        }
    } else {
        // -------------------------------------------------------------------
        // New Subinterface / Uncached Interface Mode:
        // Emit all configured fields for the new interface.
        // -------------------------------------------------------------------
        let trimmed_description = editor_form.description.trim();
        if !trimmed_description.is_empty() {
            command_list.push(format!(" description {}", trimmed_description));
        }

        if !editor_form.omit_port_state {
            if editor_form.port_enabled {
                command_list.push(" no shutdown".to_string());
            } else {
                command_list.push(" shutdown".to_string());
            }
        }

        let new_encapsulation =
            format_dot1q_encapsulation_clause(&editor_form.vlan_id, &editor_form.second_vlan_id);
        if !new_encapsulation.is_empty() {
            command_list.push(format!(" {}", new_encapsulation));
        }

        if editor_form.l2transport && editor_form.rewrite_ingress_pop > 0 {
            command_list.push(format!(
                " rewrite ingress tag pop {} symmetric",
                editor_form.rewrite_ingress_pop
            ));
        }

        let trimmed_primary_ip = editor_form.primary_ip.trim();
        if !trimmed_primary_ip.is_empty() && !editor_form.l2transport {
            let normalized_primary_ip = normalize_ip_spec(trimmed_primary_ip);
            if !normalized_primary_ip.is_empty() {
                command_list.push(format!(" {} {}", address_keyword, normalized_primary_ip));
            }
        }

        if !editor_form.l2transport {
            let secondary_ip_list = parse_multiple_ips(&editor_form.secondary_ip);
            for secondary_ip_entry in secondary_ip_list {
                command_list.push(format!(
                    " {} {} secondary",
                    address_keyword, secondary_ip_entry
                ));
            }
        }

        let trimmed_mtu = editor_form.mtu.trim();
        if !trimmed_mtu.is_empty() {
            command_list.push(format!(" mtu {}", trimmed_mtu));
        }

        if editor_form.negotiation_auto {
            command_list.push(" negotiation auto".to_string());
        }
    }

    // If an L2VPN attachment was configured inside the Port Editor, include its `l2vpn` stanza
    // in the same atomic transaction before `commit`.
    if let Some(ref l2vpn_form) = editor_form.pending_l2vpn {
        let mut synced_l2vpn = l2vpn_form.clone();
        if !target_interface_name.is_empty() {
            synced_l2vpn.target_interface = expand_full_interface_name(target_interface_name);
        }
        let l2vpn_inner_lines = build_l2vpn_inner_commands(&synced_l2vpn);
        if !l2vpn_inner_lines.is_empty() {
            command_list.push("l2vpn".to_string());
            command_list.extend(l2vpn_inner_lines);
        }
    }

    if operating_system == CiscoOs::IosXr {
        command_list.push("commit".to_string());
    }
    command_list.push("end".to_string());

    command_list
}

/// Expands Cisco IOS-XR abbreviated interface names (case-insensitively, e.g. `Gi`, `GI`, `gi`, `Gig`,
/// `Te`, `TE`, `Ten`, `BE`, `be`, `BV`, `BVI`, `Hu`, `TF`, `Fo`, `Lo`, `Mg`) into their canonical
/// full `running-config` equivalents (e.g. `GI0/0/0/1.100` -> `GigabitEthernet0/0/0/1.100`,
/// `te0/0/0/1.200` -> `TenGigE0/0/0/1.200`, `be10.100` -> `Bundle-Ether10.100`, `bv10` -> `BVI10`).
pub fn expand_full_interface_name(raw_name: &str) -> String {
    let trimmed = raw_name.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // Split into alphabetic/hyphen prefix and the numeric/slash/dot suffix (e.g. "GI" + "0/0/0/1.100")
    let first_digit_index = trimmed.find(|character: char| character.is_ascii_digit());
    let Some(digit_index) = first_digit_index else {
        return trimmed.to_string();
    };

    let prefix = trimmed[..digit_index].trim();
    let numeric_suffix = &trimmed[digit_index..];
    let lower_prefix = prefix.to_ascii_lowercase();

    let canonical_prefix = match lower_prefix.as_str() {
        "gi" | "gig" | "gige" | "gigabitethernet" => Some("GigabitEthernet"),
        "te" | "ten" | "tengig" | "tengige" | "tengigabitethernet" => Some("TenGigE"),
        "be" | "bundle-ether" | "bundle" => Some("Bundle-Ether"),
        "bv" | "bvi" => Some("BVI"),
        "hu" | "hun" | "hundredgige" => Some("HundredGigE"),
        "tf" | "twentyfivegige" => Some("TwentyFiveGigE"),
        "fo" | "fortygige" => Some("FortyGigE"),
        "lo" | "loopback" => Some("Loopback"),
        "mg" | "mgmt" | "mgmteth" => Some("MgmtEth"),
        "fa" | "fastethernet" => Some("FastEthernet"),
        _ => None,
    };

    if let Some(full_prefix) = canonical_prefix {
        format!("{}{}", full_prefix, numeric_suffix)
    } else {
        trimmed.to_string()
    }
}

/// Converts a full or arbitrarily-cased Cisco interface name into its compact 2-letter table abbreviation
/// (e.g. `GigabitEthernet0/0/0/1.100` or `GI0/0/0/1.100` -> `Gi0/0/0/1.100`, `Bundle-Ether10.100` -> `BE10.100`).
pub fn abbreviate_interface_name(raw_name: &str) -> String {
    let trimmed = raw_name.trim();
    let Some(digit_index) = trimmed.find(|character: char| character.is_ascii_digit()) else {
        return trimmed.to_string();
    };
    let prefix = trimmed[..digit_index].trim().to_ascii_lowercase();
    let numeric_suffix = &trimmed[digit_index..];

    let short_prefix = match prefix.as_str() {
        "gi" | "gig" | "gige" | "gigabitethernet" => Some("Gi"),
        "te" | "ten" | "tengig" | "tengige" | "tengigabitethernet" => Some("Te"),
        "be" | "bundle-ether" | "bundle" => Some("BE"),
        "hu" | "hun" | "hundredgige" => Some("Hu"),
        "tf" | "twentyfivegige" => Some("TF"),
        "fo" | "fortygige" => Some("Fo"),
        "lo" | "loopback" => Some("Lo"),
        "mg" | "mgmt" | "mgmteth" => Some("Mg"),
        _ => None,
    };

    if let Some(short) = short_prefix {
        format!("{}{}", short, numeric_suffix)
    } else {
        trimmed.to_string()
    }
}

/// Returns `true` if `left_name` and `right_name` refer to the same Cisco interface
/// regardless of whether one is abbreviated (`Gi0/0/0/1.100` vs `GigabitEthernet0/0/0/1.100`, `BV10` vs `BVI10`).
pub fn same_cisco_interface(left_name: &str, right_name: &str) -> bool {
    expand_full_interface_name(left_name)
        .eq_ignore_ascii_case(&expand_full_interface_name(right_name))
}

/// Parses `show running-config l2vpn` output from Cisco IOS-XR into a list of
/// `L2vpnServiceEntry` items (`xconnect group` -> `p2p` and `bridge group` -> `bridge-domain`).
pub fn parse_running_config_l2vpn(raw_l2vpn_text: &str) -> Vec<L2vpnServiceEntry> {
    let sanitized_text = sanitize_pty_output(raw_l2vpn_text);
    let mut services: Vec<L2vpnServiceEntry> = Vec::new();

    let mut current_group_type: Option<L2vpnServiceType> = None;
    let mut current_group_name = String::new();
    let mut active_service: Option<L2vpnServiceEntry> = None;
    let mut active_stanza_lines: Vec<String> = Vec::new();

    for raw_line in sanitized_text.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("show ")
            || trimmed.starts_with("RP/")
            || trimmed.ends_with(" UTC")
            || trimmed.ends_with(" CST")
            || trimmed.ends_with(" CDT")
            || trimmed.ends_with(" EST")
            || trimmed.ends_with(" EDT")
            || trimmed.ends_with(" PST")
            || trimmed.ends_with(" PDT")
        {
            continue;
        }

        if let Some(xconnect_group) = trimmed.strip_prefix("xconnect group ") {
            if let Some(mut finished_service) = active_service.take() {
                finished_service.raw_stanza = active_stanza_lines.join("\n");
                services.push(finished_service);
                active_stanza_lines.clear();
            }
            current_group_type = Some(L2vpnServiceType::XconnectP2p);
            current_group_name = xconnect_group.trim().to_string();
            continue;
        }

        if let Some(bridge_group) = trimmed.strip_prefix("bridge group ") {
            if let Some(mut finished_service) = active_service.take() {
                finished_service.raw_stanza = active_stanza_lines.join("\n");
                services.push(finished_service);
                active_stanza_lines.clear();
            }
            current_group_type = Some(L2vpnServiceType::BridgeDomain);
            current_group_name = bridge_group.trim().to_string();
            continue;
        }

        if let Some(p2p_name) = trimmed.strip_prefix("p2p ") {
            if current_group_type == Some(L2vpnServiceType::XconnectP2p) {
                if let Some(mut finished_service) = active_service.take() {
                    finished_service.raw_stanza = active_stanza_lines.join("\n");
                    services.push(finished_service);
                    active_stanza_lines.clear();
                }
                let clean_p2p = p2p_name.trim().to_string();
                active_stanza_lines = vec![
                    "l2vpn".to_string(),
                    format!(" xconnect group {}", current_group_name),
                    format!("  p2p {}", clean_p2p),
                ];
                active_service = Some(L2vpnServiceEntry {
                    service_type: L2vpnServiceType::XconnectP2p,
                    group_name: current_group_name.clone(),
                    service_name: clean_p2p,
                    ..Default::default()
                });
                continue;
            }
        }

        if let Some(bd_name) = trimmed.strip_prefix("bridge-domain ") {
            if current_group_type == Some(L2vpnServiceType::BridgeDomain) {
                if let Some(mut finished_service) = active_service.take() {
                    finished_service.raw_stanza = active_stanza_lines.join("\n");
                    services.push(finished_service);
                    active_stanza_lines.clear();
                }
                let clean_bd = bd_name.trim().to_string();
                active_stanza_lines = vec![
                    "l2vpn".to_string(),
                    format!(" bridge group {}", current_group_name),
                    format!("  bridge-domain {}", clean_bd),
                ];
                active_service = Some(L2vpnServiceEntry {
                    service_type: L2vpnServiceType::BridgeDomain,
                    group_name: current_group_name.clone(),
                    service_name: clean_bd.clone(),
                    vfi_name: clean_bd,
                    ..Default::default()
                });
                continue;
            }
        }

        if let Some(ref mut service) = active_service {
            active_stanza_lines.push(raw_line.to_string());

            if let Some(mtu_value) = trimmed.strip_prefix("mtu ") {
                service.mtu = mtu_value.trim().to_string();
            } else if let Some(bvi_value) = trimmed.strip_prefix("routed interface ") {
                service.routed_bvi = bvi_value.trim().to_string();
            } else if let Some(vfi_value) = trimmed.strip_prefix("vfi ") {
                service.vfi_name = vfi_value.trim().to_string();
            } else if let Some(interface_value) = trimmed.strip_prefix("interface ") {
                service.interfaces.push(L2vpnAttachmentInterface {
                    interface_name: interface_value.trim().to_string(),
                    split_horizon_group: false,
                });
            } else if trimmed == "split-horizon group" {
                if let Some(last_interface) = service.interfaces.last_mut() {
                    last_interface.split_horizon_group = true;
                }
            } else if let Some(neighbor_rest) = trimmed.strip_prefix("neighbor ") {
                // Supports both `neighbor ipv4 192.0.2.10 pw-id 100` and `neighbor 192.0.2.20 pw-id 200`
                let without_ipv4 = neighbor_rest
                    .strip_prefix("ipv4 ")
                    .unwrap_or(neighbor_rest)
                    .trim();
                if let Some((ip_part, pw_part)) = without_ipv4.split_once("pw-id") {
                    let peer_ip = ip_part.trim().to_string();
                    let pw_id = pw_part
                        .split_whitespace()
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if !peer_ip.is_empty() && !pw_id.is_empty() {
                        service.neighbors.push(L2vpnPseudowireNeighbor {
                            peer_ipv4: peer_ip,
                            pw_id,
                        });
                    }
                }
            }
        }
    }

    if let Some(mut finished_service) = active_service.take() {
        finished_service.raw_stanza = active_stanza_lines.join("\n");
        services.push(finished_service);
    }

    services
}

/// Finds the L2VPN service (`xconnect` or `bridge-domain`) that `interface_name` belongs to
/// (matching both attachment subinterfaces and `routed interface BVI<id>`), and returns both
/// the service reference and a compact summary badge for display in the main Interface Table.
pub fn find_l2vpn_for_interface<'a>(
    interface_name: &str,
    services: &'a [L2vpnServiceEntry],
) -> Option<(&'a L2vpnServiceEntry, String)> {
    for service in services {
        if !service.routed_bvi.is_empty()
            && same_cisco_interface(interface_name, &service.routed_bvi)
        {
            let badge = format!(
                "BD: {}/{} [BVI]",
                service.group_name, service.service_name
            );
            return Some((service, badge));
        }

        for attached in &service.interfaces {
            if same_cisco_interface(interface_name, &attached.interface_name) {
                let badge = match service.service_type {
                    L2vpnServiceType::XconnectP2p => {
                        if let Some(first_neighbor) = service.neighbors.first() {
                            format!(
                                "XC: {}/{} ({}:{})",
                                service.group_name,
                                service.service_name,
                                first_neighbor.peer_ipv4,
                                first_neighbor.pw_id
                            )
                        } else {
                            format!("XC: {}/{}", service.group_name, service.service_name)
                        }
                    }
                    L2vpnServiceType::BridgeDomain => {
                        if attached.split_horizon_group {
                            format!(
                                "BD: {}/{} [SHG]",
                                service.group_name, service.service_name
                            )
                        } else {
                            format!("BD: {}/{}", service.group_name, service.service_name)
                        }
                    }
                };
                return Some((service, badge));
            }
        }
    }
    None
}

/// Parses a comma-separated string of `<IP> <PW_ID>` or `<IP>:<PW_ID>` entries into `L2vpnPseudowireNeighbor` structs.
pub fn parse_l2vpn_neighbors(raw_neighbors: &str) -> Vec<L2vpnPseudowireNeighbor> {
    let mut parsed_list = Vec::new();
    for entry in raw_neighbors.split([',', ';']) {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            continue;
        }
        let cleaned = trimmed.replace("pw-id", " ").replace(':', " ");
        let mut tokens = cleaned.split_whitespace();
        if let (Some(peer_ip), Some(pw_id)) = (tokens.next(), tokens.next()) {
            parsed_list.push(L2vpnPseudowireNeighbor {
                peer_ipv4: peer_ip.to_string(),
                pw_id: pw_id.to_string(),
            });
        }
    }
    parsed_list
}

/// Formats a slice of `L2vpnPseudowireNeighbor` items into a comma-separated `<IP> <PW_ID>` string for the editor form.
pub fn format_l2vpn_neighbors(neighbors: &[L2vpnPseudowireNeighbor]) -> String {
    neighbors
        .iter()
        .map(|neighbor| format!("{} {}", neighbor.peer_ipv4, neighbor.pw_id))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Normalizes a BVI input such as `"10"` or `"BV10"` or `"BVI10"` into `"BVI10"`.
pub fn normalize_bvi_name(raw_bvi: &str) -> String {
    let trimmed = raw_bvi.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.chars().all(|character| character.is_ascii_digit()) {
        return format!("BVI{}", trimmed);
    }
    expand_full_interface_name(trimmed)
}

/// Holds the editable fields inside the L2VPN Service / Attachment Editor Modal (`w` or `Ctrl+W`).
#[derive(Clone, Debug, Default)]
pub struct L2vpnEditorForm {
    /// `BridgeDomain` (`bridge group` -> `bridge-domain`) or `XconnectP2p` (`xconnect group` -> `p2p`).
    pub service_type: L2vpnServiceType,
    /// `bridge group <group_name>` or `xconnect group <group_name>`.
    pub group_name: String,
    /// `bridge-domain <service_name>` or `p2p <service_name>`.
    pub service_name: String,
    /// Subinterface to attach, modify, or remove (e.g. `"GigabitEthernet0/0/0/1.100"`).
    pub target_interface: String,
    /// Action for `target_interface`:
    /// - `0`: Attach without `split-horizon group`
    /// - `1`: Attach WITH `split-horizon group` (Bridge-Domain only)
    /// - `2`: Remove interface (`no interface <target_interface>`)
    pub interface_action: u8,
    /// Comma-separated `<Peer_IP> <PW_ID>` pseudowire neighbors (for `p2p` or `vfi`).
    pub neighbors_input: String,
    /// Optional `routed interface BVI<id>` (Bridge-Domain only, e.g. `"BVI10"`).
    pub routed_bvi: String,
    /// Optional `mtu <bytes>` (Bridge-Domain only, e.g. `"9100"`).
    pub mtu: String,
    /// Optional `vfi <name>` (Bridge-Domain only; defaults to `service_name` if blank).
    pub vfi_name: String,
    /// If `true`, pressing `Enter` saves this L2VPN config back into the open Port Editor (`pending_l2vpn`)
    /// so both the subinterface and L2VPN stanza push in a single atomic commit.
    pub return_to_port_editor: bool,
    /// Snapshot of the existing L2VPN service on the router for Delta-Only command generation.
    pub original_service: Option<L2vpnServiceEntry>,
}

impl L2vpnEditorForm {
    /// Returns a short one-line summary for display inside the Port Editor's L2VPN field.
    pub fn summary_badge(&self) -> String {
        let group = self.group_name.trim();
        let service = self.service_name.trim();
        if group.is_empty() || service.is_empty() {
            return "Incomplete L2VPN".to_string();
        }
        match self.service_type {
            L2vpnServiceType::BridgeDomain => {
                if self.interface_action == 2 {
                    format!("REMOVE from BD: {}/{}", group, service)
                } else if self.interface_action == 1 {
                    format!("BD: {}/{} [split-horizon]", group, service)
                } else {
                    format!("BD: {}/{}", group, service)
                }
            }
            L2vpnServiceType::XconnectP2p => {
                let neighbors = parse_l2vpn_neighbors(&self.neighbors_input);
                if let Some(first) = neighbors.first() {
                    format!("XC: {}/{} ({}:{})", group, service, first.peer_ipv4, first.pw_id)
                } else {
                    format!("XC: {}/{}", group, service)
                }
            }
        }
    }
}

/// Builds the inner lines under `l2vpn` (without `configure terminal` / `l2vpn` / `commit` / `end`)
/// so they can be used both standalone and embedded inside `build_unified_interface_script`.
pub fn build_l2vpn_inner_commands(form: &L2vpnEditorForm) -> Vec<String> {
    let group_name = form.group_name.trim();
    let service_name = form.service_name.trim();
    if group_name.is_empty() || service_name.is_empty() {
        return Vec::new();
    }

    let full_target_interface = expand_full_interface_name(&form.target_interface);
    let parsed_neighbors = parse_l2vpn_neighbors(&form.neighbors_input);

    let previous_matching = form.original_service.as_ref().filter(|original_service| {
        original_service.service_type == form.service_type
            && original_service.group_name == group_name
            && original_service.service_name == service_name
    });

    let mut lines = Vec::new();

    match form.service_type {
        L2vpnServiceType::XconnectP2p => {
            lines.push(format!(" xconnect group {}", group_name));
            lines.push(format!("  p2p {}", service_name));

            if let Some(previous) = previous_matching {
                // Delta mode for existing p2p xconnect
                if !full_target_interface.is_empty() {
                    if form.interface_action == 2 {
                        lines.push(format!("   no interface {}", full_target_interface));
                    } else {
                        let already_attached = previous
                            .interfaces
                            .iter()
                            .any(|item| same_cisco_interface(&item.interface_name, &full_target_interface));
                        if !already_attached {
                            for old_interface in &previous.interfaces {
                                lines.push(format!("   no interface {}", old_interface.interface_name));
                            }
                            lines.push(format!("   interface {}", full_target_interface));
                        }
                    }
                }

                for old_neighbor in &previous.neighbors {
                    if !parsed_neighbors.contains(old_neighbor) {
                        lines.push(format!(
                            "   no neighbor ipv4 {} pw-id {}",
                            old_neighbor.peer_ipv4, old_neighbor.pw_id
                        ));
                    }
                }
                for new_neighbor in &parsed_neighbors {
                    if !previous.neighbors.contains(new_neighbor) {
                        lines.push(format!(
                            "   neighbor ipv4 {} pw-id {}",
                            new_neighbor.peer_ipv4, new_neighbor.pw_id
                        ));
                    }
                }
            } else {
                // New p2p xconnect
                if !full_target_interface.is_empty() {
                    if form.interface_action == 2 {
                        lines.push(format!("   no interface {}", full_target_interface));
                    } else {
                        lines.push(format!("   interface {}", full_target_interface));
                    }
                }
                for neighbor in &parsed_neighbors {
                    lines.push(format!(
                        "   neighbor ipv4 {} pw-id {}",
                        neighbor.peer_ipv4, neighbor.pw_id
                    ));
                }
            }
        }

        L2vpnServiceType::BridgeDomain => {
            lines.push(format!(" bridge group {}", group_name));
            lines.push(format!("  bridge-domain {}", service_name));

            let normalized_bvi = normalize_bvi_name(&form.routed_bvi);
            let trimmed_mtu = form.mtu.trim();
            let effective_vfi_name = if form.vfi_name.trim().is_empty() {
                service_name
            } else {
                form.vfi_name.trim()
            };

            if let Some(previous) = previous_matching {
                // 1. Bridge-Domain MTU (delta)
                let old_mtu = previous.mtu.trim();
                if old_mtu != trimmed_mtu {
                    if !old_mtu.is_empty() && trimmed_mtu.is_empty() {
                        lines.push(format!("   no mtu {}", old_mtu));
                    } else if !trimmed_mtu.is_empty() {
                        lines.push(format!("   mtu {}", trimmed_mtu));
                    }
                }

                // 2. Target Subinterface Attachment / Split-Horizon / Removal (delta)
                if !full_target_interface.is_empty() {
                    let existing_attachment = previous
                        .interfaces
                        .iter()
                        .find(|item| same_cisco_interface(&item.interface_name, &full_target_interface));

                    let canonical_name = existing_attachment
                        .map(|item| item.interface_name.as_str())
                        .unwrap_or(&full_target_interface);

                    if form.interface_action == 2 {
                        lines.push(format!("   no interface {}", canonical_name));
                    } else {
                        let want_split_horizon = form.interface_action == 1;
                        match existing_attachment {
                            None => {
                                lines.push(format!("   interface {}", canonical_name));
                                if want_split_horizon {
                                    lines.push("    split-horizon group".to_string());
                                }
                            }
                            Some(existing) if existing.split_horizon_group != want_split_horizon => {
                                lines.push(format!("   interface {}", canonical_name));
                                if want_split_horizon {
                                    lines.push("    split-horizon group".to_string());
                                } else {
                                    lines.push("    no split-horizon group".to_string());
                                }
                            }
                            Some(_) => {}
                        }
                    }
                }

                // 3. VFI & Pseudowire Neighbors (delta)
                let mut vfi_subcommands = Vec::new();
                for old_neighbor in &previous.neighbors {
                    if !parsed_neighbors.contains(old_neighbor) {
                        vfi_subcommands.push(format!(
                            "    no neighbor {} pw-id {}",
                            old_neighbor.peer_ipv4, old_neighbor.pw_id
                        ));
                    }
                }
                for new_neighbor in &parsed_neighbors {
                    if !previous.neighbors.contains(new_neighbor) {
                        vfi_subcommands.push(format!(
                            "    neighbor {} pw-id {}",
                            new_neighbor.peer_ipv4, new_neighbor.pw_id
                        ));
                    }
                }

                if !previous.neighbors.is_empty() && parsed_neighbors.is_empty() {
                    let old_vfi = if previous.vfi_name.trim().is_empty() {
                        service_name
                    } else {
                        previous.vfi_name.trim()
                    };
                    lines.push(format!("   no vfi {}", old_vfi));
                } else if !vfi_subcommands.is_empty() {
                    lines.push(format!("   vfi {}", effective_vfi_name));
                    lines.extend(vfi_subcommands);
                }

                // 4. Routed Interface BVI (delta)
                let old_bvi = normalize_bvi_name(&previous.routed_bvi);
                if !same_cisco_interface(&old_bvi, &normalized_bvi) {
                    if !old_bvi.is_empty() {
                        lines.push(format!("   no routed interface {}", old_bvi));
                    }
                    if !normalized_bvi.is_empty() {
                        lines.push(format!("   routed interface {}", normalized_bvi));
                    }
                }
            } else {
                // New Bridge-Domain or uncached service
                if !trimmed_mtu.is_empty() {
                    lines.push(format!("   mtu {}", trimmed_mtu));
                }

                if !full_target_interface.is_empty() {
                    if form.interface_action == 2 {
                        lines.push(format!("   no interface {}", full_target_interface));
                    } else {
                        lines.push(format!("   interface {}", full_target_interface));
                        if form.interface_action == 1 {
                            lines.push("    split-horizon group".to_string());
                        }
                    }
                }

                if !parsed_neighbors.is_empty() {
                    lines.push(format!("   vfi {}", effective_vfi_name));
                    for neighbor in &parsed_neighbors {
                        lines.push(format!(
                            "    neighbor {} pw-id {}",
                            neighbor.peer_ipv4, neighbor.pw_id
                        ));
                    }
                }

                if !normalized_bvi.is_empty() {
                    lines.push(format!("   routed interface {}", normalized_bvi));
                }
            }
        }
    }

    lines
}

/// Builds the complete standalone Cisco CLI script for the L2VPN Service Editor modal.
pub fn build_l2vpn_service_script(
    form: &L2vpnEditorForm,
    operating_system: CiscoOs,
) -> Vec<String> {
    let mut commands = vec!["configure terminal".to_string(), "l2vpn".to_string()];
    commands.extend(build_l2vpn_inner_commands(form));
    if operating_system == CiscoOs::IosXr {
        commands.push("commit".to_string());
    }
    commands.push("end".to_string());
    commands
}

/// Builds a CLI script to delete a subinterface AND automatically remove any reference to it
/// inside `l2vpn` (`bridge-domain` or `xconnect p2p`) in the same atomic commit.
pub fn build_delete_subinterface_with_l2vpn_script(
    interface_name: &str,
    l2vpn_services: &[L2vpnServiceEntry],
    operating_system: CiscoOs,
) -> Result<Vec<String>, String> {
    let trimmed_name = interface_name.trim();
    if !is_deletable_subinterface(trimmed_name) {
        return Err(format!(
            "Safety block: '{}' is not a subinterface and cannot be deleted.",
            trimmed_name
        ));
    }

    let mut command_list = vec![
        "configure terminal".to_string(),
        format!("no interface {}", trimmed_name),
    ];

    // Check if this subinterface is attached to any L2VPN bridge-domain or xconnect
    let mut l2vpn_cleanup_lines = Vec::new();
    for service in l2vpn_services {
        for attached in &service.interfaces {
            if same_cisco_interface(trimmed_name, &attached.interface_name) {
                match service.service_type {
                    L2vpnServiceType::BridgeDomain => {
                        l2vpn_cleanup_lines.push(format!(" bridge group {}", service.group_name));
                        l2vpn_cleanup_lines
                            .push(format!("  bridge-domain {}", service.service_name));
                        l2vpn_cleanup_lines
                            .push(format!("   no interface {}", attached.interface_name));
                    }
                    L2vpnServiceType::XconnectP2p => {
                        l2vpn_cleanup_lines
                            .push(format!(" xconnect group {}", service.group_name));
                        l2vpn_cleanup_lines.push(format!("  p2p {}", service.service_name));
                        l2vpn_cleanup_lines
                            .push(format!("   no interface {}", attached.interface_name));
                    }
                }
            }
        }
    }

    if !l2vpn_cleanup_lines.is_empty() {
        command_list.push("l2vpn".to_string());
        command_list.extend(l2vpn_cleanup_lines);
    }

    if operating_system == CiscoOs::IosXr {
        command_list.push("commit".to_string());
    }
    command_list.push("end".to_string());
    Ok(command_list)
}

/// Builds a CLI script to delete an entire L2VPN `p2p` xconnect or `bridge-domain` stanza.
pub fn build_delete_l2vpn_service_script(
    service: &L2vpnServiceEntry,
    operating_system: CiscoOs,
) -> Vec<String> {
    let mut command_list = vec!["configure terminal".to_string(), "l2vpn".to_string()];
    match service.service_type {
        L2vpnServiceType::XconnectP2p => {
            command_list.push(format!(" xconnect group {}", service.group_name));
            command_list.push(format!("  no p2p {}", service.service_name));
        }
        L2vpnServiceType::BridgeDomain => {
            command_list.push(format!(" bridge group {}", service.group_name));
            command_list.push(format!("  no bridge-domain {}", service.service_name));
        }
    }
    if operating_system == CiscoOs::IosXr {
        command_list.push("commit".to_string());
    }
    command_list.push("end".to_string());
    command_list
}

/// Parses a dotted-decimal IPv4 address or subnet mask into a 32-bit integer.
fn parse_ipv4_to_u32(ipv4_text: &str) -> Option<u32> {
    let octets: Vec<&str> = ipv4_text.trim().split('.').collect();
    if octets.len() != 4 {
        return None;
    }
    let mut value: u32 = 0;
    for octet_text in octets {
        let octet: u8 = octet_text.parse().ok()?;
        value = (value << 8) | (octet as u32);
    }
    Some(value)
}

/// Validates the IPv4 Primary and Secondary fields in `editor_form` and returns
/// human-readable warnings if any address is a subnet network address (e.g. `.0` on a `/24`),
/// a broadcast address (e.g. `.255` on a `/24`), or if Secondary IPs are entered without a Primary IP.
pub fn check_ipv4_warnings(editor_form: &InterfaceEditorForm) -> Vec<String> {
    if editor_form.l2transport {
        return Vec::new();
    }

    let mut warnings = Vec::new();
    let trimmed_primary = editor_form.primary_ip.trim();
    let trimmed_secondary = editor_form.secondary_ip.trim();

    if trimmed_primary.is_empty() && !trimmed_secondary.is_empty() {
        warnings.push(
            "! WARNING: Cisco requires a Primary IPv4 address before adding Secondary IPs"
                .to_string(),
        );
    }

    let mut all_normalized_ips = Vec::new();
    if !trimmed_primary.is_empty() {
        all_normalized_ips.push(normalize_ip_spec(trimmed_primary));
    }
    for secondary_ip in parse_multiple_ips(trimmed_secondary) {
        all_normalized_ips.push(secondary_ip);
    }

    for normalized_ip in all_normalized_ips {
        if let Some((ip_part, mask_part)) = normalized_ip.split_once(' ') {
            if let (Some(ip_address_bits), Some(subnet_mask_bits)) =
                (parse_ipv4_to_u32(ip_part), parse_ipv4_to_u32(mask_part))
            {
                // For masks shorter than /31, all-zero host bits is the network address
                // and all-one host bits is the broadcast address.
                let host_mask = !subnet_mask_bits;
                if host_mask > 1 {
                    let host_bits = ip_address_bits & host_mask;
                    if host_bits == 0 {
                        let suggested_ip = ip_address_bits | 1;
                        let suggested_address_text = format!(
                            "{}.{}.{}.{}",
                            (suggested_ip >> 24) & 0xFF,
                            (suggested_ip >> 16) & 0xFF,
                            (suggested_ip >> 8) & 0xFF,
                            suggested_ip & 0xFF
                        );
                        warnings.push(format!(
                            "! WARNING: {} is a subnet network address (.0); use a host IP like {}",
                            ip_part.trim(),
                            suggested_address_text
                        ));
                    } else if host_bits == host_mask {
                        warnings.push(format!(
                            "! WARNING: {} is a subnet broadcast address for mask {}",
                            ip_part.trim(),
                            mask_part.trim()
                        ));
                    }
                }
            }
        }
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ios_xr_show_int_desc() {
        let sample_output = r#"
RP/0/RSP0/CPU0:Router#show interfaces description
Interface          Status          Protocol    Description
--------------------------------------------------------------------------------
Te0/0/0/0          up              up          Transit Provider Level3
Te0/0/0/1          admin down      down        Maintenance Reserved
Te0/0/0/2.100      up              up          Cust: Acme L2Transport
Bundle-Ether1      up              up          LAG-Core-Spine
Loopback0          up              up          Router-ID BGP
Nu0                up              up          
RP/0/RSP0/CPU0:Router#
"#;
        let parsed_entries = parse_show_interfaces_description(sample_output);
        assert_eq!(parsed_entries.len(), 6);
        assert_eq!(parsed_entries[0].name, "Te0/0/0/0");
        assert_eq!(parsed_entries[0].status, "up");
        assert_eq!(parsed_entries[0].protocol, "up");
        assert_eq!(parsed_entries[0].description, "Transit Provider Level3");

        assert_eq!(parsed_entries[1].name, "Te0/0/0/1");
        assert_eq!(parsed_entries[1].status, "admin down");
        assert_eq!(parsed_entries[1].protocol, "down");
        assert_eq!(parsed_entries[1].description, "Maintenance Reserved");

        assert!(has_ios_xr_interface_naming(&parsed_entries));
    }

    #[test]
    fn test_parse_ios_xe_show_int_desc() {
        let sample_output = r#"
Router#show interfaces description
Interface                      Status         Protocol Description
Gi0/0/0                        up             up       Uplink to ISP
Gi0/0/1                        administratively down down     Spare Port
Gi0/0/2                        down           down     
Router#
"#;
        let parsed_entries = parse_show_interfaces_description(sample_output);
        assert_eq!(parsed_entries.len(), 3);
        assert_eq!(parsed_entries[0].name, "Gi0/0/0");
        assert_eq!(parsed_entries[0].status, "up");
        assert_eq!(parsed_entries[1].name, "Gi0/0/1");
        assert_eq!(parsed_entries[1].status, "admin down");
        assert_eq!(parsed_entries[1].protocol, "down");
        assert_eq!(parsed_entries[1].description, "Spare Port");
        assert_eq!(parsed_entries[2].description, "");
        assert!(!has_ios_xr_interface_naming(&parsed_entries));
    }

    #[test]
    fn test_build_l2transport() {
        let generated_script = build_l2transport_script(
            "TenGigE0/0/0/1.100",
            "100",
            "Customer XYZ L2VPN",
            true,
            Some("9216"),
            true,
            CiscoOs::IosXr,
        );
        assert!(generated_script.contains(&"interface TenGigE0/0/0/1.100 l2transport".to_string()));
        assert!(generated_script.contains(&" encapsulation dot1q 100".to_string()));
        assert!(generated_script.contains(&" rewrite ingress tag pop 1 symmetric".to_string()));
        assert!(generated_script.contains(&" mtu 9216".to_string()));
        assert!(generated_script.contains(&"commit".to_string()));
    }

    #[test]
    fn test_build_shutdown_and_no_shutdown() {
        let shutdown_script = build_shutdown_script("GigabitEthernet0/0/1", CiscoOs::IosXr);
        assert_eq!(
            shutdown_script,
            vec![
                "configure terminal",
                "interface GigabitEthernet0/0/1",
                "shutdown",
                "commit",
                "end"
            ]
        );

        let no_shutdown_script = build_no_shutdown_script("GigabitEthernet0/0/1", CiscoOs::Ios);
        assert_eq!(
            no_shutdown_script,
            vec![
                "configure terminal",
                "interface GigabitEthernet0/0/1",
                "no shutdown",
                "end"
            ]
        );
    }

    #[test]
    fn test_build_description() {
        let update_script =
            build_description_script("TenGigE0/0/0/0", "Transit to Level3", CiscoOs::IosXr);
        assert_eq!(
            update_script,
            vec![
                "configure terminal",
                "interface TenGigE0/0/0/0",
                "description Transit to Level3",
                "commit",
                "end"
            ]
        );

        let clear_script = build_description_script("TenGigE0/0/0/0", "", CiscoOs::Ios);
        assert_eq!(
            clear_script,
            vec![
                "configure terminal",
                "interface TenGigE0/0/0/0",
                "no description",
                "end"
            ]
        );
    }

    #[test]
    fn test_format_subinterface_name() {
        assert_eq!(
            format_subinterface_name("TenGigE0/0/0/1", "100"),
            "TenGigE0/0/0/1.100"
        );
        assert_eq!(
            format_subinterface_name("TenGigE0/0/0/1", ".200"),
            "TenGigE0/0/0/1.200"
        );
        assert_eq!(
            format_subinterface_name("TenGigE0/0/0/1.50", "100"),
            "TenGigE0/0/0/1.100"
        );
    }

    #[test]
    fn test_multiple_secondary_ips() {
        let sample_running_config = r#"interface TenGigE0/0/0/1
 description Multi Gateway Interface
 ipv4 address 10.100.1.1 255.255.255.252
 ipv4 address 192.168.10.1 255.255.255.0 secondary
 ipv4 address 192.168.20.1 255.255.255.0 secondary
 ipv4 address 172.16.1.1 255.255.255.240 secondary
 no shutdown
!"#;
        let parsed_config = parse_interface_running_config(sample_running_config);
        assert_eq!(parsed_config.primary_ip, "10.100.1.1/30");
        assert_eq!(
            parsed_config.secondary_ip,
            "192.168.10.1/24, 192.168.20.1/24, 172.16.1.1/28"
        );

        // 1. New interface creation (original_config is None): emits all configured IPs
        let new_interface_form = InterfaceEditorForm {
            interface: "TenGigE0/0/0/1".to_string(),
            description: "Multi Gateway Interface".to_string(),
            port_enabled: true,
            omit_port_state: false,
            primary_ip: "10.100.1.1/30".to_string(),
            secondary_ip: "192.168.10.1/24, 192.168.20.1/24, 172.16.1.1/28".to_string(),
            l2transport: false,
            vlan_id: String::new(),
            second_vlan_id: String::new(),
            rewrite_ingress_pop: 0,
            mtu: String::new(),
            negotiation_auto: false,
            original_interface: String::new(),
            original_config: None,
            pending_l2vpn: None,
        };

        let generated_script = build_unified_interface_script(&new_interface_form, CiscoOs::IosXr);
        assert!(generated_script.contains(&" ipv4 address 10.100.1.1 255.255.255.252".to_string()));
        assert!(generated_script
            .contains(&" ipv4 address 192.168.10.1 255.255.255.0 secondary".to_string()));
        assert!(generated_script
            .contains(&" ipv4 address 192.168.20.1 255.255.255.0 secondary".to_string()));
        assert!(generated_script
            .contains(&" ipv4 address 172.16.1.1 255.255.255.240 secondary".to_string()));

        // 2. Existing interface edit (original_config is Some): skips unchanged IPs, negates removed IP, adds new IP
        let modified_existing_form = InterfaceEditorForm {
            interface: "TenGigE0/0/0/1".to_string(),
            description: "Multi Gateway Interface".to_string(),
            port_enabled: true,
            omit_port_state: false,
            primary_ip: "10.100.1.1/30".to_string(),
            secondary_ip: "192.168.20.1/24, 172.16.1.1/28, 192.168.30.1/24".to_string(),
            l2transport: false,
            vlan_id: String::new(),
            second_vlan_id: String::new(),
            rewrite_ingress_pop: 0,
            mtu: String::new(),
            negotiation_auto: false,
            original_interface: "TenGigE0/0/0/1".to_string(),
            original_config: Some(parsed_config),
            pending_l2vpn: None,
        };

        let delta_script = build_unified_interface_script(&modified_existing_form, CiscoOs::IosXr);
        // Unchanged primary and unchanged secondaries should NOT be re-sent
        assert!(!delta_script.contains(&" ipv4 address 10.100.1.1 255.255.255.252".to_string()));
        assert!(!delta_script
            .contains(&" ipv4 address 192.168.20.1 255.255.255.0 secondary".to_string()));
        // Removed secondary IP is negated, and newly added secondary IP is pushed
        assert!(delta_script
            .contains(&" no ipv4 address 192.168.10.1 255.255.255.0 secondary".to_string()));
        assert!(delta_script
            .contains(&" ipv4 address 192.168.30.1 255.255.255.0 secondary".to_string()));
    }

    #[test]
    fn test_netmask_to_cidr() {
        assert_eq!(netmask_to_cidr("255.255.255.0"), Some(24));
        assert_eq!(netmask_to_cidr("255.255.255.252"), Some(30));
        assert_eq!(netmask_to_cidr("255.255.255.248"), Some(29));
        assert_eq!(netmask_to_cidr("255.255.255.240"), Some(28));
        assert_eq!(netmask_to_cidr("255.0.0.0"), Some(8));
        assert_eq!(netmask_to_cidr("255.255.0.0"), Some(16));
        assert_eq!(netmask_to_cidr("invalid"), None);
    }

    #[test]
    fn test_cidr_to_netmask() {
        assert_eq!(cidr_to_netmask(24), "255.255.255.0");
        assert_eq!(cidr_to_netmask(30), "255.255.255.252");
        assert_eq!(cidr_to_netmask(32), "255.255.255.255");
        assert_eq!(cidr_to_netmask(16), "255.255.0.0");
    }

    #[test]
    fn test_normalize_ip_spec() {
        assert_eq!(
            normalize_ip_spec("10.100.1.1/30"),
            "10.100.1.1 255.255.255.252"
        );
        assert_eq!(
            normalize_ip_spec("192.168.1.1/24"),
            "192.168.1.1 255.255.255.0"
        );
        assert_eq!(
            normalize_ip_spec("10.0.0.1 255.255.255.0"),
            "10.0.0.1 255.255.255.0"
        );
    }

    #[test]
    fn test_parse_and_build_unified_interface() {
        let sample_config = r#"interface TenGigE0/0/0/1.100 l2transport
 description Existing Circuit
 encapsulation dot1q 100
 rewrite ingress tag pop 1 symmetric
 mtu 9216
 no shutdown
!"#;
        let parsed = parse_interface_running_config(sample_config);
        assert_eq!(parsed.description, "Existing Circuit");
        assert!(parsed.port_enabled);
        assert!(parsed.l2transport);
        assert_eq!(parsed.vlan_id, "100");
        assert_eq!(parsed.second_vlan_id, "");
        assert_eq!(parsed.rewrite_ingress_pop, 1);
        assert_eq!(parsed.mtu, "9216");

        let editor_form = InterfaceEditorForm {
            interface: "Gi0/0/0/1.100".to_string(),
            description: "Core PE Subinterface".to_string(),
            port_enabled: true,
            omit_port_state: false,
            primary_ip: "10.100.1.1/30".to_string(),
            secondary_ip: "192.168.10.1/24".to_string(),
            l2transport: false,
            vlan_id: "100".to_string(),
            second_vlan_id: String::new(),
            rewrite_ingress_pop: 0,
            mtu: String::new(),
            negotiation_auto: true,
            original_interface: String::new(),
            original_config: None,
            pending_l2vpn: None,
        };

        let generated_script = build_unified_interface_script(&editor_form, CiscoOs::IosXr);
        assert!(generated_script.contains(&"interface Gi0/0/0/1.100".to_string()));
        assert!(generated_script.contains(&" description Core PE Subinterface".to_string()));
        assert!(generated_script.contains(&" encapsulation dot1q 100".to_string()));
        assert!(generated_script.contains(&" no shutdown".to_string()));
        assert!(generated_script.contains(&" ipv4 address 10.100.1.1 255.255.255.252".to_string()));
        assert!(generated_script
            .contains(&" ipv4 address 192.168.10.1 255.255.255.0 secondary".to_string()));
        assert!(generated_script.contains(&" negotiation auto".to_string()));
        assert!(!generated_script.iter().any(|line| line.contains("mtu")));
        assert!(generated_script.contains(&"commit".to_string()));
    }

    #[test]
    fn test_double_tagged_qinq_subinterface() {
        let qinq_config = r#"Wed Nov  4 22:57:17.818 UTC
interface TenGigE0/1/0/1.10002000 l2transport
 description Customer Metro ELAN
 encapsulation dot1q 1000 second-dot1q 2000
 rewrite ingress tag pop 2 symmetric
!"#;
        let parsed = parse_interface_running_config(qinq_config);
        assert_eq!(parsed.description, "Customer Metro ELAN");
        assert!(parsed.port_enabled);
        assert!(parsed.l2transport);
        assert_eq!(parsed.vlan_id, "1000");
        assert_eq!(parsed.second_vlan_id, "2000");
        assert_eq!(parsed.rewrite_ingress_pop, 2);

        let (extracted_outer, extracted_inner) =
            extract_vlans_from_subinterface_name("Te0/1/0/1.10002000");
        assert_eq!(extracted_outer, "1000");
        assert_eq!(extracted_inner, "2000");

        let editor_form = InterfaceEditorForm {
            interface: "Te0/1/0/1.10002000".to_string(),
            description: parsed.description.clone(),
            port_enabled: parsed.port_enabled,
            omit_port_state: true,
            primary_ip: parsed.primary_ip.clone(),
            secondary_ip: parsed.secondary_ip.clone(),
            l2transport: parsed.l2transport,
            vlan_id: parsed.vlan_id.clone(),
            second_vlan_id: parsed.second_vlan_id.clone(),
            rewrite_ingress_pop: parsed.rewrite_ingress_pop,
            mtu: parsed.mtu.clone(),
            negotiation_auto: parsed.negotiation_auto,
            original_interface: String::new(),
            original_config: None,
            pending_l2vpn: None,
        };

        let generated_script = build_unified_interface_script(&editor_form, CiscoOs::IosXr);
        assert!(generated_script
            .contains(&"interface Te0/1/0/1.10002000 l2transport".to_string()));
        assert!(generated_script.contains(&" description Customer Metro ELAN".to_string()));
        assert!(generated_script
            .contains(&" encapsulation dot1q 1000 second-dot1q 2000".to_string()));
        assert!(generated_script
            .contains(&" rewrite ingress tag pop 2 symmetric".to_string()));
        assert!(!generated_script
            .iter()
            .any(|line| line.contains("shutdown")));
        assert!(generated_script.contains(&"commit".to_string()));
    }

    #[test]
    fn test_negation_statements_and_subinterface_deletion_safety() {
        let initial_stanza = r#"interface TenGigE0/1/0/1.10002000 l2transport
 description Customer Metro ELAN
 encapsulation dot1q 1000 second-dot1q 2000
 rewrite ingress tag pop 2 symmetric
 mtu 9216
 negotiation auto
!"#;
        let parsed = parse_interface_running_config(initial_stanza);
        assert!(parsed.negotiation_auto);

        // Modify inner VLAN from 2000 -> 2001, clear description, clear MTU, disable negotiation auto, and change pop 2 -> pop 1
        let modified_form = InterfaceEditorForm {
            interface: "Te0/1/0/1.10002000".to_string(),
            description: String::new(),
            port_enabled: true,
            omit_port_state: true,
            primary_ip: String::new(),
            secondary_ip: String::new(),
            l2transport: true,
            vlan_id: "1000".to_string(),
            second_vlan_id: "2001".to_string(),
            rewrite_ingress_pop: 1,
            mtu: String::new(),
            negotiation_auto: false,
            original_interface: "Te0/1/0/1.10002000".to_string(),
            original_config: Some(parsed),
            pending_l2vpn: None,
        };

        let generated_script = build_unified_interface_script(&modified_form, CiscoOs::IosXr);
        assert!(generated_script.contains(&" no description".to_string()));
        assert!(generated_script
            .contains(&" no encapsulation dot1q 1000 second-dot1q 2000".to_string()));
        assert!(generated_script
            .contains(&" encapsulation dot1q 1000 second-dot1q 2001".to_string()));
        assert!(generated_script
            .contains(&" no rewrite ingress tag pop 2 symmetric".to_string()));
        assert!(generated_script
            .contains(&" rewrite ingress tag pop 1 symmetric".to_string()));
        assert!(generated_script.contains(&" no mtu 9216".to_string()));
        assert!(generated_script.contains(&" no negotiation auto".to_string()));

        // Verify subinterface deletion safety check
        assert!(is_deletable_subinterface("Te0/1/0/1.10002000"));
        assert!(is_deletable_subinterface("Gi0/0/0/1.100"));
        assert!(!is_deletable_subinterface("Gi0/0/0/1"));
        assert!(!is_deletable_subinterface("Loopback0"));
        assert!(!is_deletable_subinterface("Bundle-Ether1"));

        assert!(build_delete_subinterface_script("Gi0/0/0/1", CiscoOs::IosXr).is_err());
        let delete_script =
            build_delete_subinterface_script("Te0/1/0/1.10002000", CiscoOs::IosXr).unwrap();
        assert_eq!(
            delete_script,
            vec![
                "configure terminal",
                "no interface Te0/1/0/1.10002000",
                "commit",
                "end"
            ]
        );
    }

    #[test]
    fn test_sanitize_pty_output_and_ipv4_warnings() {
        let raw_router_stream = "configure terminal\r\n\rWed Nov  5 17:20:35.754 UTC\r\nRP/0/RP0/CPU0:router-lab-01(config-if)#ipv4 address 192.168.0.0 255.255.255.0 second\r$ddress 192.168.0.0 255.255.255.0 secondary\r#ipv4 address 192.168.0.0 255.255.255.0 secondary\r\n";
        let sanitized = sanitize_pty_output(raw_router_stream);
        assert!(!sanitized.contains('\r'));
        assert!(sanitized.contains("Wed Nov  5 17:20:35.754 UTC"));
        assert!(sanitized.contains(
            "RP/0/RP0/CPU0:router-lab-01(config-if)#ipv4 address 192.168.0.0 255.255.255.0 secondary"
        ));

        let form_with_network_ip = InterfaceEditorForm {
            interface: "BV10".to_string(),
            l2transport: false,
            primary_ip: String::new(),
            secondary_ip: "192.168.0.0/24, 192.168.1.0/24".to_string(),
            ..Default::default()
        };
        let warnings = check_ipv4_warnings(&form_with_network_ip);
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("Primary IPv4")));
        assert!(warnings
            .iter()
            .any(|warning| warning.contains("192.168.0.0 is a subnet network address")));
    }

    #[test]
    fn test_parse_and_build_l2vpn() {
        let sample_l2vpn_config = r#"l2vpn
 load-balancing flow src-dst-ip
 xconnect group METRO_CIRCUITS
  p2p CUSTOMER_SITE_A
   interface GigabitEthernet0/0/0/1.100
   neighbor ipv4 192.0.2.10 pw-id 100
   !
  !
 !
 bridge group ENTERPRISE_SERVICES
  bridge-domain CORP_VOICE
   mtu 9100
   interface Bundle-Ether10.200
    split-horizon group
   !
   interface TenGigE0/0/0/1.200
   !
   vfi CORP_VOICE
    neighbor 192.0.2.20 pw-id 200
    !
   !
   routed interface BVI20
   !
  !
 !
!"#;
        let services = parse_running_config_l2vpn(sample_l2vpn_config);
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].service_type, L2vpnServiceType::XconnectP2p);
        assert_eq!(services[0].group_name, "METRO_CIRCUITS");
        assert_eq!(services[0].service_name, "CUSTOMER_SITE_A");
        assert_eq!(
            services[0].interfaces[0].interface_name,
            "GigabitEthernet0/0/0/1.100"
        );
        assert_eq!(services[0].neighbors[0].peer_ipv4, "192.0.2.10");
        assert_eq!(services[0].neighbors[0].pw_id, "100");

        assert_eq!(services[1].service_type, L2vpnServiceType::BridgeDomain);
        assert_eq!(services[1].group_name, "ENTERPRISE_SERVICES");
        assert_eq!(services[1].service_name, "CORP_VOICE");
        assert_eq!(services[1].mtu, "9100");
        assert_eq!(services[1].routed_bvi, "BVI20");
        assert!(services[1].interfaces[0].split_horizon_group);
        assert!(!services[1].interfaces[1].split_horizon_group);

        // Short interface name lookup should match full interface names
        let (matched_xconnect, xconnect_badge) =
            find_l2vpn_for_interface("Gi0/0/0/1.100", &services).unwrap();
        assert_eq!(matched_xconnect.service_name, "CUSTOMER_SITE_A");
        assert_eq!(
            xconnect_badge,
            "XC: METRO_CIRCUITS/CUSTOMER_SITE_A (192.0.2.10:100)"
        );

        let (matched_bridge_domain, bridge_domain_badge) =
            find_l2vpn_for_interface("BE10.200", &services).unwrap();
        assert_eq!(matched_bridge_domain.service_name, "CORP_VOICE");
        assert_eq!(bridge_domain_badge, "BD: ENTERPRISE_SERVICES/CORP_VOICE [SHG]");

        // Deleting a subinterface that belongs to a Bridge-Domain should clean up L2VPN as well
        let delete_script =
            build_delete_subinterface_with_l2vpn_script("BE10.200", &services, CiscoOs::IosXr)
                .unwrap();
        assert!(delete_script.contains(&"no interface BE10.200".to_string()));
        assert!(delete_script.contains(&"l2vpn".to_string()));
        assert!(delete_script.contains(&" bridge group ENTERPRISE_SERVICES".to_string()));
        assert!(delete_script.contains(&"  bridge-domain CORP_VOICE".to_string()));
        assert!(delete_script.contains(&"   no interface Bundle-Ether10.200".to_string()));
    }
}
