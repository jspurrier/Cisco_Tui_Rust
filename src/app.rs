use crate::cisco::{
    build_delete_l2vpn_service_script, build_delete_subinterface_with_l2vpn_script,
    build_l2vpn_service_script, build_no_shutdown_script, build_shutdown_script,
    build_unified_interface_script, expand_full_interface_name,
    extract_vlans_from_subinterface_name, find_l2vpn_for_interface, format_l2vpn_neighbors,
    has_ios_xr_interface_naming, is_deletable_subinterface, parse_interface_running_config,
    same_cisco_interface, InterfaceEditorForm, L2vpnEditorForm,
};
use crate::model::{
    ActionLog, CiscoOs, ConnectionConfig, InterfaceEntry, L2vpnServiceEntry, L2vpnServiceType,
    LogLevel, SortField, SshRequest, SshResponse,
};
use ratatui::widgets::TableState;
use std::collections::HashMap;
use tokio::sync::mpsc;

/// Identifies which screen or popup modal currently has keyboard focus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentView {
    InterfaceList,
    L2vpnList,
    ViewConfig,
    EditInterface,
    EditL2vpn,
    ConfirmAction,
    ConnectionModal,
    CommandRunner,
    ActionLogs,
    Help,
}

/// Central application state for the TUI.
pub struct App {
    pub current_view: CurrentView,
    pub previous_view: CurrentView,

    // Main interface table state
    pub interfaces: Vec<InterfaceEntry>,
    pub table_state: TableState,
    pub selected_interface_name: Option<String>,
    pub filter_query: String,
    pub is_filtering: bool,
    pub sort_field: SortField,
    pub sort_ascending: bool,

    // Local cache of `show running-config interface <name>` outputs for instant opening
    pub config_cache: HashMap<String, String>,

    // Active router connection metadata
    pub connected_host: String,
    pub connected_os: CiscoOs,
    pub is_connected: bool,
    pub is_loading: bool,
    pub status_message: String,
    pub device_banner: String,

    // Connection login modal fields
    pub connection_host: String,
    pub connection_port: String,
    pub connection_username: String,
    pub connection_password: String,
    pub connection_os: CiscoOs,
    pub connection_use_mock: bool,
    pub connection_active_field: usize,
    pub connection_show_password: bool,

    // Unified Port Configuration Editor state
    // Field indices follow strict visual reading order (left-to-right, top-to-bottom):
    //   0: Interface Name      (Row 1, Left)
    //   1: Port State          (Row 1, Right)
    //   2: Description         (Row 2, Full width)
    //   3: IPv4 Primary        (Row 3, Left)
    //   4: IPv4 Secondary      (Row 3, Right)
    //   5: Port Mode (L2/L3)   (Row 4, Col 1)
    //   6: Dot1Q Outer VLAN    (Row 4, Col 2)
    //   7: 2nd Dot1Q VLAN      (Row 4, Col 3)
    //   8: Rewrite Ingress Tag (Row 4, Col 4)
    //   9: Jumbo MTU           (Row 5, Left)
    //  10: Negotiation Auto    (Row 5, Right)
    pub editor_form: InterfaceEditorForm,
    pub editor_active_field: usize,

    // L2VPN (Xconnect & Bridge-Domain) Table & Editor state
    pub l2vpn_services: Vec<L2vpnServiceEntry>,
    pub l2vpn_table_state: TableState,
    pub l2vpn_filter_query: String,
    pub l2vpn_is_filtering: bool,
    pub l2vpn_form: L2vpnEditorForm,
    pub l2vpn_active_field: usize,

    // Confirmation modal state
    pub confirm_title: String,
    pub confirm_commands: Vec<String>,
    pub confirm_action_description: String,

    // Running-config viewer modal state
    pub config_interface: String,
    pub config_content: String,
    pub config_scroll: usize,

    // Custom CLI command runner modal state
    pub command_input: String,
    pub command_output: String,
    pub command_scroll: usize,

    // Audit log viewer state
    pub logs: Vec<ActionLog>,
    pub logs_scroll: usize,

    // Channel sender to the background SSH worker task
    pub ssh_request_sender: mpsc::Sender<SshRequest>,

    // Flag indicating the user requested application exit
    pub should_quit: bool,
}

impl App {
    pub fn new(
        ssh_request_sender: mpsc::Sender<SshRequest>,
        initial_connection_config: Option<ConnectionConfig>,
    ) -> Self {
        let mut initial_table_state = TableState::default();
        initial_table_state.select(Some(0));

        let mut initial_l2vpn_table_state = TableState::default();
        initial_l2vpn_table_state.select(Some(0));

        let (host, port_text, username, password, operating_system, use_mock_router) =
            if let Some(config) = initial_connection_config {
                (
                    config.host,
                    config.port.to_string(),
                    config.username,
                    config.password,
                    config.operating_system,
                    config.use_mock_router,
                )
            } else {
                (
                    String::new(),
                    "22".to_string(),
                    String::new(),
                    String::new(),
                    CiscoOs::IosXr,
                    false,
                )
            };

        Self {
            current_view: CurrentView::InterfaceList,
            previous_view: CurrentView::InterfaceList,

            interfaces: Vec::new(),
            table_state: initial_table_state,
            selected_interface_name: None,
            filter_query: String::new(),
            is_filtering: false,
            sort_field: SortField::Name,
            sort_ascending: true,

            config_cache: HashMap::new(),

            connected_host: "Not Connected".to_string(),
            connected_os: operating_system,
            is_connected: false,
            is_loading: false,
            status_message: "Press [c] to connect to a Cisco Router".to_string(),
            device_banner: String::new(),

            connection_host: host,
            connection_port: port_text,
            connection_username: username,
            connection_password: password,
            connection_os: operating_system,
            connection_use_mock: use_mock_router,
            connection_active_field: 0,
            connection_show_password: false,

            editor_form: InterfaceEditorForm::default(),
            editor_active_field: 0,

            l2vpn_services: Vec::new(),
            l2vpn_table_state: initial_l2vpn_table_state,
            l2vpn_filter_query: String::new(),
            l2vpn_is_filtering: false,
            l2vpn_form: L2vpnEditorForm::default(),
            l2vpn_active_field: 0,

            confirm_title: String::new(),
            confirm_commands: Vec::new(),
            confirm_action_description: String::new(),

            config_interface: String::new(),
            config_content: String::new(),
            config_scroll: 0,

            command_input: String::new(),
            command_output: String::new(),
            command_scroll: 0,

            logs: vec![ActionLog::new(
                LogLevel::Info,
                "Cisco TUI initialized. Ready for operations.",
            )],
            logs_scroll: 0,

            ssh_request_sender,
            should_quit: false,
        }
    }

    /// Returns the list of interfaces matching the current search filter, ordered by `sort_field`.
    pub fn filtered_interfaces(&self) -> Vec<&InterfaceEntry> {
        let lowercase_query = self.filter_query.to_lowercase();

        let mut matching_interfaces: Vec<&InterfaceEntry> = self
            .interfaces
            .iter()
            .filter(|entry| {
                if lowercase_query.is_empty() {
                    true
                } else {
                    let l2vpn_match = find_l2vpn_for_interface(&entry.name, &self.l2vpn_services)
                        .map(|(_, label)| label.to_lowercase().contains(&lowercase_query))
                        .unwrap_or(false);
                    entry.name.to_lowercase().contains(&lowercase_query)
                        || entry.description.to_lowercase().contains(&lowercase_query)
                        || entry.status.to_lowercase().contains(&lowercase_query)
                        || entry.protocol.to_lowercase().contains(&lowercase_query)
                        || l2vpn_match
                }
            })
            .collect();

        matching_interfaces.sort_by(|left_entry, right_entry| {
            let ordering = match self.sort_field {
                SortField::Name => left_entry.name.cmp(&right_entry.name),
                SortField::Status => left_entry.status.cmp(&right_entry.status),
                SortField::Protocol => left_entry.protocol.cmp(&right_entry.protocol),
                SortField::Description => left_entry.description.cmp(&right_entry.description),
            };
            if self.sort_ascending {
                ordering
            } else {
                ordering.reverse()
            }
        });

        matching_interfaces
    }

    /// Returns a reference to the currently highlighted interface row in the table.
    pub fn selected_interface(&self) -> Option<&InterfaceEntry> {
        let visible_interfaces = self.filtered_interfaces();
        if visible_interfaces.is_empty() {
            None
        } else {
            let selected_index = self
                .table_state
                .selected()
                .unwrap_or(0)
                .min(visible_interfaces.len() - 1);
            Some(visible_interfaces[selected_index])
        }
    }

    pub fn next_row(&mut self) {
        let visible_count = self.filtered_interfaces().len();
        if visible_count == 0 {
            self.table_state.select(None);
            self.selected_interface_name = None;
            return;
        }
        let current_index = self.table_state.selected().unwrap_or(0);
        let next_index = (current_index + 1).min(visible_count - 1);
        self.table_state.select(Some(next_index));
        self.selected_interface_name = self.selected_interface().map(|entry| entry.name.clone());
    }

    pub fn previous_row(&mut self) {
        let visible_count = self.filtered_interfaces().len();
        if visible_count == 0 {
            self.table_state.select(None);
            self.selected_interface_name = None;
            return;
        }
        let current_index = self.table_state.selected().unwrap_or(0);
        let previous_index = current_index.saturating_sub(1);
        self.table_state.select(Some(previous_index));
        self.selected_interface_name = self.selected_interface().map(|entry| entry.name.clone());
    }

    pub fn page_down(&mut self, page_size: usize) {
        let visible_count = self.filtered_interfaces().len();
        if visible_count == 0 {
            return;
        }
        let current_index = self.table_state.selected().unwrap_or(0);
        let next_index = (current_index + page_size).min(visible_count - 1);
        self.table_state.select(Some(next_index));
        self.selected_interface_name = self.selected_interface().map(|entry| entry.name.clone());
    }

    pub fn page_up(&mut self, page_size: usize) {
        let visible_count = self.filtered_interfaces().len();
        if visible_count == 0 {
            return;
        }
        let current_index = self.table_state.selected().unwrap_or(0);
        let previous_index = current_index.saturating_sub(page_size);
        self.table_state.select(Some(previous_index));
        self.selected_interface_name = self.selected_interface().map(|entry| entry.name.clone());
    }

    pub fn cycle_sort(&mut self) {
        self.sort_field = match self.sort_field {
            SortField::Name => SortField::Status,
            SortField::Status => SortField::Protocol,
            SortField::Protocol => SortField::Description,
            SortField::Description => SortField::Name,
        };
        self.sort_ascending = true;

        // Keep the same interface highlighted after re-sorting the table
        if let Some(selected_name) = self.selected_interface_name.clone() {
            let new_position = self
                .filtered_interfaces()
                .iter()
                .position(|entry| entry.name == selected_name);
            if let Some(index) = new_position {
                self.table_state.select(Some(index));
            }
        }

        self.add_log(
            LogLevel::Info,
            format!("Sorted interface table by {:?}", self.sort_field),
        );
    }

    /// Toggles the target Cisco OS syntax mode between `Cisco IOS / IOS-XE` and `Cisco IOS-XR`.
    pub fn toggle_operating_system(&mut self) {
        self.connected_os = match self.connected_os {
            CiscoOs::Ios => CiscoOs::IosXr,
            CiscoOs::IosXr => CiscoOs::Ios,
        };
        self.status_message = format!(
            "Switched CLI syntax mode to {}",
            self.connected_os.display_name()
        );
        self.add_log(
            LogLevel::Info,
            format!(
                "Switched CLI syntax mode to {}",
                self.connected_os.display_name()
            ),
        );
    }

    /// Validates the connection modal inputs and dispatches a `Connect` request to the SSH worker.
    pub fn initiate_connect_from_modal(&mut self) {
        let trimmed_host = self.connection_host.trim().to_string();
        if trimmed_host.is_empty() {
            self.status_message =
                "Please enter a router IP, hostname, or 'demo'".to_string();
            self.connection_active_field = 0;
            return;
        }

        let is_demo_session =
            self.connection_use_mock || trimmed_host.eq_ignore_ascii_case("demo");
        if !is_demo_session && self.connection_username.trim().is_empty() {
            self.status_message = "Please enter your SSH username".to_string();
            self.connection_active_field = 1;
            return;
        }

        let parsed_port: u16 = self.connection_port.trim().parse().unwrap_or(22);
        let connection_config = ConnectionConfig {
            host: trimmed_host.clone(),
            port: parsed_port,
            username: self.connection_username.trim().to_string(),
            password: self.connection_password.clone(),
            operating_system: self.connection_os,
            use_mock_router: is_demo_session,
        };

        self.is_loading = true;
        self.status_message = format!("Connecting to {} and probing router OS...", trimmed_host);

        self.add_log(
            LogLevel::Info,
            format!(
                "Connecting to {}@{}:{} [Demo={}]",
                connection_config.username,
                connection_config.host,
                connection_config.port,
                connection_config.use_mock_router
            ),
        );

        let sender = self.ssh_request_sender.clone();
        tokio::spawn(async move {
            let _ = sender.send(SshRequest::Connect(connection_config)).await;
        });
    }

    /// Disconnects from the current router session, clears device-specific state,
    /// and returns to the Connection / Login screen so the operator can connect to another device.
    pub fn disconnect_to_login_modal(&mut self) {
        let previous_host = self.connected_host.clone();
        self.is_connected = false;
        self.is_loading = false;
        self.connected_host = "Not Connected".to_string();
        self.interfaces.clear();
        self.l2vpn_services.clear();
        self.config_cache.clear();
        self.selected_interface_name = None;
        self.filter_query.clear();
        self.is_filtering = false;
        self.l2vpn_filter_query.clear();
        self.l2vpn_is_filtering = false;
        self.current_view = CurrentView::ConnectionModal;
        self.connection_active_field = 0;
        self.status_message = format!(
            "Disconnected from {}. Enter another device IP/Host (or press Esc to quit).",
            previous_host
        );
        self.add_log(
            LogLevel::Info,
            format!(
                "Disconnected from {} and returned to login screen",
                previous_host
            ),
        );

        let sender = self.ssh_request_sender.clone();
        tokio::spawn(async move {
            let _ = sender.send(SshRequest::Disconnect).await;
        });
    }

    /// Requests a fresh `show interfaces description` poll from the connected router.
    pub fn refresh_interfaces(&mut self) {
        if !self.is_connected {
            self.status_message = "Not connected. Press [c] to connect.".to_string();
            return;
        }
        self.is_loading = true;
        self.status_message = format!(
            "Refreshing interface table from {}...",
            self.connected_host
        );
        let sender = self.ssh_request_sender.clone();
        tokio::spawn(async move {
            let _ = sender.send(SshRequest::FetchInterfaces).await;
        });
    }

    /// Opens the read-only Running Configuration modal for the currently selected port.
    pub fn initiate_view_config(&mut self) {
        let selected_name_option = self.selected_interface().map(|entry| entry.name.clone());
        if let Some(interface_name) = selected_name_option {
            self.config_interface = interface_name.clone();

            if let Some(cached_config) = self.config_cache.get(&interface_name) {
                self.config_content = cached_config.clone();
            } else {
                self.config_content = "Loading running-config from router...".to_string();
            }

            self.config_scroll = 0;
            self.previous_view = self.current_view;
            self.current_view = CurrentView::ViewConfig;

            let sender = self.ssh_request_sender.clone();
            tokio::spawn(async move {
                let _ = sender
                    .send(SshRequest::GetConfig { interface_name })
                    .await;
            });
        }
    }

    /// Opens the Unified Port Configuration Editor for the currently selected interface.
    /// Populates immediately from local cache or table state and asynchronously fetches
    /// the latest running-config from the router to fill in any IP/VLAN/MTU details.
    pub fn initiate_edit_interface(&mut self) {
        let selected_entry_option = self.selected_interface().cloned();
        if let Some(interface_entry) = selected_entry_option {
            let interface_name = interface_entry.name.clone();

            let is_enabled_in_table = !interface_entry.status.to_lowercase().contains("admin");

            let mut populated_form =
                if let Some(cached_config) = self.config_cache.get(&interface_name) {
                    let mut parsed_config = parse_interface_running_config(cached_config);
                    if !parsed_config.has_explicit_shutdown_state {
                        parsed_config.port_enabled = is_enabled_in_table;
                    }
                    let is_subinterface = interface_name.contains('.');
                    InterfaceEditorForm {
                        interface: interface_name.clone(),
                        description: if !parsed_config.description.is_empty() {
                            parsed_config.description.clone()
                        } else {
                            interface_entry.description.clone()
                        },
                        port_enabled: parsed_config.port_enabled,
                        omit_port_state: is_subinterface && !parsed_config.has_explicit_shutdown_state,
                        primary_ip: parsed_config.primary_ip.clone(),
                        secondary_ip: parsed_config.secondary_ip.clone(),
                        l2transport: parsed_config.l2transport,
                        vlan_id: parsed_config.vlan_id.clone(),
                        second_vlan_id: parsed_config.second_vlan_id.clone(),
                        rewrite_ingress_pop: parsed_config.rewrite_ingress_pop,
                        mtu: parsed_config.mtu.clone(),
                        negotiation_auto: parsed_config.negotiation_auto,
                        original_interface: interface_name.clone(),
                        original_config: Some(parsed_config),
                        pending_l2vpn: None,
                    }
                } else {
                    let is_subinterface = interface_name.contains('.');
                    let (extracted_outer_vlan, extracted_inner_vlan) = if is_subinterface {
                        extract_vlans_from_subinterface_name(&interface_name)
                    } else {
                        (String::new(), String::new())
                    };
                    let default_pop_count = if !extracted_inner_vlan.is_empty() {
                        2
                    } else if is_subinterface {
                        1
                    } else {
                        0
                    };

                    // Request the full interface stanza in the background so IPs/VLANs/MTU populate automatically
                    InterfaceEditorForm {
                        interface: interface_name.clone(),
                        description: interface_entry.description.clone(),
                        port_enabled: is_enabled_in_table,
                        omit_port_state: is_subinterface,
                        primary_ip: String::new(),
                        secondary_ip: String::new(),
                        l2transport: is_subinterface,
                        vlan_id: extracted_outer_vlan,
                        second_vlan_id: extracted_inner_vlan,
                        rewrite_ingress_pop: default_pop_count,
                        mtu: String::new(),
                        negotiation_auto: false,
                        original_interface: interface_name.clone(),
                        original_config: None,
                        pending_l2vpn: None,
                    }
                };

            // Always request the latest running-config from the router so the editor reflects live state
            let sender = self.ssh_request_sender.clone();
            let requested_interface = interface_name.clone();
            tokio::spawn(async move {
                let _ = sender
                    .send(SshRequest::GetConfig {
                        interface_name: requested_interface,
                    })
                    .await;
            });

            if populated_form.interface.contains('.') && populated_form.vlan_id.is_empty() {
                let (outer_vlan, inner_vlan) =
                    extract_vlans_from_subinterface_name(&populated_form.interface);
                populated_form.vlan_id = outer_vlan;
                if populated_form.second_vlan_id.is_empty() {
                    populated_form.second_vlan_id = inner_vlan;
                }
            }

            self.editor_form = populated_form;
            // Start at Field 0 (Interface Name) so Tab / Right Arrow moves naturally to Port State (Field 1)
            self.editor_active_field = 0;
            self.previous_view = self.current_view;
            self.current_view = CurrentView::EditInterface;
        }
    }

    /// Opens the Unified Port Configuration Editor pre-filled to create a new subinterface
    /// (for example `Gi0/0/0/1.100` or `Gi0/0/0/1.100 l2transport`) on the selected parent port.
    pub fn initiate_add_subinterface(&mut self) {
        let selected_name = self
            .selected_interface()
            .map(|entry| entry.name.clone())
            .unwrap_or_else(|| "GigabitEthernet0/0/0/0".to_string());

        let parent_interface = if let Some((base_name, _)) = selected_name.split_once('.') {
            base_name.to_string()
        } else {
            selected_name
        };

        let new_subinterface_name = format!("{}.100", parent_interface);
        self.editor_form = InterfaceEditorForm {
            interface: new_subinterface_name,
            description: format!("Subinterface on {}", parent_interface),
            port_enabled: true,
            omit_port_state: true,
            primary_ip: String::new(),
            secondary_ip: String::new(),
            l2transport: true,
            vlan_id: "100".to_string(),
            second_vlan_id: String::new(),
            rewrite_ingress_pop: 1,
            mtu: String::new(),
            negotiation_auto: false,
            original_interface: String::new(),
            original_config: None,
            pending_l2vpn: None,
        };
        // Start on Field 0 (Interface Name) so the user can immediately type their desired `.vlan` number
        self.editor_active_field = 0;
        self.previous_view = self.current_view;
        self.current_view = CurrentView::EditInterface;
    }

    /// Prepares a confirmation modal to delete a subinterface (`no interface <subif>`)
    /// from the main interface table. Strictly refuses if the selected port is not a subinterface.
    pub fn initiate_delete_subinterface(&mut self) {
        let Some(selected_name) = self.selected_interface().map(|entry| entry.name.clone()) else {
            return;
        };
        self.prepare_delete_subinterface_confirmation(&selected_name);
    }

    /// Prepares a confirmation modal to delete the subinterface currently open in the editor.
    /// Strictly refuses if the port is not a subinterface.
    pub fn initiate_delete_subinterface_from_editor(&mut self) {
        let target_name = self.editor_form.interface.trim().to_string();
        if target_name.is_empty() {
            return;
        }
        self.prepare_delete_subinterface_confirmation(&target_name);
    }

    fn prepare_delete_subinterface_confirmation(&mut self, interface_name: &str) {
        if !is_deletable_subinterface(interface_name) {
            self.status_message = format!(
                "SAFETY BLOCK: Cannot delete non-subinterface '{}'. Only .vlan subports can be removed.",
                interface_name
            );
            self.add_log(
                LogLevel::Warning,
                format!(
                    "Blocked attempt to delete non-subinterface '{}'",
                    interface_name
                ),
            );
            return;
        }

        match build_delete_subinterface_with_l2vpn_script(
            interface_name,
            &self.l2vpn_services,
            self.connected_os,
        ) {
            Ok(generated_commands) => {
                self.confirm_title = format!("DELETE SUBINTERFACE - {}", interface_name);
                self.confirm_action_description =
                    format!("Delete subinterface {}", interface_name);
                self.confirm_commands = generated_commands;
                self.previous_view = self.current_view;
                self.current_view = CurrentView::ConfirmAction;
            }
            Err(error_message) => {
                self.status_message = error_message.clone();
                self.add_log(LogLevel::Warning, error_message);
            }
        }
    }

    /// Returns all L2VPN services matching `l2vpn_filter_query`.
    pub fn filtered_l2vpn_services(&self) -> Vec<&L2vpnServiceEntry> {
        let lowercase_query = self.l2vpn_filter_query.to_lowercase();
        self.l2vpn_services
            .iter()
            .filter(|service| {
                if lowercase_query.is_empty() {
                    true
                } else {
                    service.group_name.to_lowercase().contains(&lowercase_query)
                        || service
                            .service_name
                            .to_lowercase()
                            .contains(&lowercase_query)
                        || service
                            .service_type
                            .short_label()
                            .to_lowercase()
                            .contains(&lowercase_query)
                        || service
                            .routed_bvi
                            .to_lowercase()
                            .contains(&lowercase_query)
                        || service.interfaces.iter().any(|interface_attachment| {
                            interface_attachment
                                .interface_name
                                .to_lowercase()
                                .contains(&lowercase_query)
                        })
                        || service.neighbors.iter().any(|neighbor| {
                            neighbor
                                .peer_ipv4
                                .to_lowercase()
                                .contains(&lowercase_query)
                                || neighbor.pw_id.to_lowercase().contains(&lowercase_query)
                        })
                }
            })
            .collect()
    }

    /// Returns the currently highlighted L2VPN service in `CurrentView::L2vpnList`.
    pub fn selected_l2vpn_service(&self) -> Option<&L2vpnServiceEntry> {
        let visible = self.filtered_l2vpn_services();
        if visible.is_empty() {
            None
        } else {
            let selected_index = self
                .l2vpn_table_state
                .selected()
                .unwrap_or(0)
                .min(visible.len() - 1);
            Some(visible[selected_index])
        }
    }

    pub fn l2vpn_next_row(&mut self) {
        let visible_count = self.filtered_l2vpn_services().len();
        if visible_count == 0 {
            self.l2vpn_table_state.select(None);
            return;
        }
        let current = self.l2vpn_table_state.selected().unwrap_or(0);
        self.l2vpn_table_state
            .select(Some((current + 1).min(visible_count - 1)));
    }

    pub fn l2vpn_previous_row(&mut self) {
        let visible_count = self.filtered_l2vpn_services().len();
        if visible_count == 0 {
            self.l2vpn_table_state.select(None);
            return;
        }
        let current = self.l2vpn_table_state.selected().unwrap_or(0);
        self.l2vpn_table_state
            .select(Some(current.saturating_sub(1)));
    }

    pub fn l2vpn_page_down(&mut self, page_size: usize) {
        let visible_count = self.filtered_l2vpn_services().len();
        if visible_count == 0 {
            return;
        }
        let current = self.l2vpn_table_state.selected().unwrap_or(0);
        self.l2vpn_table_state
            .select(Some((current + page_size).min(visible_count - 1)));
    }

    pub fn l2vpn_page_up(&mut self, page_size: usize) {
        let visible_count = self.filtered_l2vpn_services().len();
        if visible_count == 0 {
            return;
        }
        let current = self.l2vpn_table_state.selected().unwrap_or(0);
        self.l2vpn_table_state
            .select(Some(current.saturating_sub(page_size)));
    }

    /// Populates `self.l2vpn_form` from an existing `L2vpnServiceEntry`.
    pub fn populate_l2vpn_form_from_service(
        &mut self,
        service: &L2vpnServiceEntry,
        focus_interface: Option<&str>,
        return_to_port_editor: bool,
    ) {
        let target_interface = if let Some(requested_interface) = focus_interface {
            expand_full_interface_name(requested_interface)
        } else {
            service
                .interfaces
                .first()
                .map(|interface_attachment| interface_attachment.interface_name.clone())
                .unwrap_or_default()
        };

        let interface_action = if target_interface.is_empty() {
            0
        } else if let Some(existing_attachment) = service
            .interfaces
            .iter()
            .find(|interface_attachment| {
                same_cisco_interface(&interface_attachment.interface_name, &target_interface)
            })
        {
            if service.service_type == L2vpnServiceType::BridgeDomain
                && existing_attachment.split_horizon_group
            {
                1
            } else {
                0
            }
        } else if service.service_type == L2vpnServiceType::BridgeDomain {
            1 // Default new access subinterfaces on a Bridge-Domain to `Attach + split-horizon group`
        } else {
            0
        };

        self.l2vpn_form = L2vpnEditorForm {
            service_type: service.service_type,
            group_name: service.group_name.clone(),
            service_name: service.service_name.clone(),
            target_interface,
            interface_action,
            neighbors_input: format_l2vpn_neighbors(&service.neighbors),
            vfi_name: service.vfi_name.clone(),
            routed_bvi: service.routed_bvi.clone(),
            mtu: service.mtu.clone(),
            original_service: Some(service.clone()),
            return_to_port_editor,
        };
    }

    /// Opens the L2VPN Editor modal for the currently selected port (from the Interface Table or Port Editor).
    pub fn initiate_edit_l2vpn_for_selected_interface(&mut self, from_port_editor: bool) {
        if from_port_editor {
            if let Some(existing_pending) = self.editor_form.pending_l2vpn.clone() {
                self.l2vpn_form = existing_pending;
                self.l2vpn_form.return_to_port_editor = true;
                self.l2vpn_form.target_interface =
                    expand_full_interface_name(self.editor_form.interface.trim());
                self.l2vpn_active_field = 1;
                self.previous_view = CurrentView::EditInterface;
                self.current_view = CurrentView::EditL2vpn;
                return;
            }
        }

        let target_port_name = if from_port_editor {
            self.editor_form.interface.trim().to_string()
        } else {
            match self.selected_interface() {
                Some(entry) => entry.name.clone(),
                None => return,
            }
        };

        if target_port_name.is_empty() {
            return;
        }

        if let Some((existing_service, _)) =
            find_l2vpn_for_interface(&target_port_name, &self.l2vpn_services)
        {
            let cloned_service = existing_service.clone();
            self.populate_l2vpn_form_from_service(
                &cloned_service,
                Some(&target_port_name),
                from_port_editor,
            );
            self.l2vpn_active_field = 5; // Focus Interface Action / Split-Horizon toggle
        } else {
            let expanded_port = expand_full_interface_name(&target_port_name);
            let is_bvi = expanded_port.to_uppercase().starts_with("BVI");
            self.l2vpn_form = L2vpnEditorForm {
                service_type: L2vpnServiceType::BridgeDomain,
                group_name: String::new(),
                service_name: String::new(),
                target_interface: if is_bvi {
                    String::new()
                } else {
                    expanded_port.clone()
                },
                interface_action: if is_bvi { 0 } else { 1 }, // Default subinterface to Attach + split-horizon group
                neighbors_input: String::new(),
                vfi_name: String::new(),
                routed_bvi: if is_bvi { expanded_port } else { String::new() },
                mtu: String::new(),
                original_service: None,
                return_to_port_editor: from_port_editor,
            };
            // Start on Field 1 (Existing Group/BD Picker) so the user can press Space/Right to pick an existing Bridge-Domain or Xconnect group
            self.l2vpn_active_field = 1;
        }

        self.previous_view = self.current_view;
        self.current_view = CurrentView::EditL2vpn;
    }

    /// Opens the L2VPN Editor modal for the highlighted row in `CurrentView::L2vpnList`.
    pub fn initiate_edit_selected_l2vpn_service(&mut self) {
        let Some(selected_service) = self.selected_l2vpn_service().cloned() else {
            return;
        };
        self.populate_l2vpn_form_from_service(&selected_service, None, false);
        self.l2vpn_active_field = 4; // Focus Target Interface
        self.previous_view = CurrentView::L2vpnList;
        self.current_view = CurrentView::EditL2vpn;
    }

    /// Opens the L2VPN Editor modal to create a brand-new Xconnect or Bridge-Domain service.
    pub fn initiate_add_l2vpn_service(&mut self) {
        self.l2vpn_form = L2vpnEditorForm {
            service_type: L2vpnServiceType::BridgeDomain,
            group_name: String::new(),
            service_name: String::new(),
            target_interface: String::new(),
            interface_action: 1,
            neighbors_input: String::new(),
            vfi_name: String::new(),
            routed_bvi: String::new(),
            mtu: String::new(),
            original_service: None,
            return_to_port_editor: false,
        };
        self.l2vpn_active_field = 0;
        self.previous_view = self.current_view;
        self.current_view = CurrentView::EditL2vpn;
    }

    /// Cycles through existing router L2VPN services in Field 1 (`Existing Group/BD Picker`)
    /// so the operator can attach a port to an existing Bridge-Domain or Xconnect without typing.
    pub fn cycle_l2vpn_preset(&mut self, forward: bool) {
        let matching_services: Vec<L2vpnServiceEntry> = self
            .l2vpn_services
            .iter()
            .filter(|service| service.service_type == self.l2vpn_form.service_type)
            .cloned()
            .collect();

        if matching_services.is_empty() {
            self.status_message = format!(
                "No existing {} services found on router; type Group and Service Name below.",
                self.l2vpn_form.service_type.display_name()
            );
            return;
        }

        let current_position = matching_services.iter().position(|service| {
            service.group_name == self.l2vpn_form.group_name
                && service.service_name == self.l2vpn_form.service_name
        });

        let next_index = match current_position {
            Some(index) => {
                if forward {
                    (index + 1) % matching_services.len()
                } else if index == 0 {
                    matching_services.len() - 1
                } else {
                    index - 1
                }
            }
            None => 0,
        };

        let chosen = &matching_services[next_index];
        let preserved_target = self.l2vpn_form.target_interface.clone();
        let preserved_return = self.l2vpn_form.return_to_port_editor;

        let focus_interface = if !preserved_target.is_empty() {
            Some(preserved_target.as_str())
        } else {
            None
        };
        self.populate_l2vpn_form_from_service(chosen, focus_interface, preserved_return);
    }

    /// Cycles Field 4 (`Target Interface`) through candidate ports:
    /// first any member interfaces already attached to this Bridge-Domain / Xconnect,
    /// followed by all `.vlan` subinterfaces present on the router.
    pub fn cycle_l2vpn_target_interface(&mut self) {
        let mut candidate_ports: Vec<(String, Option<bool>)> = Vec::new();

        if let Some(ref original_service) = self.l2vpn_form.original_service {
            for attached in &original_service.interfaces {
                candidate_ports.push((
                    attached.interface_name.clone(),
                    Some(attached.split_horizon_group),
                ));
            }
        }

        for entry in &self.interfaces {
            if entry.name.contains('.') {
                let expanded = expand_full_interface_name(&entry.name);
                let already_listed = candidate_ports
                    .iter()
                    .any(|(existing, _)| same_cisco_interface(existing, &expanded));
                if !already_listed {
                    candidate_ports.push((expanded, None));
                }
            }
        }

        if candidate_ports.is_empty() {
            return;
        }

        let current_index = candidate_ports.iter().position(|(name, _)| {
            same_cisco_interface(name, &self.l2vpn_form.target_interface)
        });
        let next_index = match current_index {
            Some(index) => (index + 1) % candidate_ports.len(),
            None => 0,
        };

        let (chosen_name, existing_split_horizon) = &candidate_ports[next_index];
        self.l2vpn_form.target_interface = chosen_name.clone();
        self.l2vpn_form.interface_action = match existing_split_horizon {
            Some(true) => 1,
            Some(false) => 0,
            None => {
                if self.l2vpn_form.service_type == L2vpnServiceType::BridgeDomain {
                    1 // Default newly picked subinterface on a BD to +split-horizon group
                } else {
                    0
                }
            }
        };
    }

    /// Requests a fresh `show running-config l2vpn` poll from the connected router.
    pub fn refresh_l2vpn(&mut self) {
        if !self.is_connected {
            self.status_message = "Not connected. Press [c] to connect.".to_string();
            return;
        }
        self.status_message = format!("Refreshing L2VPN table from {}...", self.connected_host);
        let sender = self.ssh_request_sender.clone();
        tokio::spawn(async move {
            let _ = sender.send(SshRequest::FetchL2vpn).await;
        });
    }

    /// Validates and confirms the L2VPN Editor modal.
    /// If opened from the Port Editor (`Ctrl+W`), attaches the L2VPN config to `editor_form.pending_l2vpn`
    /// so both push together in a single atomic commit. Otherwise opens `ConfirmAction`.
    pub fn confirm_l2vpn_form(&mut self) {
        if self.l2vpn_form.group_name.trim().is_empty()
            || self.l2vpn_form.service_name.trim().is_empty()
        {
            self.status_message =
                "L2VPN Group Name and Service (BD / P2P) Name are required.".to_string();
            return;
        }

        if self.l2vpn_form.return_to_port_editor {
            let summary = format!(
                "{}: {}/{}",
                self.l2vpn_form.service_type.short_label(),
                self.l2vpn_form.group_name.trim(),
                self.l2vpn_form.service_name.trim()
            );
            self.editor_form.pending_l2vpn = Some(self.l2vpn_form.clone());
            self.status_message = format!(
                "Attached L2VPN ({}) to port editor — press Enter in Port Editor to commit both.",
                summary
            );
            self.current_view = CurrentView::EditInterface;
            return;
        }

        let generated_commands = build_l2vpn_service_script(&self.l2vpn_form, self.connected_os);
        let title_label = format!(
            "{} {}/{}",
            self.l2vpn_form.service_type.short_label(),
            self.l2vpn_form.group_name.trim(),
            self.l2vpn_form.service_name.trim()
        );
        self.confirm_title = format!("CONFIGURE L2VPN - {}", title_label);
        self.confirm_action_description = format!("Configure L2VPN {}", title_label);
        self.confirm_commands = generated_commands;
        self.previous_view = CurrentView::EditL2vpn;
        self.current_view = CurrentView::ConfirmAction;
    }

    /// Prepares a confirmation modal to delete an entire Xconnect P2P or Bridge-Domain stanza.
    pub fn initiate_delete_selected_l2vpn_service(&mut self) {
        let Some(selected_service) = self.selected_l2vpn_service().cloned() else {
            return;
        };
        let generated_commands =
            build_delete_l2vpn_service_script(&selected_service, self.connected_os);
        let label = format!(
            "{} {}/{}",
            selected_service.service_type.short_label(),
            selected_service.group_name,
            selected_service.service_name
        );
        self.confirm_title = format!("DELETE L2VPN SERVICE - {}", label);
        self.confirm_action_description = format!("Delete L2VPN {}", label);
        self.confirm_commands = generated_commands;
        self.previous_view = CurrentView::L2vpnList;
        self.current_view = CurrentView::ConfirmAction;
    }

    /// Transitions from the Unified Port Editor to the Confirmation modal.
    pub fn confirm_editor_form(&mut self) {
        let generated_commands =
            build_unified_interface_script(&self.editor_form, self.connected_os);
        let target_interface = self.editor_form.interface.trim().to_string();
        self.confirm_title = format!("CONFIGURE INTERFACE - {}", target_interface);
        self.confirm_action_description = format!("Update configuration on {}", target_interface);
        self.confirm_commands = generated_commands;
        self.previous_view = CurrentView::EditInterface;
        self.current_view = CurrentView::ConfirmAction;
    }

    /// Prepares a quick `no shutdown` confirmation for the selected interface.
    pub fn initiate_no_shutdown(&mut self) {
        let selected_name_option = self.selected_interface().map(|entry| entry.name.clone());
        if let Some(interface_name) = selected_name_option {
            let generated_commands =
                build_no_shutdown_script(&interface_name, self.connected_os);
            self.confirm_title = format!("ENABLE PORT (no shutdown) - {}", interface_name);
            self.confirm_action_description =
                format!("Enable port (no shutdown) {}", interface_name);
            self.confirm_commands = generated_commands;
            self.previous_view = self.current_view;
            self.current_view = CurrentView::ConfirmAction;
        }
    }

    /// Prepares a quick `shutdown` confirmation for the selected interface.
    pub fn initiate_shutdown(&mut self) {
        let selected_name_option = self.selected_interface().map(|entry| entry.name.clone());
        if let Some(interface_name) = selected_name_option {
            let generated_commands = build_shutdown_script(&interface_name, self.connected_os);
            self.confirm_title = format!("ADMIN DISABLE PORT (shutdown) - {}", interface_name);
            self.confirm_action_description =
                format!("Admin disable port (shutdown) {}", interface_name);
            self.confirm_commands = generated_commands;
            self.previous_view = self.current_view;
            self.current_view = CurrentView::ConfirmAction;
        }
    }

    /// Sends the confirmed CLI commands to the background SSH worker for execution.
    pub fn execute_confirmed_action(&mut self) {
        let commands_to_push = self.confirm_commands.clone();
        let action_description = self.confirm_action_description.clone();

        // Invalidate cached config for any modified or deleted interface so the next view fetches fresh state
        for command_line in &commands_to_push {
            let trimmed_line = command_line.trim();
            if let Some(after_keyword) = trimmed_line.strip_prefix("interface ") {
                if let Some(interface_name) = after_keyword.split_whitespace().next() {
                    self.config_cache.remove(interface_name);
                }
            } else if let Some(after_no_interface) = trimmed_line.strip_prefix("no interface ") {
                if let Some(interface_name) = after_no_interface.split_whitespace().next() {
                    self.config_cache.remove(interface_name);
                }
            }
        }

        self.is_loading = true;
        self.status_message = format!("Pushing '{}' to router...", action_description);
        self.current_view = CurrentView::InterfaceList;

        self.add_log(
            LogLevel::Info,
            format!("Pushing configuration: {}", action_description),
        );

        let sender = self.ssh_request_sender.clone();
        tokio::spawn(async move {
            let _ = sender
                .send(SshRequest::PushConfig {
                    commands: commands_to_push,
                    action_description,
                })
                .await;
        });
    }

    /// Sends a custom CLI show/exec command to the router from the Command Runner modal.
    pub fn execute_custom_command(&mut self) {
        let trimmed_command = self.command_input.trim().to_string();
        if trimmed_command.is_empty() {
            return;
        }
        self.command_output = format!("Running '{}' on router...", trimmed_command);
        self.command_scroll = 0;

        self.add_log(LogLevel::Info, format!("CLI Exec: {}", trimmed_command));

        let sender = self.ssh_request_sender.clone();
        tokio::spawn(async move {
            let _ = sender
                .send(SshRequest::RunCommand {
                    command: trimmed_command,
                })
                .await;
        });
    }

    pub fn handle_ssh_response(&mut self, worker_response: SshResponse) {
        match worker_response {
            SshResponse::Connected {
                host,
                operating_system,
                banner,
            } => {
                self.is_connected = true;
                self.is_loading = false;
                self.connected_host = host.clone();
                self.connected_os = operating_system;
                self.device_banner = banner;
                self.status_message = format!(
                    "Connected to {} | OS: {}",
                    host,
                    operating_system.display_name()
                );
                self.current_view = CurrentView::InterfaceList;
                self.add_log(
                    LogLevel::Success,
                    format!(
                        "Connected to {} ({})",
                        host,
                        operating_system.display_name()
                    ),
                );
            }
            SshResponse::Interfaces(Ok(polled_entries)) => {
                self.is_loading = false;
                let interface_count = polled_entries.len();

                // Automatically upgrade to Cisco IOS-XR mode if 4-part interface names (e.g. Gi0/0/0/6) are present
                if has_ios_xr_interface_naming(&polled_entries)
                    && self.connected_os != CiscoOs::IosXr
                {
                    self.connected_os = CiscoOs::IosXr;
                    self.add_log(
                        LogLevel::Info,
                        "Detected 4-part rack/slot/module/port interfaces; set CLI mode to Cisco IOS-XR."
                            .to_string(),
                    );
                }

                self.interfaces = polled_entries;

                // Preserve selection on the same interface name across table refreshes
                let visible_names: Vec<String> = self
                    .filtered_interfaces()
                    .iter()
                    .map(|entry| entry.name.clone())
                    .collect();

                if let Some(ref current_selected_name) = self.selected_interface_name {
                    if let Some(matching_index) = visible_names
                        .iter()
                        .position(|name| name == current_selected_name)
                    {
                        self.table_state.select(Some(matching_index));
                    } else if !visible_names.is_empty() {
                        self.table_state.select(Some(0));
                        self.selected_interface_name = Some(visible_names[0].clone());
                    }
                } else if !visible_names.is_empty() {
                    self.table_state.select(Some(0));
                    self.selected_interface_name = Some(visible_names[0].clone());
                }

                self.status_message = format!(
                    "Connected to {} ({}) | Total Ports: {}",
                    self.connected_host,
                    self.connected_os.display_name(),
                    interface_count
                );
                self.add_log(
                    LogLevel::Info,
                    format!("Polled {} interfaces from router", interface_count),
                );
            }
            SshResponse::Interfaces(Err(error_message)) => {
                self.is_loading = false;
                self.status_message = format!("Failed to poll interfaces: {}", error_message);
                self.add_log(
                    LogLevel::Error,
                    format!("Interface poll error: {}", error_message),
                );
            }
            SshResponse::L2vpnServices(Ok(polled_services)) => {
                let service_count = polled_services.len();
                self.l2vpn_services = polled_services;
                let visible_count = self.filtered_l2vpn_services().len();
                if visible_count == 0 {
                    self.l2vpn_table_state.select(None);
                } else {
                    let current = self.l2vpn_table_state.selected().unwrap_or(0);
                    self.l2vpn_table_state
                        .select(Some(current.min(visible_count - 1)));
                }
                self.add_log(
                    LogLevel::Info,
                    format!("Polled {} L2VPN services from router", service_count),
                );
            }
            SshResponse::L2vpnServices(Err(error_message)) => {
                self.add_log(
                    LogLevel::Warning,
                    format!("L2VPN poll error: {}", error_message),
                );
            }
            SshResponse::ConfigResult {
                interface_name,
                result: Ok(running_config),
            } => {
                self.is_loading = false;
                self.config_cache
                    .insert(interface_name.clone(), running_config.clone());

                if self.config_interface == interface_name {
                    self.config_content = running_config.clone();
                }

                // If the user currently has this interface open in the editor, populate all parsed running-config fields
                if self.current_view == CurrentView::EditInterface
                    && self.editor_form.interface == interface_name
                {
                    let mut parsed_config = parse_interface_running_config(&running_config);
                    if !parsed_config.has_explicit_shutdown_state {
                        if let Some(table_entry) = self
                            .interfaces
                            .iter()
                            .find(|entry| entry.name == interface_name)
                        {
                            parsed_config.port_enabled =
                                !table_entry.status.to_lowercase().contains("admin");
                        }
                    }

                    if !parsed_config.description.is_empty() {
                        self.editor_form.description = parsed_config.description.clone();
                    }
                    self.editor_form.port_enabled = parsed_config.port_enabled;
                    self.editor_form.omit_port_state =
                        interface_name.contains('.') && !parsed_config.has_explicit_shutdown_state;
                    if !parsed_config.primary_ip.is_empty() {
                        self.editor_form.primary_ip = parsed_config.primary_ip.clone();
                    }
                    if !parsed_config.secondary_ip.is_empty() {
                        self.editor_form.secondary_ip = parsed_config.secondary_ip.clone();
                    }
                    if !parsed_config.mtu.is_empty() {
                        self.editor_form.mtu = parsed_config.mtu.clone();
                    }
                    if !parsed_config.vlan_id.is_empty() {
                        self.editor_form.vlan_id = parsed_config.vlan_id.clone();
                    }
                    if !parsed_config.second_vlan_id.is_empty() {
                        self.editor_form.second_vlan_id = parsed_config.second_vlan_id.clone();
                    }
                    self.editor_form.l2transport = parsed_config.l2transport;
                    self.editor_form.rewrite_ingress_pop = parsed_config.rewrite_ingress_pop;
                    self.editor_form.negotiation_auto = parsed_config.negotiation_auto;
                    self.editor_form.original_interface = interface_name.clone();
                    self.editor_form.original_config = Some(parsed_config);
                }

                self.add_log(
                    LogLevel::Info,
                    format!("Loaded running-config for {}", interface_name),
                );
            }
            SshResponse::ConfigResult {
                interface_name,
                result: Err(error_message),
            } => {
                self.is_loading = false;
                if self.config_interface == interface_name {
                    self.config_content =
                        format!("Error retrieving running-config: {}", error_message);
                }
                self.add_log(
                    LogLevel::Error,
                    format!(
                        "Error loading running-config for {}: {}",
                        interface_name, error_message
                    ),
                );
            }
            SshResponse::PushResult {
                action_description,
                result: Ok(router_transcript),
            } => {
                self.is_loading = false;
                self.config_cache.clear();
                self.status_message = format!("[SUCCESS] {}", action_description);
                self.add_log(
                    LogLevel::Success,
                    format!("Executed: {}", action_description),
                );
                self.logs.push(ActionLog::with_details(
                    LogLevel::Success,
                    format!("Commit transcript: {}", action_description),
                    "Configuration Push",
                    router_transcript,
                ));
            }
            SshResponse::PushResult {
                action_description,
                result: Err(error_transcript),
            } => {
                self.is_loading = false;
                self.status_message =
                    format!("[FAILED] {} (Showing router error details)", action_description);
                self.logs.push(ActionLog::with_details(
                    LogLevel::Error,
                    format!("Failed: {}", action_description),
                    "Configuration Push Error",
                    error_transcript.clone(),
                ));

                // Automatically open the scrollable viewer so the full router error & `show configuration failed` output is visible
                self.config_interface = format!("PUSH FAILED: {}", action_description);
                self.config_content = error_transcript;
                self.config_scroll = 0;
                self.previous_view = CurrentView::InterfaceList;
                self.current_view = CurrentView::ViewConfig;
            }
            SshResponse::CommandResult {
                command,
                result: Ok(command_output),
            } => {
                self.command_output = command_output;
                self.add_log(
                    LogLevel::Success,
                    format!("Command succeeded: {}", command),
                );
            }
            SshResponse::CommandResult {
                command,
                result: Err(error_message),
            } => {
                self.command_output = format!("Command error: {}", error_message);
                self.add_log(
                    LogLevel::Error,
                    format!("Command failed: {} ({})", command, error_message),
                );
            }
            SshResponse::ConnectionError(error_message) => {
                self.is_connected = false;
                self.is_loading = false;
                self.connected_host = "Not Connected".to_string();
                self.interfaces.clear();
                self.l2vpn_services.clear();
                self.config_cache.clear();
                self.selected_interface_name = None;
                self.status_message = format!("Session ended: {}", error_message);
                self.current_view = CurrentView::ConnectionModal;
                self.connection_active_field = 0;
                self.add_log(
                    LogLevel::Error,
                    format!("Session / connection ended: {}", error_message),
                );
            }
            SshResponse::Status(status_text) => {
                self.status_message = status_text.clone();
                self.add_log(LogLevel::Info, status_text);
            }
        }
    }

    pub fn add_log(&mut self, level: LogLevel, message: impl Into<String>) {
        self.logs.push(ActionLog::new(level, message));
        if self.logs.len() > 200 {
            self.logs.remove(0);
        }
    }
}
