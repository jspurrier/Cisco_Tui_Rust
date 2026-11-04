use crate::cisco::{
    clean_cisco_output, has_ios_xr_interface_naming, parse_running_config_l2vpn,
    parse_show_interfaces_description, sanitize_pty_output,
};
use crate::model::{
    CiscoOs, ConnectionConfig, InterfaceEntry, L2vpnServiceEntry, SshRequest, SshResponse,
};
use async_trait::async_trait;
use russh::client::{self, Handle};
use russh::{Channel, ChannelMsg};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Minimal SSH client callback handler required by `russh`.
/// Accepts router host keys so operators can connect to lab and production devices
/// without pre-populating an external `known_hosts` file.
struct RouterSshClientHandler;

#[async_trait]
impl client::Handler for RouterSshClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &russh_keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Background worker that owns the persistent SSH channel (or offline mock router)
/// and processes requests sent from the TUI event loop.
pub struct SshWorker {
    request_receiver: mpsc::Receiver<SshRequest>,
    response_sender: mpsc::Sender<SshResponse>,
    active_connection_config: Option<ConnectionConfig>,
    live_ssh_channel: Option<Channel<client::Msg>>,
    live_ssh_session: Option<Handle<RouterSshClientHandler>>,
    mock_router: Option<MockCiscoRouter>,
}

impl SshWorker {
    pub fn new(
        request_receiver: mpsc::Receiver<SshRequest>,
        response_sender: mpsc::Sender<SshResponse>,
    ) -> Self {
        Self {
            request_receiver,
            response_sender,
            active_connection_config: None,
            live_ssh_channel: None,
            live_ssh_session: None,
            mock_router: None,
        }
    }

    /// Main asynchronous processing loop for SSH operations.
    /// Simultaneously listens for TUI requests and monitors the live SSH channel for
    /// router-initiated disconnects or VTY `exec-timeout` closures.
    pub async fn run(mut self) {
        loop {
            let next_request = if let Some(active_channel) = self.live_ssh_channel.as_mut() {
                tokio::select! {
                    maybe_request = self.request_receiver.recv() => maybe_request,
                    channel_event = active_channel.wait() => {
                        match channel_event {
                            Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                                self.close_current_session().await;
                                let _ = self
                                    .response_sender
                                    .send(SshResponse::ConnectionError(
                                        "Router closed SSH session (idle exec-timeout or remote disconnect).".to_string(),
                                    ))
                                    .await;
                            }
                            Some(ChannelMsg::Data { ref data }) => {
                                let text = String::from_utf8_lossy(data);
                                let lower = text.to_lowercase();
                                if lower.contains("timeout")
                                    || lower.contains("idle")
                                    || lower.contains("connection closed")
                                {
                                    self.close_current_session().await;
                                    let _ = self
                                        .response_sender
                                        .send(SshResponse::ConnectionError(
                                            "Router session timed out (VTY exec-timeout).".to_string(),
                                        ))
                                        .await;
                                }
                            }
                            _ => {}
                        }
                        continue;
                    }
                }
            } else {
                self.request_receiver.recv().await
            };

            let Some(incoming_request) = next_request else {
                break;
            };

            match incoming_request {
                SshRequest::Connect(connection_config) => {
                    self.handle_connect(connection_config).await;
                }
                SshRequest::FetchInterfaces => {
                    self.handle_fetch_interfaces().await;
                }
                SshRequest::FetchL2vpn => {
                    self.handle_fetch_l2vpn().await;
                }
                SshRequest::GetConfig { interface_name } => {
                    self.handle_get_config(interface_name).await;
                }
                SshRequest::PushConfig {
                    commands,
                    action_description,
                } => {
                    self.handle_push_config(commands, action_description).await;
                }
                SshRequest::RunCommand { command } => {
                    self.handle_run_command(command).await;
                }
                SshRequest::Disconnect => {
                    self.close_current_session().await;
                }
            }
        }
    }

    /// Cleanly closes any open SSH channel or mock router state.
    async fn close_current_session(&mut self) {
        if let Some(open_channel) = self.live_ssh_channel.take() {
            let _ = open_channel.eof().await;
        }
        self.live_ssh_session = None;
        self.mock_router = None;
        self.active_connection_config = None;
    }

    /// Establishes a new SSH session (or initializes the simulated demo router),
    /// disables CLI pagination, probes the Cisco OS type, and triggers an initial port poll.
    async fn handle_connect(&mut self, connection_config: ConnectionConfig) {
        self.close_current_session().await;

        let _ = self
            .response_sender
            .send(SshResponse::Status(format!(
                "Connecting to {}@{}:{}...",
                connection_config.username, connection_config.host, connection_config.port
            )))
            .await;

        let is_demo_session = connection_config.use_mock_router
            || connection_config.host.eq_ignore_ascii_case("demo");

        if is_demo_session {
            let simulated_router = MockCiscoRouter::new(connection_config.operating_system);
            self.mock_router = Some(simulated_router);
            self.active_connection_config = Some(connection_config.clone());

            let display_hostname = if connection_config.host.eq_ignore_ascii_case("demo") {
                "cisco-asr9k (Demo)".to_string()
            } else {
                format!("{} (Demo)", connection_config.host)
            };

            let login_banner = format!(
                "Connected to [MOCK DEMO] {} ({})\nCisco IOS XR Software, Version 7.9.2\nSystem uptime is 42 weeks, 3 days",
                display_hostname,
                connection_config.operating_system.display_name()
            );

            let _ = self
                .response_sender
                .send(SshResponse::Connected {
                    host: display_hostname,
                    operating_system: connection_config.operating_system,
                    banner: login_banner,
                })
                .await;

            self.handle_fetch_interfaces().await;
            return;
        }

        // Configure and initiate the live SSH TCP connection
        let ssh_client_config = Arc::new(client::Config::default());
        let connect_future = client::connect(
            ssh_client_config,
            (&connection_config.host[..], connection_config.port),
            RouterSshClientHandler,
        );

        let connection_attempt =
            tokio::time::timeout(Duration::from_secs(10), connect_future).await;

        match connection_attempt {
            Ok(Ok(mut ssh_session)) => {
                let auth_result = ssh_session
                    .authenticate_password(
                        &connection_config.username,
                        &connection_config.password,
                    )
                    .await;

                match auth_result {
                    Ok(true) => match ssh_session.channel_open_session().await {
                        Ok(mut ssh_channel) => {
                            let _ = ssh_channel
                                .request_pty(false, "xterm", 512, 50, 0, 0, &[])
                                .await;

                            if let Err(shell_error) = ssh_channel.request_shell(true).await {
                                let _ = self
                                    .response_sender
                                    .send(SshResponse::ConnectionError(format!(
                                        "Failed to open interactive shell: {}",
                                        shell_error
                                    )))
                                    .await;
                                return;
                            }

                            // Wait for the initial router login banner and prompt before sending setup commands
                            let initial_banner =
                                read_channel_until_prompt_or_quiet(&mut ssh_channel, 3000).await;

                            // Disable pagination and 80-column line wrapping once the router prompt is ready
                            let _ = ssh_channel.data(&b"terminal length 0\n"[..]).await;
                            let _ =
                                read_channel_until_prompt_or_quiet(&mut ssh_channel, 1500).await;

                            let _ = ssh_channel.data(&b"terminal width 512\n"[..]).await;
                            let _ =
                                read_channel_until_prompt_or_quiet(&mut ssh_channel, 1500).await;

                            let _ = self
                                .response_sender
                                .send(SshResponse::Status(
                                    "Connected. Detecting Cisco operating system...".to_string(),
                                ))
                                .await;

                            // Probe whether the device runs Cisco IOS-XR or IOS / IOS-XE
                            let lowercase_banner = initial_banner.to_lowercase();
                            let detected_operating_system = if lowercase_banner.contains("ios xr")
                                || lowercase_banner.contains("ios-xr")
                                || initial_banner.contains("RP/")
                            {
                                CiscoOs::IosXr
                            } else {
                                let _ = ssh_channel.data(&b"show version\n"[..]).await;
                                let version_output =
                                    read_channel_until_prompt_or_quiet(&mut ssh_channel, 1000)
                                        .await;
                                let lowercase_version = version_output.to_lowercase();
                                if lowercase_version.contains("ios xr")
                                    || lowercase_version.contains("ios-xr")
                                    || version_output.contains("RP/")
                                {
                                    CiscoOs::IosXr
                                } else {
                                    CiscoOs::Ios
                                }
                            };

                            let mut active_config = connection_config.clone();
                            active_config.operating_system = detected_operating_system;

                            self.active_connection_config = Some(active_config);
                            self.live_ssh_channel = Some(ssh_channel);
                            self.live_ssh_session = Some(ssh_session);

                            let _ = self
                                .response_sender
                                .send(SshResponse::Connected {
                                    host: connection_config.host,
                                    operating_system: detected_operating_system,
                                    banner: initial_banner,
                                })
                                .await;

                            self.handle_fetch_interfaces().await;
                        }
                        Err(channel_error) => {
                            let _ = self
                                .response_sender
                                .send(SshResponse::ConnectionError(format!(
                                    "Failed to open SSH session channel: {}",
                                    channel_error
                                )))
                                .await;
                        }
                    },
                    Ok(false) => {
                        let _ = self
                            .response_sender
                            .send(SshResponse::ConnectionError(
                                "Authentication failed: invalid username or password".to_string(),
                            ))
                            .await;
                    }
                    Err(auth_error) => {
                        let _ = self
                            .response_sender
                            .send(SshResponse::ConnectionError(format!(
                                "SSH authentication error: {}",
                                auth_error
                            )))
                            .await;
                    }
                }
            }
            Ok(Err(connect_error)) => {
                let _ = self
                    .response_sender
                    .send(SshResponse::ConnectionError(format!(
                        "Unable to connect to {}:{}: {}",
                        connection_config.host, connection_config.port, connect_error
                    )))
                    .await;
            }
            Err(_) => {
                let _ = self
                    .response_sender
                    .send(SshResponse::ConnectionError(format!(
                        "Connection to {}:{} timed out after 10 seconds",
                        connection_config.host, connection_config.port
                    )))
                    .await;
            }
        }
    }

    /// Queries `show interfaces description` from the router and returns the parsed table rows.
    async fn handle_fetch_interfaces(&mut self) {
        if let Some(simulated_router) = &self.mock_router {
            let interface_list = simulated_router.get_interfaces();
            let _ = self
                .response_sender
                .send(SshResponse::Interfaces(Ok(interface_list)))
                .await;
            self.handle_fetch_l2vpn().await;
            return;
        }

        let ssh_channel = match self.live_ssh_channel.as_mut() {
            Some(channel) => channel,
            None => {
                let _ = self
                    .response_sender
                    .send(SshResponse::Interfaces(Err(
                        "Not connected to a router".to_string(),
                    )))
                    .await;
                return;
            }
        };

        let command_text = "show interfaces description\n";
        if let Err(send_error) = ssh_channel.data(command_text.as_bytes()).await {
            let _ = self
                .response_sender
                .send(SshResponse::Interfaces(Err(format!(
                    "Failed to send command: {}",
                    send_error
                ))))
                .await;
            return;
        }

        let raw_output = read_channel_until_prompt_or_quiet(ssh_channel, 1000).await;
        let parsed_interfaces = parse_show_interfaces_description(&raw_output);

        // If the router has 4-part interface names like Gi0/0/0/6, ensure OS is set to IOS-XR
        if has_ios_xr_interface_naming(&parsed_interfaces) {
            if let Some(active_config) = self.active_connection_config.as_mut() {
                active_config.operating_system = CiscoOs::IosXr;
            }
        }

        let _ = self
            .response_sender
            .send(SshResponse::Interfaces(Ok(parsed_interfaces)))
            .await;

        self.handle_fetch_l2vpn().await;
    }

    /// Queries `show running-config l2vpn` from the router and returns all parsed Xconnects & Bridge-Domains.
    async fn handle_fetch_l2vpn(&mut self) {
        if let Some(simulated_router) = &self.mock_router {
            let services = simulated_router.get_l2vpn_services();
            let _ = self
                .response_sender
                .send(SshResponse::L2vpnServices(Ok(services)))
                .await;
            return;
        }

        let ssh_channel = match self.live_ssh_channel.as_mut() {
            Some(channel) => channel,
            None => {
                let _ = self
                    .response_sender
                    .send(SshResponse::L2vpnServices(Err(
                        "Not connected to a router".to_string(),
                    )))
                    .await;
                return;
            }
        };

        // Drain any lingering bytes from earlier commands before sending the new request
        while let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_millis(20), ssh_channel.wait()).await
        {}

        let command_text = "show running-config l2vpn\n";
        if let Err(send_error) = ssh_channel.data(command_text.as_bytes()).await {
            let _ = self
                .response_sender
                .send(SshResponse::L2vpnServices(Err(format!(
                    "Failed to send command: {}",
                    send_error
                ))))
                .await;
            return;
        }

        let raw_output = read_channel_until_prompt_or_quiet(ssh_channel, 2500).await;
        let parsed_services = parse_running_config_l2vpn(&raw_output);

        let _ = self
            .response_sender
            .send(SshResponse::L2vpnServices(Ok(parsed_services)))
            .await;
    }

    /// Queries `show running-config interface <name>` for a specific port.
    async fn handle_get_config(&mut self, interface_name: String) {
        if let Some(simulated_router) = &self.mock_router {
            let running_config = simulated_router.get_config(&interface_name);
            let _ = self
                .response_sender
                .send(SshResponse::ConfigResult {
                    interface_name,
                    result: Ok(running_config),
                })
                .await;
            return;
        }

        let ssh_channel = match self.live_ssh_channel.as_mut() {
            Some(channel) => channel,
            None => {
                let _ = self
                    .response_sender
                    .send(SshResponse::ConfigResult {
                        interface_name,
                        result: Err("Not connected to a router".to_string()),
                    })
                    .await;
                return;
            }
        };

        // Drain any lingering bytes from earlier commands before sending the new request
        while let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_millis(20), ssh_channel.wait()).await
        {}

        let command_text = format!("show running-config interface {}\n", interface_name);
        if let Err(send_error) = ssh_channel.data(command_text.as_bytes()).await {
            let _ = self
                .response_sender
                .send(SshResponse::ConfigResult {
                    interface_name,
                    result: Err(format!("Failed to send command: {}", send_error)),
                })
                .await;
            return;
        }

        let raw_output = read_channel_until_prompt_or_quiet(ssh_channel, 800).await;
        let cleaned_config = clean_cisco_output(&raw_output, &command_text);

        let _ = self
            .response_sender
            .send(SshResponse::ConfigResult {
                interface_name,
                result: Ok(cleaned_config),
            })
            .await;
    }

    /// Pushes a sequence of configuration lines to the router and refreshes the interface table.
    async fn handle_push_config(&mut self, commands: Vec<String>, action_description: String) {
        if let Some(simulated_router) = &mut self.mock_router {
            let execution_transcript = simulated_router.execute_config(&commands);
            let _ = self
                .response_sender
                .send(SshResponse::PushResult {
                    action_description,
                    result: Ok(execution_transcript),
                })
                .await;
            self.handle_fetch_interfaces().await;
            return;
        }

        let ssh_channel = match self.live_ssh_channel.as_mut() {
            Some(channel) => channel,
            None => {
                let _ = self
                    .response_sender
                    .send(SshResponse::PushResult {
                        action_description,
                        result: Err("Not connected to a router".to_string()),
                    })
                    .await;
                return;
            }
        };

        // Drain any lingering output before entering configuration mode
        while let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_millis(25), ssh_channel.wait()).await
        {}

        let mut command_log_lines: Vec<String> = Vec::new();
        let mut commit_failure_details = String::new();
        let mut encountered_cli_error = false;

        for command_line in &commands {
            let trimmed_command = command_line.trim();
            if trimmed_command.is_empty() {
                continue;
            }

            let command_with_newline = format!("{}\n", trimmed_command);
            if let Err(send_error) = ssh_channel.data(command_with_newline.as_bytes()).await {
                let _ = self
                    .response_sender
                    .send(SshResponse::PushResult {
                        action_description,
                        result: Err(format!(
                            "Failed while sending '{}': {}",
                            trimmed_command, send_error
                        )),
                    })
                    .await;
                return;
            }

            // Allow up to 15 seconds for `commit` on Cisco IOS-XR (e.g. NCS 540 / ASR9K)
            // so `end` is never sent while `commit` is still validating/applying.
            let max_wait_ms = if trimmed_command == "commit" {
                15_000
            } else {
                4_000
            };

            let command_response =
                read_channel_until_prompt_or_quiet(ssh_channel, max_wait_ms).await;

            command_log_lines.push(format!("> {}", trimmed_command));
            let cleaned_response = clean_cisco_output(&command_response, trimmed_command);
            if !cleaned_response.is_empty() {
                for response_line in cleaned_response.lines() {
                    let trimmed_line = response_line.trim();
                    if !trimmed_line.is_empty() {
                        command_log_lines.push(format!("  {}", trimmed_line));
                    }
                }
            }

            let has_commit_failure = command_response.contains("Failed to commit")
                || command_response.contains("show configuration failed");
            let has_cli_error = has_commit_failure
                || command_response.contains("% Invalid")
                || command_response.contains("% Error")
                || command_response.contains("% Bad mask")
                || command_response.contains("% Ambiguous")
                || command_response.contains("% Incomplete")
                || command_response.contains("Failed");

            if has_commit_failure {
                encountered_cli_error = true;

                // Query `show configuration failed` immediately while still in `(config)` / `(config-if)` mode
                // BEFORE exiting or aborting so the uncommitted failed target buffer is still present.
                let _ = ssh_channel.data(&b"show configuration failed\n"[..]).await;
                let failed_raw = read_channel_until_prompt_or_quiet(ssh_channel, 5_000).await;
                let cleaned_failed = clean_cisco_output(&failed_raw, "show configuration failed");
                if !cleaned_failed.is_empty() {
                    commit_failure_details = cleaned_failed;
                }

                // Now cleanly abort the uncommitted IOS-XR configuration session (only if still in config mode)
                if failed_raw.contains("(config") || command_response.contains("(config") {
                    let _ = ssh_channel.data(&b"abort\n"[..]).await;
                    let _ = read_channel_until_prompt_or_quiet(ssh_channel, 3_000).await;
                }
                break;
            }

            if command_response.contains("commit them before exiting") {
                encountered_cli_error = true;
                let _ = ssh_channel.data(&b"no\n"[..]).await;
                let _ = read_channel_until_prompt_or_quiet(ssh_channel, 2_000).await;
                break;
            }

            if has_cli_error {
                encountered_cli_error = true;
                if command_response.contains("(config") {
                    let is_ios_xr = self
                        .active_connection_config
                        .as_ref()
                        .map_or(true, |config| config.operating_system == CiscoOs::IosXr);
                    let exit_command = if is_ios_xr { "abort\n" } else { "end\n" };
                    let _ = ssh_channel.data(exit_command.as_bytes()).await;
                    let _ = read_channel_until_prompt_or_quiet(ssh_channel, 2_500).await;
                }
                break;
            }
        }

        let formatted_transcript = if encountered_cli_error {
            let mut report_sections = Vec::new();
            if !commit_failure_details.is_empty() {
                report_sections.push(
                    "!! ROUTER COMMIT REJECTED (show configuration failed) !!".to_string(),
                );
                report_sections
                    .push("--------------------------------------------------------".to_string());
                report_sections.push(commit_failure_details);
                report_sections.push(String::new());
            }
            report_sections.push("Pushed Commands & Session Log:".to_string());
            report_sections.push("------------------------------".to_string());
            report_sections.push(command_log_lines.join("\n"));
            report_sections.push(String::new());
            report_sections.push(
                "! Note: Uncommitted changes were automatically rolled back (aborted).".to_string(),
            );
            report_sections.join("\n")
        } else {
            command_log_lines.join("\n")
        };

        if encountered_cli_error {
            let _ = self
                .response_sender
                .send(SshResponse::PushResult {
                    action_description,
                    result: Err(formatted_transcript),
                })
                .await;
        } else {
            let _ = self
                .response_sender
                .send(SshResponse::PushResult {
                    action_description,
                    result: Ok(formatted_transcript),
                })
                .await;
            self.handle_fetch_interfaces().await;
        }
    }

    /// Executes an arbitrary read/show command entered in the custom CLI runner modal.
    async fn handle_run_command(&mut self, command: String) {
        if let Some(simulated_router) = &self.mock_router {
            let simulated_output = simulated_router.run_command(&command);
            let _ = self
                .response_sender
                .send(SshResponse::CommandResult {
                    command,
                    result: Ok(simulated_output),
                })
                .await;
            return;
        }

        let ssh_channel = match self.live_ssh_channel.as_mut() {
            Some(channel) => channel,
            None => {
                let _ = self
                    .response_sender
                    .send(SshResponse::CommandResult {
                        command,
                        result: Err("Not connected to a router".to_string()),
                    })
                    .await;
                return;
            }
        };

        let command_with_newline = format!("{}\n", command.trim());
        if let Err(send_error) = ssh_channel.data(command_with_newline.as_bytes()).await {
            let _ = self
                .response_sender
                .send(SshResponse::CommandResult {
                    command,
                    result: Err(format!("Failed to send command: {}", send_error)),
                })
                .await;
            return;
        }

        let raw_output = read_channel_until_prompt_or_quiet(ssh_channel, 3000).await;
        let cleaned_output = clean_cisco_output(&raw_output, &command);

        let _ = self
            .response_sender
            .send(SshResponse::CommandResult {
                command,
                result: Ok(cleaned_output),
            })
            .await;
    }
}

/// Reads bytes from the SSH channel until a Cisco router prompt (`#`, `>`, or `[cancel]:`)
/// appears on the active (unterminated) last line of output, or `max_wait_ms` elapses.
/// All returned text is sanitized through `sanitize_pty_output` so no embedded `\r` or
/// control characters can corrupt the TUI display.
async fn read_channel_until_prompt_or_quiet(
    ssh_channel: &mut Channel<client::Msg>,
    max_wait_ms: u64,
) -> String {
    let mut raw_collected_output = String::new();
    let deadline = std::time::Instant::now() + Duration::from_millis(max_wait_ms);

    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            break;
        }
        let remaining_ms = (deadline - now).as_millis() as u64;
        let wait_duration = Duration::from_millis(remaining_ms.max(20));

        let wait_result = tokio::time::timeout(wait_duration, ssh_channel.wait()).await;

        match wait_result {
            Ok(Some(ChannelMsg::Data { ref data })) => {
                raw_collected_output.push_str(&String::from_utf8_lossy(data));

                let has_completed_command_line = raw_collected_output.contains('\n')
                    || raw_collected_output.contains("[cancel]:")
                    || raw_collected_output.contains("(yes/no");

                if has_completed_command_line && ends_with_cisco_prompt(&raw_collected_output) {
                    // Drain any trailing bytes arriving in the same network burst
                    while let Ok(Some(ChannelMsg::Data {
                        data: ref trailing_data,
                    })) =
                        tokio::time::timeout(Duration::from_millis(25), ssh_channel.wait()).await
                    {
                        raw_collected_output.push_str(&String::from_utf8_lossy(trailing_data));
                        if !ends_with_cisco_prompt(&raw_collected_output) {
                            break;
                        }
                    }
                    if ends_with_cisco_prompt(&raw_collected_output) {
                        break;
                    }
                }
            }
            _ => break,
        }
    }

    sanitize_pty_output(&raw_collected_output)
}

/// Checks whether the active (unterminated) last line of `output_text` is a Cisco CLI prompt
/// waiting for user input (such as `Router#`, `RP/0/RP0/CPU0:router-lab-01(config-if)#`, or `[cancel]:`).
fn ends_with_cisco_prompt(output_text: &str) -> bool {
    let active_line_after_last_newline = output_text.rsplit('\n').next().unwrap_or("");
    let active_segment = active_line_after_last_newline
        .rsplit('\r')
        .find(|segment| !segment.trim().is_empty())
        .unwrap_or("");
    let trimmed_prompt = active_segment.trim();

    if trimmed_prompt.is_empty() {
        return false;
    }

    if trimmed_prompt.ends_with("[cancel]:")
        || trimmed_prompt.ends_with("(yes/no/cancel)?")
        || trimmed_prompt.ends_with("[confirm]")
        || trimmed_prompt.ends_with("(yes/no)?")
        || trimmed_prompt.ends_with("[yes/no]:")
    {
        return true;
    }

    // Standard exec or config prompt (e.g. "Router#", "RP/0/RP0/CPU0:router-lab-01(config-if)#")
    // Must be at least 2 characters (never a bare '#' horizontal scroll marker) and contain no spaces.
    trimmed_prompt.len() >= 2
        && !trimmed_prompt.contains(' ')
        && (trimmed_prompt.ends_with('#') || trimmed_prompt.ends_with('>'))
}

struct MockCiscoRouter {
    operating_system: CiscoOs,
    interfaces: Vec<InterfaceEntry>,
    running_configs: HashMap<String, String>,
}

impl MockCiscoRouter {
    fn new(operating_system: CiscoOs) -> Self {
        let initial_interfaces = vec![
            InterfaceEntry {
                name: "GigabitEthernet0/0/0/0".to_string(),
                status: "up".to_string(),
                protocol: "up".to_string(),
                description: "UPLINK-TO-CORE-PE01".to_string(),
            },
            InterfaceEntry {
                name: "GigabitEthernet0/0/0/1".to_string(),
                status: "admin down".to_string(),
                protocol: "down".to_string(),
                description: "CUST-A-BACKUP-1G".to_string(),
            },
            InterfaceEntry {
                name: "GigabitEthernet0/0/0/2".to_string(),
                status: "up".to_string(),
                protocol: "up".to_string(),
                description: "OOB-MANAGEMENT-SWITCH".to_string(),
            },
            InterfaceEntry {
                name: "GigabitEthernet0/0/0/6".to_string(),
                status: "admin down".to_string(),
                protocol: "down".to_string(),
                description: "SPARE-PE-CUSTOMER-ACCESS-PORT".to_string(),
            },
            InterfaceEntry {
                name: "TenGigE0/0/0/0".to_string(),
                status: "up".to_string(),
                protocol: "up".to_string(),
                description: "TRANSIT: PRIMARY 10G IP TRANSIT".to_string(),
            },
            InterfaceEntry {
                name: "TenGigE0/0/0/1".to_string(),
                status: "up".to_string(),
                protocol: "up".to_string(),
                description: "TRANSIT: SECONDARY 10G IP TRANSIT".to_string(),
            },
            InterfaceEntry {
                name: "TenGigE0/0/0/2".to_string(),
                status: "down".to_string(),
                protocol: "down".to_string(),
                description: "SPARE DARK FIBER TO DC2".to_string(),
            },
            InterfaceEntry {
                name: "TenGigE0/0/0/3".to_string(),
                status: "up".to_string(),
                protocol: "up".to_string(),
                description: "TRUNK-TO-AGGREGATION-01".to_string(),
            },
            InterfaceEntry {
                name: "TenGigE0/0/0/3.100".to_string(),
                status: "up".to_string(),
                protocol: "up".to_string(),
                description: "L2TRANSPORT: VLAN 100 - ALPHA CLOUD".to_string(),
            },
            InterfaceEntry {
                name: "TenGigE0/0/0/3.200".to_string(),
                status: "up".to_string(),
                protocol: "up".to_string(),
                description: "L2TRANSPORT: VLAN 200 - BETA CORP".to_string(),
            },
            InterfaceEntry {
                name: "Te0/1/0/1.10002000".to_string(),
                status: "up".to_string(),
                protocol: "up".to_string(),
                description: "Customer Metro ELAN".to_string(),
            },
            InterfaceEntry {
                name: "Bundle-Ether1".to_string(),
                status: "up".to_string(),
                protocol: "up".to_string(),
                description: "LAG: DC-FABRIC-SPINE-1".to_string(),
            },
            InterfaceEntry {
                name: "Bundle-Ether2".to_string(),
                status: "admin down".to_string(),
                protocol: "down".to_string(),
                description: "LAG: DC-FABRIC-SPINE-2 (STANDBY)".to_string(),
            },
            InterfaceEntry {
                name: "Loopback0".to_string(),
                status: "up".to_string(),
                protocol: "up".to_string(),
                description: "ROUTER-ID BGP/OSPF".to_string(),
            },
        ];

        let mut running_configs = HashMap::new();
        running_configs.insert(
            "GigabitEthernet0/0/0/0".to_string(),
            r#"interface GigabitEthernet0/0/0/0
 description UPLINK-TO-CORE-PE01
 ipv4 address 10.100.1.2 255.255.255.252
 load-interval 30
 carrier-delay up 100 down 0
!"#
            .to_string(),
        );

        running_configs.insert(
            "GigabitEthernet0/0/0/1".to_string(),
            r#"interface GigabitEthernet0/0/0/1
 description CUST-A-BACKUP-1G
 shutdown
 ipv4 address 192.168.10.1 255.255.255.0
!"#
            .to_string(),
        );

        running_configs.insert(
            "GigabitEthernet0/0/0/6".to_string(),
            r#"interface GigabitEthernet0/0/0/6
 description SPARE-PE-CUSTOMER-ACCESS-PORT
 shutdown
!"#
            .to_string(),
        );

        running_configs.insert(
            "TenGigE0/0/0/3.100".to_string(),
            r#"interface TenGigE0/0/0/3.100 l2transport
 description L2TRANSPORT: VLAN 100 - ALPHA CLOUD
 encapsulation dot1q 100
 rewrite ingress tag pop 1 symmetric
 mtu 9216
!"#
            .to_string(),
        );

        running_configs.insert(
            "Te0/1/0/1.10002000".to_string(),
            r#"interface TenGigE0/1/0/1.10002000 l2transport
 description Customer Metro ELAN
 encapsulation dot1q 1000 second-dot1q 2000
 rewrite ingress tag pop 2 symmetric
!"#
            .to_string(),
        );

        Self {
            operating_system,
            interfaces: initial_interfaces,
            running_configs,
        }
    }

    fn get_interfaces(&self) -> Vec<InterfaceEntry> {
        self.interfaces.clone()
    }

    fn get_l2vpn_services(&self) -> Vec<L2vpnServiceEntry> {
        let sample_l2vpn = r#"l2vpn
 load-balancing flow src-dst-ip
 xconnect group METRO_CIRCUITS
  p2p ALPHA_CLOUD_PW
   interface TenGigE0/0/0/3.100
   neighbor ipv4 192.0.2.100 pw-id 100
   !
  !
  p2p BETA_CORP_PW
   interface TenGigE0/0/0/3.200
   neighbor ipv4 192.0.2.200 pw-id 200
   !
  !
 !
 bridge group ENTERPRISE_ELAN
  bridge-domain METRO_ELAN_BD
   mtu 9100
   interface TenGigE0/1/0/1.10002000
   !
   vfi METRO_ELAN_BD
    neighbor 192.0.2.10 pw-id 2000
    !
   !
  !
  bridge-domain CORP_MGMT_BD
   interface Bundle-Ether1.10
    split-horizon group
   !
   routed interface BVI10
   !
  !
 !
!"#;
        parse_running_config_l2vpn(sample_l2vpn)
    }

    fn get_config(&self, interface_name: &str) -> String {
        if let Some(existing_config) = self.running_configs.get(interface_name) {
            return existing_config.clone();
        }

        // Synthesize a realistic running-config stanza if none was pre-populated
        let matching_entry = self
            .interfaces
            .iter()
            .find(|entry| entry.name == interface_name);
        let description_text = matching_entry
            .map(|entry| entry.description.as_str())
            .unwrap_or("");
        let is_administratively_down = matching_entry
            .map(|entry| entry.status == "admin down")
            .unwrap_or(false);
        let is_subinterface = interface_name.contains('.');

        let mut config_lines = Vec::new();
        if is_subinterface && self.operating_system == CiscoOs::IosXr {
            config_lines.push(format!("interface {} l2transport", interface_name));
        } else {
            config_lines.push(format!("interface {}", interface_name));
        }

        if !description_text.is_empty() {
            config_lines.push(format!(" description {}", description_text));
        }
        if is_subinterface {
            let vlan_id = interface_name.rsplit('.').next().unwrap_or("100");
            config_lines.push(format!(" encapsulation dot1q {}", vlan_id));
            if self.operating_system == CiscoOs::IosXr {
                config_lines.push(" rewrite ingress tag pop 1 symmetric".to_string());
            }
        }
        if is_administratively_down {
            config_lines.push(" shutdown".to_string());
        }
        config_lines.push("!".to_string());

        config_lines.join("\n")
    }

    fn execute_config(&mut self, commands: &[String]) -> String {
        let mut target_interface_name: Option<String> = None;
        let mut is_l2transport_mode = false;

        for command_line in commands {
            let trimmed_command = command_line.trim();
            if let Some(deleted_interface) = trimmed_command.strip_prefix("no interface ") {
                let target_to_delete = deleted_interface.split_whitespace().next().unwrap_or("");
                if !target_to_delete.is_empty() {
                    self.interfaces
                        .retain(|entry| entry.name != target_to_delete);
                    self.running_configs.remove(target_to_delete);
                }
            } else if let Some(after_interface_keyword) =
                trimmed_command.strip_prefix("interface ")
            {
                let words: Vec<&str> = after_interface_keyword.split_whitespace().collect();
                if let Some(first_word) = words.first() {
                    target_interface_name = Some((*first_word).to_string());
                    is_l2transport_mode = after_interface_keyword.contains("l2transport");
                }
            } else if let Some(ref current_interface) = target_interface_name {
                if trimmed_command == "shutdown" {
                    if let Some(entry) = self
                        .interfaces
                        .iter_mut()
                        .find(|entry| &entry.name == current_interface)
                    {
                        entry.status = "admin down".to_string();
                        entry.protocol = "down".to_string();
                    }
                } else if trimmed_command == "no shutdown" {
                    if let Some(entry) = self
                        .interfaces
                        .iter_mut()
                        .find(|entry| &entry.name == current_interface)
                    {
                        entry.status = "up".to_string();
                        entry.protocol = "up".to_string();
                    }
                } else if let Some(new_description) = trimmed_command.strip_prefix("description ") {
                    if let Some(entry) = self
                        .interfaces
                        .iter_mut()
                        .find(|entry| &entry.name == current_interface)
                    {
                        entry.description = new_description.trim().to_string();
                    }
                } else if trimmed_command == "no description" {
                    if let Some(entry) = self
                        .interfaces
                        .iter_mut()
                        .find(|entry| &entry.name == current_interface)
                    {
                        entry.description = String::new();
                    }
                }
            }
        }

        // If the configured interface is a newly created subinterface, add it to the interface list
        if let Some(interface_name) = target_interface_name {
            let already_exists = self
                .interfaces
                .iter()
                .any(|entry| entry.name == interface_name);

            if !already_exists {
                let configured_description = commands
                    .iter()
                    .find_map(|line| line.trim().strip_prefix("description "))
                    .map(|description_text| description_text.trim().to_string())
                    .unwrap_or_default();

                let is_shutdown = commands.iter().any(|line| line.trim() == "shutdown");

                self.interfaces.push(InterfaceEntry {
                    name: interface_name.clone(),
                    status: if is_shutdown {
                        "admin down".to_string()
                    } else {
                        "up".to_string()
                    },
                    protocol: if is_shutdown {
                        "down".to_string()
                    } else {
                        "up".to_string()
                    },
                    description: configured_description,
                });
            }

            // Record the updated stanza in the mock router's running configuration table
            let mut stanza_lines = Vec::new();
            if is_l2transport_mode {
                stanza_lines.push(format!("interface {} l2transport", interface_name));
            } else {
                stanza_lines.push(format!("interface {}", interface_name));
            }

            for command_line in commands {
                let trimmed_line = command_line.trim();
                if trimmed_line.starts_with("description ")
                    || trimmed_line.starts_with("encapsulation ")
                    || trimmed_line.starts_with("rewrite ")
                    || trimmed_line.starts_with("mtu ")
                    || trimmed_line.starts_with("ipv4 address ")
                    || trimmed_line.starts_with("ip address ")
                    || trimmed_line == "shutdown"
                    || trimmed_line == "no shutdown"
                {
                    stanza_lines.push(format!(" {}", trimmed_line));
                }
            }
            stanza_lines.push("!".to_string());
            self.running_configs
                .insert(interface_name, stanza_lines.join("\n"));
        }

        if self.operating_system == CiscoOs::IosXr {
            "RP/0/RSP0/CPU0:Router(config)# commit\nCommit complete.\nRP/0/RSP0/CPU0:Router(config)# end\nRP/0/RSP0/CPU0:Router#"
                .to_string()
        } else {
            "Router(config)# end\nRouter#".to_string()
        }
    }

    fn run_command(&self, command_text: &str) -> String {
        let lowercase_command = command_text.trim().to_lowercase();
        if lowercase_command.contains("show ip int brief")
            || lowercase_command.contains("show ipv4 int brief")
        {
            r#"Interface                      IP-Address      Status          Protocol Vrf-Name
GigabitEthernet0/0/0/0         10.100.1.2      Up              Up       default
GigabitEthernet0/0/0/1         192.168.10.1    Shutdown        Down     default
GigabitEthernet0/0/0/2         10.254.0.1      Up              Up       mgmt
GigabitEthernet0/0/0/6         unassigned      Shutdown        Down     default
TenGigE0/0/0/0                 198.51.100.2    Up              Up       default
TenGigE0/0/0/1                 203.0.113.2     Up              Up       default
Loopback0                      192.0.2.1       Up              Up       default"#
                .to_string()
        } else if lowercase_command.contains("show version") {
            r#"Cisco IOS XR Software, Version 7.9.2
Copyright (c) 2013-2024 by Cisco Systems, Inc.

ROM: System Bootstrap, Version 16.12(1r)
cisco ASR9001 (PowerPC) processor with 16777216K bytes of memory.
12 GigabitEthernet
4 TenGigE
Uptime is 42 weeks, 3 days, 14 hours, 22 minutes"#
                .to_string()
        } else if lowercase_command.contains("show l2vpn")
            || lowercase_command.contains("xconnect")
        {
            r#"Legend: ST = State, UP = Up, DN = Down, AD = Admin Down, UR = Unresolved
XC Name         Type  ST  Interface           Peer / VC ID
--------------- ----- --- ------------------- -----------------------
ALPHA_PW        p2p   UP  Te0/0/0/3.100       192.0.2.100 / 10001 (UP)
BETA_PW         p2p   UP  Te0/0/0/3.200       192.0.2.200 / 20002 (UP)"#
                .to_string()
        } else {
            format!(
                "Command executed successfully on router:\n{}\n[Output OK]",
                command_text
            )
        }
    }
}
