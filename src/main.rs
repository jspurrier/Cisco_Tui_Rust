mod app;
mod cisco;
mod model;
mod ssh;
mod ui;

use app::{App, CurrentView};
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use model::{CiscoOs, ConnectionConfig, L2vpnServiceType, SshRequest, SshResponse};
use ratatui::{backend::CrosstermBackend, Terminal};
use ssh::SshWorker;
use std::env;
use std::io;
use std::time::Duration;
use tokio::sync::mpsc;

/// If the binary is double-clicked from a desktop file manager on Linux or macOS (where `stdin` is not a TTY),
/// re-launches the executable inside a desktop terminal window so the TUI opens automatically.
/// On Windows, console `.exe` binaries open a console window natively when double-clicked.
fn ensure_running_in_terminal_if_needed() {
    #[cfg(unix)]
    {
        use std::io::IsTerminal;
        use std::process::Command;

        if io::stdin().is_terminal() && io::stdout().is_terminal() {
            return;
        }
        if env::var("CISCO_TUI_IN_TERMINAL").is_ok() {
            return;
        }

        let Ok(current_executable) = env::current_exe() else {
            return;
        };
        let forwarded_arguments: Vec<String> = env::args().skip(1).collect();

        #[cfg(target_os = "macos")]
        {
            let mut open_command = Command::new("open");
            open_command
                .env("CISCO_TUI_IN_TERMINAL", "1")
                .arg("-a")
                .arg("Terminal")
                .arg(&current_executable);
            if !forwarded_arguments.is_empty() {
                open_command.arg("--args").args(&forwarded_arguments);
            }
            if open_command.spawn().is_ok() {
                std::process::exit(0);
            }
        }

        #[cfg(target_os = "linux")]
        {
            if env::var("DISPLAY").is_err() && env::var("WAYLAND_DISPLAY").is_err() {
                return;
            }

            let terminal_candidates: &[(&str, &[&str])] = &[
                ("ptyxis", &["--"]),
                ("kgx", &["--"]),
                ("gnome-terminal", &["--"]),
                ("xfce4-terminal", &["-x"]),
                ("konsole", &["-e"]),
                ("mate-terminal", &["-x"]),
                ("tilix", &["-e"]),
                ("kitty", &["--"]),
                ("alacritty", &["-e"]),
                ("wezterm", &["start", "--"]),
                ("x-terminal-emulator", &["-e"]),
                ("xterm", &["-e"]),
            ];

            for (terminal_binary, separator_flags) in terminal_candidates {
                let mut command = Command::new(terminal_binary);
                command.env("CISCO_TUI_IN_TERMINAL", "1");
                for flag in *separator_flags {
                    command.arg(flag);
                }
                command.arg(&current_executable);
                command.args(&forwarded_arguments);

                if command.spawn().is_ok() {
                    std::process::exit(0);
                }
            }
        }
    }
}

/// Prints command-line usage instructions when `--help` or `-h` is passed.
fn print_command_line_usage() {
    println!(
        r#"Cisco TUI - Terminal User Interface for Cisco Routers

USAGE:
    cisco-tui [OPTIONS]

OPTIONS:
    --host <HOST>       Router hostname or IP address
    --port <PORT>       SSH port (default: 22)
    --user <USERNAME>   SSH username
    --pass <PASSWORD>   SSH password
    --os <ios|ios-xr>   Initial Cisco OS mode: 'ios' (IOS/IOS-XE) or 'ios-xr' (default: ios-xr)
    --demo, --mock      Start in offline simulated router mode
    -h, --help          Print this help message

KEYBOARD SHORTCUTS:
    Enter, e            Open Unified Port Configuration Editor
    n                   Create a new Subinterface / L2Transport on selected port
    b                   Bind / Edit L2VPN (Bridge-Domain or Xconnect) for selected port
    w                   Switch between Interfaces Table and L2VPN Table View
    x, Delete           Delete selected .vlan subinterface (auto-cleans L2VPN binding)
    v                   View running-config of selected interface
    u                   Quick Enable port ('no shutdown')
    d                   Quick Admin Disable port ('shutdown')
    o                   Toggle CLI syntax mode (Cisco IOS/IOS-XE vs Cisco IOS-XR)
    /                   Filter interfaces or L2VPNs by name, description, or status
    s                   Cycle sort column (Name, Status, Protocol, Description)
    r                   Refresh interface and L2VPN tables from router
    c                   Open Connection login modal
    :                   Execute custom Cisco CLI command
    L                   Open session Audit & Action Logs
    ?                   Open Help reference modal
    q, Esc              Disconnect and return to Login screen (or quit from Login)
"#
    );
}

/// Parses optional command-line flags. If no host/user are provided on the command line,
/// the application opens the interactive Connection Modal on startup.
fn parse_command_line_arguments() -> (Option<ConnectionConfig>, bool) {
    let command_line_args: Vec<String> = env::args().collect();
    let mut target_host: Option<String> = None;
    let mut ssh_port: u16 = 22;
    let mut ssh_username: Option<String> = None;
    let mut ssh_password: Option<String> = None;
    let mut operating_system = CiscoOs::IosXr;
    let mut use_mock_router = false;

    let mut arg_index = 1;
    while arg_index < command_line_args.len() {
        match command_line_args[arg_index].as_str() {
            "-h" | "--help" => {
                print_command_line_usage();
                std::process::exit(0);
            }
            "--demo" | "--mock" => {
                use_mock_router = true;
            }
            "--host" => {
                if arg_index + 1 < command_line_args.len() {
                    target_host = Some(command_line_args[arg_index + 1].clone());
                    arg_index += 1;
                }
            }
            "--port" => {
                if arg_index + 1 < command_line_args.len() {
                    ssh_port = command_line_args[arg_index + 1].parse().unwrap_or(22);
                    arg_index += 1;
                }
            }
            "--user" => {
                if arg_index + 1 < command_line_args.len() {
                    ssh_username = Some(command_line_args[arg_index + 1].clone());
                    arg_index += 1;
                }
            }
            "--pass" => {
                if arg_index + 1 < command_line_args.len() {
                    ssh_password = Some(command_line_args[arg_index + 1].clone());
                    arg_index += 1;
                }
            }
            "--os" => {
                if arg_index + 1 < command_line_args.len() {
                    let os_argument = command_line_args[arg_index + 1].to_lowercase();
                    if os_argument == "ios" || os_argument == "ios-xe" || os_argument == "xe" {
                        operating_system = CiscoOs::Ios;
                    } else {
                        operating_system = CiscoOs::IosXr;
                    }
                    arg_index += 1;
                }
            }
            _ => {}
        }
        arg_index += 1;
    }

    if use_mock_router {
        let config = ConnectionConfig {
            host: target_host.unwrap_or_else(|| "cisco-asr9k-core01".to_string()),
            port: ssh_port,
            username: ssh_username.unwrap_or_else(|| "admin".to_string()),
            password: ssh_password.unwrap_or_default(),
            operating_system,
            use_mock_router: true,
        };
        (Some(config), true)
    } else if let (Some(host), Some(username)) = (target_host, ssh_username) {
        let config = ConnectionConfig {
            host,
            port: ssh_port,
            username,
            password: ssh_password.unwrap_or_default(),
            operating_system,
            use_mock_router: false,
        };
        (Some(config), true)
    } else {
        (None, false)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (initial_connection_config, should_auto_connect) = parse_command_line_arguments();
    ensure_running_in_terminal_if_needed();

    // Asynchronous channels linking the TUI thread and the background SSH worker
    let (ssh_request_sender, ssh_request_receiver) = mpsc::channel::<SshRequest>(32);
    let (ssh_response_sender, mut ssh_response_receiver) = mpsc::channel::<SshResponse>(32);

    // Spawn the background SSH client worker
    let ssh_worker = SshWorker::new(ssh_request_receiver, ssh_response_sender);
    tokio::spawn(async move {
        ssh_worker.run().await;
    });

    let mut app = App::new(
        ssh_request_sender.clone(),
        initial_connection_config.clone(),
    );

    if should_auto_connect {
        if let Some(config) = initial_connection_config {
            app.is_loading = true;
            app.status_message = format!("Connecting to {}...", config.host);
            let sender = ssh_request_sender.clone();
            tokio::spawn(async move {
                let _ = sender.send(SshRequest::Connect(config)).await;
            });
        }
    } else {
        // Prompt for Device IP/Hostname, Username, and Password on startup
        app.current_view = CurrentView::ConnectionModal;
    }

    // Initialize terminal raw mode and alternate screen buffer
    enable_raw_mode()?;
    let mut stdout_handle = io::stdout();
    execute!(stdout_handle, EnterAlternateScreen)?;
    let terminal_backend = CrosstermBackend::new(stdout_handle);
    let mut terminal = Terminal::new(terminal_backend)?;

    // Main render and input event loop
    loop {
        while let Ok(worker_response) = ssh_response_receiver.try_recv() {
            app.handle_ssh_response(worker_response);
        }

        terminal.draw(|frame| {
            ui::render(frame, &mut app);
        })?;

        if app.should_quit {
            break;
        }

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key_event) = event::read()? {
                handle_keyboard_input(&mut app, key_event);
            }
        }
    }

    // Restore original terminal state before exiting
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

/// Dispatches keyboard events based on the active screen or modal dialog.
fn handle_keyboard_input(app: &mut App, key_event: event::KeyEvent) {
    // Allow Ctrl+C or Ctrl+Q to cleanly exit from anywhere in the application
    if key_event.modifiers.contains(KeyModifiers::CONTROL)
        && (key_event.code == KeyCode::Char('c') || key_event.code == KeyCode::Char('q'))
    {
        app.should_quit = true;
        return;
    }

    match app.current_view {
        // -------------------------------------------------------------------
        // Main Interface Table View
        // -------------------------------------------------------------------
        CurrentView::InterfaceList => {
            if app.is_filtering {
                match key_event.code {
                    KeyCode::Esc => {
                        app.is_filtering = false;
                        app.filter_query.clear();
                    }
                    KeyCode::Enter => {
                        app.is_filtering = false;
                    }
                    KeyCode::Backspace => {
                        app.filter_query.pop();
                    }
                    KeyCode::Char(typed_char) => {
                        app.filter_query.push(typed_char);
                    }
                    _ => {}
                }
            } else {
                match key_event.code {
                    KeyCode::Char('q') => {
                        if app.is_connected {
                            app.disconnect_to_login_modal();
                        } else {
                            app.should_quit = true;
                        }
                    }
                    KeyCode::Char('c') => app.current_view = CurrentView::ConnectionModal,
                    KeyCode::Char('r') => app.refresh_interfaces(),
                    KeyCode::Char('/') => {
                        app.is_filtering = true;
                    }
                    KeyCode::Char('s') => app.cycle_sort(),
                    KeyCode::Char('o') => app.toggle_operating_system(),
                    KeyCode::Enter | KeyCode::Char('e') => app.initiate_edit_interface(),
                    KeyCode::Char('v') => app.initiate_view_config(),
                    KeyCode::Char('n') | KeyCode::Char('a') | KeyCode::Char('l') => {
                        app.initiate_add_subinterface()
                    }
                    KeyCode::Char('b') => app.initiate_edit_l2vpn_for_selected_interface(false),
                    KeyCode::Char('w') => app.current_view = CurrentView::L2vpnList,
                    KeyCode::Char('x') | KeyCode::Delete => app.initiate_delete_subinterface(),
                    KeyCode::Char('u') => app.initiate_no_shutdown(),
                    KeyCode::Char('d') => app.initiate_shutdown(),
                    KeyCode::Char(':') => app.current_view = CurrentView::CommandRunner,
                    KeyCode::Char('L') => app.current_view = CurrentView::ActionLogs,
                    KeyCode::Char('?') => app.current_view = CurrentView::Help,
                    KeyCode::Down | KeyCode::Char('j') => app.next_row(),
                    KeyCode::Up | KeyCode::Char('k') => app.previous_row(),
                    KeyCode::PageDown => app.page_down(10),
                    KeyCode::PageUp => app.page_up(10),
                    KeyCode::Home => {
                        if !app.interfaces.is_empty() {
                            app.table_state.select(Some(0));
                            app.selected_interface_name =
                                app.selected_interface().map(|entry| entry.name.clone());
                        }
                    }
                    KeyCode::End => {
                        let visible_count = app.filtered_interfaces().len();
                        if visible_count > 0 {
                            app.table_state.select(Some(visible_count - 1));
                            app.selected_interface_name =
                                app.selected_interface().map(|entry| entry.name.clone());
                        }
                    }
                    KeyCode::Esc => {
                        if !app.filter_query.is_empty() {
                            app.filter_query.clear();
                        } else if app.is_connected {
                            app.disconnect_to_login_modal();
                        } else {
                            app.should_quit = true;
                        }
                    }
                    _ => {}
                }
            }
        }

        // -------------------------------------------------------------------
        // Dedicated L2VPN (Xconnect & Bridge-Domain) Table View (`w`)
        // -------------------------------------------------------------------
        CurrentView::L2vpnList => {
            if app.l2vpn_is_filtering {
                match key_event.code {
                    KeyCode::Esc => {
                        app.l2vpn_is_filtering = false;
                        app.l2vpn_filter_query.clear();
                    }
                    KeyCode::Enter => {
                        app.l2vpn_is_filtering = false;
                    }
                    KeyCode::Backspace => {
                        app.l2vpn_filter_query.pop();
                    }
                    KeyCode::Char(typed_char) => {
                        app.l2vpn_filter_query.push(typed_char);
                    }
                    _ => {}
                }
            } else {
                match key_event.code {
                    KeyCode::Char('q') => {
                        if app.is_connected {
                            app.disconnect_to_login_modal();
                        } else {
                            app.should_quit = true;
                        }
                    }
                    KeyCode::Char('w') => app.current_view = CurrentView::InterfaceList,
                    KeyCode::Esc => {
                        if !app.l2vpn_filter_query.is_empty() {
                            app.l2vpn_filter_query.clear();
                        } else {
                            app.current_view = CurrentView::InterfaceList;
                        }
                    }
                    KeyCode::Char('/') => {
                        app.l2vpn_is_filtering = true;
                    }
                    KeyCode::Enter | KeyCode::Char('e') | KeyCode::Char('b') => {
                        app.initiate_edit_selected_l2vpn_service()
                    }
                    KeyCode::Char('n') | KeyCode::Char('a') => app.initiate_add_l2vpn_service(),
                    KeyCode::Char('x') | KeyCode::Delete => {
                        app.initiate_delete_selected_l2vpn_service()
                    }
                    KeyCode::Char('r') => app.refresh_l2vpn(),
                    KeyCode::Char(':') => app.current_view = CurrentView::CommandRunner,
                    KeyCode::Char('L') => app.current_view = CurrentView::ActionLogs,
                    KeyCode::Char('?') => app.current_view = CurrentView::Help,
                    KeyCode::Down | KeyCode::Char('j') => app.l2vpn_next_row(),
                    KeyCode::Up | KeyCode::Char('k') => app.l2vpn_previous_row(),
                    KeyCode::PageDown => app.l2vpn_page_down(10),
                    KeyCode::PageUp => app.l2vpn_page_up(10),
                    KeyCode::Home => {
                        if !app.filtered_l2vpn_services().is_empty() {
                            app.l2vpn_table_state.select(Some(0));
                        }
                    }
                    KeyCode::End => {
                        let visible_count = app.filtered_l2vpn_services().len();
                        if visible_count > 0 {
                            app.l2vpn_table_state.select(Some(visible_count - 1));
                        }
                    }
                    _ => {}
                }
            }
        }

        // -------------------------------------------------------------------
        // Read-Only Running Configuration Viewer Modal
        // -------------------------------------------------------------------
        CurrentView::ViewConfig => match key_event.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                app.current_view = app.previous_view;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.config_scroll = app.config_scroll.saturating_add(1);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.config_scroll = app.config_scroll.saturating_sub(1);
            }
            KeyCode::PageDown => {
                app.config_scroll = app.config_scroll.saturating_add(15);
            }
            KeyCode::PageUp => {
                app.config_scroll = app.config_scroll.saturating_sub(15);
            }
            KeyCode::Home => {
                app.config_scroll = 0;
            }
            _ => {}
        },

        // -------------------------------------------------------------------
        // Unified Port Configuration Editor Modal
        //
        // Visual field order (11 fields, 0..=10):
        //   Row 1: [0] Interface Name        | [1] Port State (ENABLED vs ADMIN DOWN)
        //   Row 2: [2] Interface Description
        //   Row 3: [3] IPv4 Primary          | [4] IPv4 Secondary
        //   Row 4: [5] Port Mode (L2/L3)     | [6] Dot1Q VLAN | [7] 2nd VLAN (Opt) | [8] Rewrite Tag
        //   Row 5: [9] Jumbo MTU (Optional)  | [10] Negotiation Auto (negotiation auto)
        // -------------------------------------------------------------------
        CurrentView::EditInterface => {
            if key_event.modifiers.contains(KeyModifiers::CONTROL)
                && key_event.code == KeyCode::Char('o')
            {
                app.toggle_operating_system();
                return;
            }

            if key_event.modifiers.contains(KeyModifiers::CONTROL)
                && (key_event.code == KeyCode::Char('w') || key_event.code == KeyCode::Char('b'))
            {
                app.initiate_edit_l2vpn_for_selected_interface(true);
                return;
            }

            if (key_event.modifiers.contains(KeyModifiers::CONTROL)
                && key_event.code == KeyCode::Char('x'))
                || key_event.code == KeyCode::Delete
            {
                app.initiate_delete_subinterface_from_editor();
                return;
            }

            match key_event.code {
                KeyCode::Esc => {
                    app.current_view = CurrentView::InterfaceList;
                }
                // Tab or Right Arrow steps through every field in left-to-right, top-to-bottom order
                KeyCode::Tab | KeyCode::Right => {
                    app.editor_active_field = (app.editor_active_field + 1) % 11;
                }
                // Shift+Tab or Left Arrow steps backward in right-to-left, bottom-to-top order
                KeyCode::BackTab | KeyCode::Left => {
                    app.editor_active_field = if app.editor_active_field == 0 {
                        10
                    } else {
                        app.editor_active_field - 1
                    };
                }
                // Down Arrow moves vertically to the corresponding field in the row below
                KeyCode::Down => {
                    app.editor_active_field = match app.editor_active_field {
                        0 | 1 => 2,      // Row 1 (Interface / Port State) -> Row 2 (Description)
                        2 => 3,          // Row 2 (Description)            -> Row 3 (IPv4 Primary)
                        3 => 5,          // Row 3 Left (IPv4 Primary)      -> Row 4 Left (Mode)
                        4 => 7,          // Row 3 Right (IPv4 Secondary)   -> Row 4 Right (2nd VLAN)
                        5 | 6 => 9,      // Row 4 Left/Mid                 -> Row 5 Left (Jumbo MTU)
                        7 | 8 => 10,     // Row 4 Right                    -> Row 5 Mid (Negotiation Auto)
                        9 => 0,          // Row 5 Left (Jumbo MTU)         -> Wrap to Row 1 Left
                        10 => 1,         // Row 5 Mid (Negotiation Auto)   -> Wrap to Row 1 Right
                        _ => 0,
                    };
                }
                // Up Arrow moves vertically to the corresponding field in the row above
                KeyCode::Up => {
                    app.editor_active_field = match app.editor_active_field {
                        0 => 9,          // Row 1 Left                     -> Wrap to Row 5 Left (Jumbo MTU)
                        1 => 10,         // Row 1 Right                    -> Wrap to Row 5 Mid (Negotiation)
                        2 => 0,          // Row 2 (Description)            -> Row 1 (Interface Name)
                        3 | 4 => 2,      // Row 3 (IPv4 fields)            -> Row 2 (Description)
                        5 | 6 => 3,      // Row 4 Left/Mid                 -> Row 3 Left (IPv4 Primary)
                        7 | 8 => 4,      // Row 4 Right                    -> Row 3 Right (IPv4 Secondary)
                        9 => 5,          // Row 5 Left (Jumbo MTU)         -> Row 4 Left (Mode)
                        10 => 7,         // Row 5 Mid (Negotiation Auto)   -> Row 4 Right (2nd VLAN)
                        _ => 0,
                    };
                }
                KeyCode::Char(' ') => match app.editor_active_field {
                    // Cycle Port State: Omit [Inherit] -> ENABLED [no shut] -> ADMIN DOWN [shut] -> Omit
                    1 => {
                        if app.editor_form.omit_port_state {
                            app.editor_form.omit_port_state = false;
                            app.editor_form.port_enabled = true;
                        } else if app.editor_form.port_enabled {
                            app.editor_form.port_enabled = false;
                        } else {
                            app.editor_form.omit_port_state = true;
                        }
                    }
                    // Toggle Port Mode (L2Transport vs L3)
                    5 => app.editor_form.l2transport = !app.editor_form.l2transport,
                    // Cycle Rewrite Ingress Tag: pop 1 -> pop 2 -> none (0) -> pop 1
                    8 => {
                        app.editor_form.rewrite_ingress_pop =
                            match app.editor_form.rewrite_ingress_pop {
                                1 => 2,
                                2 => 0,
                                _ => 1,
                            };
                    }
                    // Toggle Auto-Negotiation (`negotiation auto` vs Off)
                    10 => app.editor_form.negotiation_auto = !app.editor_form.negotiation_auto,
                    // Text fields that accept spaces
                    2 => app.editor_form.description.push(' '),
                    3 => app.editor_form.primary_ip.push(' '),
                    4 => app.editor_form.secondary_ip.push(' '),
                    _ => {}
                },
                KeyCode::Enter => {
                    app.confirm_editor_form();
                }
                KeyCode::Backspace => match app.editor_active_field {
                    0 => {
                        app.editor_form.interface.pop();
                        sync_vlan_from_interface_name(&mut app.editor_form);
                    }
                    2 => {
                        app.editor_form.description.pop();
                    }
                    3 => {
                        app.editor_form.primary_ip.pop();
                    }
                    4 => {
                        app.editor_form.secondary_ip.pop();
                    }
                    6 => {
                        app.editor_form.vlan_id.pop();
                    }
                    7 => {
                        app.editor_form.second_vlan_id.pop();
                        if app.editor_form.second_vlan_id.is_empty()
                            && app.editor_form.rewrite_ingress_pop == 2
                        {
                            app.editor_form.rewrite_ingress_pop = 1;
                        }
                    }
                    9 => {
                        app.editor_form.mtu.pop();
                    }
                    _ => {}
                },
                KeyCode::Char(typed_char) => match app.editor_active_field {
                    0 => {
                        app.editor_form.interface.push(typed_char);
                        sync_vlan_from_interface_name(&mut app.editor_form);
                    }
                    2 => app.editor_form.description.push(typed_char),
                    3 => app.editor_form.primary_ip.push(typed_char),
                    4 => app.editor_form.secondary_ip.push(typed_char),
                    6 => {
                        if typed_char.is_ascii_digit() {
                            app.editor_form.vlan_id.push(typed_char);
                        }
                    }
                    7 => {
                        if typed_char.is_ascii_digit() {
                            app.editor_form.second_vlan_id.push(typed_char);
                            if app.editor_form.rewrite_ingress_pop == 1 {
                                app.editor_form.rewrite_ingress_pop = 2;
                            }
                        }
                    }
                    9 => {
                        if typed_char.is_ascii_digit() {
                            app.editor_form.mtu.push(typed_char);
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        // -------------------------------------------------------------------
        // L2VPN (Xconnect P2P & Bridge-Domain) Configuration Editor Modal
        //
        // Visual field order (9 fields, 0..=8):
        //   Row 1: [0] L2VPN Type (BD vs XC) | [1] Existing Group / BD Picker
        //   Row 2: [2] Group Name            | [3] Service (BD / P2P) Name
        //   Row 3: [4] Target Interface      | [5] Interface Action / Split-Horizon
        //   Row 4: [6] Pseudowire Neighbors (`<IP> <pw-id>`, comma-separated)
        //   Row 5: [7] Routed Interface BVI  | [8] Bridge-Domain MTU
        // -------------------------------------------------------------------
        CurrentView::EditL2vpn => {
            if key_event.modifiers.contains(KeyModifiers::CONTROL)
                && key_event.code == KeyCode::Char('t')
            {
                app.cycle_l2vpn_target_interface();
                return;
            }

            match key_event.code {
                KeyCode::Esc => {
                    if app.l2vpn_form.return_to_port_editor {
                        app.current_view = CurrentView::EditInterface;
                    } else if app.previous_view == CurrentView::L2vpnList {
                        app.current_view = CurrentView::L2vpnList;
                    } else {
                        app.current_view = CurrentView::InterfaceList;
                    }
                }
                KeyCode::Tab | KeyCode::Right => {
                    app.l2vpn_active_field = (app.l2vpn_active_field + 1) % 9;
                }
                KeyCode::BackTab | KeyCode::Left => {
                    app.l2vpn_active_field = if app.l2vpn_active_field == 0 {
                        8
                    } else {
                        app.l2vpn_active_field - 1
                    };
                }
                KeyCode::Down => {
                    app.l2vpn_active_field = match app.l2vpn_active_field {
                        0 => 2,
                        1 => 3,
                        2 => 4,
                        3 => 5,
                        4 | 5 => 6,
                        6 => 7,
                        7 => 0,
                        8 => 1,
                        _ => 0,
                    };
                }
                KeyCode::Up => {
                    app.l2vpn_active_field = match app.l2vpn_active_field {
                        0 => 7,
                        1 => 8,
                        2 => 0,
                        3 => 1,
                        4 => 2,
                        5 => 3,
                        6 => 4,
                        7 | 8 => 6,
                        _ => 0,
                    };
                }
                KeyCode::Char(' ') => match app.l2vpn_active_field {
                    0 => {
                        app.l2vpn_form.service_type = match app.l2vpn_form.service_type {
                            L2vpnServiceType::BridgeDomain => L2vpnServiceType::XconnectP2p,
                            L2vpnServiceType::XconnectP2p => L2vpnServiceType::BridgeDomain,
                        };
                    }
                    1 => {
                        app.cycle_l2vpn_preset(true);
                    }
                    4 => {
                        app.cycle_l2vpn_target_interface();
                    }
                    5 => {
                        app.l2vpn_form.interface_action = match app.l2vpn_form.service_type {
                            L2vpnServiceType::BridgeDomain => match app.l2vpn_form.interface_action
                            {
                                1 => 0, // +split-horizon -> Attach (No SHG)
                                0 => 2, // Attach (No SHG) -> Remove (no interface)
                                _ => 1, // Remove -> +split-horizon
                            },
                            L2vpnServiceType::XconnectP2p => {
                                if app.l2vpn_form.interface_action == 2 {
                                    0
                                } else {
                                    2
                                }
                            }
                        };
                    }
                    6 => app.l2vpn_form.neighbors_input.push(' '),
                    _ => {}
                },
                KeyCode::Backspace => match app.l2vpn_active_field {
                    1 => app.cycle_l2vpn_preset(false),
                    2 => {
                        app.l2vpn_form.group_name.pop();
                    }
                    3 => {
                        app.l2vpn_form.service_name.pop();
                    }
                    4 => {
                        app.l2vpn_form.target_interface.pop();
                    }
                    6 => {
                        app.l2vpn_form.neighbors_input.pop();
                    }
                    7 => {
                        app.l2vpn_form.routed_bvi.pop();
                    }
                    8 => {
                        app.l2vpn_form.mtu.pop();
                    }
                    _ => {}
                },
                KeyCode::Char(typed_char) => match app.l2vpn_active_field {
                    1 => app.cycle_l2vpn_preset(true),
                    2 => app.l2vpn_form.group_name.push(typed_char),
                    3 => app.l2vpn_form.service_name.push(typed_char),
                    4 => app.l2vpn_form.target_interface.push(typed_char),
                    6 => app.l2vpn_form.neighbors_input.push(typed_char),
                    7 => app.l2vpn_form.routed_bvi.push(typed_char),
                    8 => {
                        if typed_char.is_ascii_digit() {
                            app.l2vpn_form.mtu.push(typed_char);
                        }
                    }
                    _ => {}
                },
                KeyCode::Enter => {
                    app.confirm_l2vpn_form();
                }
                _ => {}
            }
        }

        // -------------------------------------------------------------------
        // Configuration Push Confirmation Modal
        // -------------------------------------------------------------------
        CurrentView::ConfirmAction => match key_event.code {
            KeyCode::Enter => {
                app.execute_confirmed_action();
            }
            KeyCode::Esc => {
                app.current_view = app.previous_view;
            }
            _ => {}
        },

        // -------------------------------------------------------------------
        // Initial SSH Connection Login Modal
        // -------------------------------------------------------------------
        CurrentView::ConnectionModal => {
            if key_event.modifiers.contains(KeyModifiers::CONTROL)
                && key_event.code == KeyCode::Char('p')
            {
                app.connection_show_password = !app.connection_show_password;
                return;
            }

            if key_event.modifiers.contains(KeyModifiers::CONTROL)
                && key_event.code == KeyCode::Char('d')
            {
                app.connection_host = "demo".to_string();
                app.initiate_connect_from_modal();
                return;
            }

            match key_event.code {
                KeyCode::Esc => {
                    if app.is_connected {
                        app.current_view = CurrentView::InterfaceList;
                    } else {
                        app.should_quit = true;
                    }
                }
                KeyCode::Tab | KeyCode::Down => {
                    app.connection_active_field = (app.connection_active_field + 1) % 4;
                }
                KeyCode::BackTab | KeyCode::Up => {
                    app.connection_active_field = if app.connection_active_field == 0 {
                        3
                    } else {
                        app.connection_active_field - 1
                    };
                }
                KeyCode::Enter => {
                    let trimmed_host = app.connection_host.trim().to_string();
                    let is_demo_host = trimmed_host.eq_ignore_ascii_case("demo");

                    if is_demo_host {
                        app.initiate_connect_from_modal();
                    } else if app.connection_active_field == 0 && !trimmed_host.is_empty() {
                        app.connection_active_field = 1;
                    } else if app.connection_active_field == 1
                        && !app.connection_username.trim().is_empty()
                    {
                        app.connection_active_field = 2;
                    } else {
                        app.initiate_connect_from_modal();
                    }
                }
                KeyCode::Backspace => match app.connection_active_field {
                    0 => {
                        app.connection_host.pop();
                    }
                    1 => {
                        app.connection_username.pop();
                    }
                    2 => {
                        app.connection_password.pop();
                    }
                    3 => {
                        app.connection_port.pop();
                    }
                    _ => {}
                },
                KeyCode::Char(typed_char) => match app.connection_active_field {
                    0 => app.connection_host.push(typed_char),
                    1 => app.connection_username.push(typed_char),
                    2 => app.connection_password.push(typed_char),
                    3 => {
                        if typed_char.is_ascii_digit() {
                            app.connection_port.push(typed_char);
                        }
                    }
                    _ => {}
                },
                _ => {}
            }
        }

        // -------------------------------------------------------------------
        // Custom CLI Command Runner Modal
        // -------------------------------------------------------------------
        CurrentView::CommandRunner => match key_event.code {
            KeyCode::Esc => {
                app.current_view = CurrentView::InterfaceList;
            }
            KeyCode::Enter => {
                app.execute_custom_command();
            }
            KeyCode::Backspace => {
                app.command_input.pop();
            }
            KeyCode::Down => {
                app.command_scroll = app.command_scroll.saturating_add(1);
            }
            KeyCode::Up => {
                app.command_scroll = app.command_scroll.saturating_sub(1);
            }
            KeyCode::PageDown => {
                app.command_scroll = app.command_scroll.saturating_add(10);
            }
            KeyCode::PageUp => {
                app.command_scroll = app.command_scroll.saturating_sub(10);
            }
            KeyCode::Char(typed_char) => {
                app.command_input.push(typed_char);
            }
            _ => {}
        },

        // -------------------------------------------------------------------
        // Session Audit & Action Logs Modal
        // -------------------------------------------------------------------
        CurrentView::ActionLogs => match key_event.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('L') => {
                app.current_view = CurrentView::InterfaceList;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.logs_scroll = app.logs_scroll.saturating_add(1);
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.logs_scroll = app.logs_scroll.saturating_sub(1);
            }
            KeyCode::PageDown => {
                app.logs_scroll = app.logs_scroll.saturating_add(10);
            }
            KeyCode::PageUp => {
                app.logs_scroll = app.logs_scroll.saturating_sub(10);
            }
            _ => {}
        },

        // -------------------------------------------------------------------
        // Help Reference Modal
        // -------------------------------------------------------------------
        CurrentView::Help => match key_event.code {
            KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q') => {
                app.current_view = CurrentView::InterfaceList;
            }
            _ => {}
        },
    }
}

/// When the user edits the `Interface Name` field and adds or modifies a `.vlan` suffix
/// (such as typing `Gi0/0/0/1.100` or a double-tag `Te0/1/0/1.10002000`), automatically
/// synchronizes `Dot1Q VLAN` and `2nd VLAN` with the subinterface suffix.
fn sync_vlan_from_interface_name(editor_form: &mut cisco::InterfaceEditorForm) {
    if let Some(ref mut pending_l2vpn) = editor_form.pending_l2vpn {
        pending_l2vpn.target_interface =
            cisco::expand_full_interface_name(editor_form.interface.trim());
    }
    if editor_form.interface.contains('.') {
        let (outer_vlan, inner_vlan) =
            cisco::extract_vlans_from_subinterface_name(&editor_form.interface);
        editor_form.vlan_id = outer_vlan;
        editor_form.second_vlan_id = inner_vlan;
        editor_form.omit_port_state = true;
        if !editor_form.second_vlan_id.is_empty() {
            editor_form.rewrite_ingress_pop = 2;
        } else if !editor_form.vlan_id.is_empty() && editor_form.rewrite_ingress_pop == 0 {
            editor_form.rewrite_ingress_pop = 1;
        }
    } else {
        editor_form.vlan_id.clear();
        editor_form.second_vlan_id.clear();
        editor_form.l2transport = false;
        editor_form.rewrite_ingress_pop = 0;
        editor_form.omit_port_state = false;
    }
}
