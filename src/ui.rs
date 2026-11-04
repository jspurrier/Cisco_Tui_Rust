use crate::app::{App, CurrentView};
use crate::cisco::{
    abbreviate_interface_name, build_l2vpn_service_script, build_unified_interface_script,
    check_ipv4_warnings, find_l2vpn_for_interface, sanitize_pty_output,
};
use crate::model::{L2vpnServiceType, LogLevel, SortField};
use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
    Frame,
};

/// Top-level rendering entry point called on every TUI frame.
/// Draws the header banner, main interface (or L2VPN) table, bottom shortcut bar,
/// and whichever modal dialog (if any) is currently active.
pub fn render(frame: &mut Frame, app: &mut App) {
    let terminal_area = frame.size();

    let main_vertical_sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Top device status banner
            Constraint::Min(8),    // Central interface or L2VPN table
            Constraint::Length(3), // Bottom hotkey and status bar
        ])
        .split(terminal_area);

    render_header_banner(frame, app, main_vertical_sections[0]);

    let show_l2vpn_background = app.current_view == CurrentView::L2vpnList
        || (app.current_view == CurrentView::EditL2vpn && app.previous_view == CurrentView::L2vpnList)
        || (app.current_view == CurrentView::ConfirmAction
            && (app.previous_view == CurrentView::L2vpnList
                || (app.previous_view == CurrentView::EditL2vpn
                    && !app.l2vpn_form.return_to_port_editor)));

    if show_l2vpn_background {
        render_l2vpn_table(frame, app, main_vertical_sections[1]);
    } else {
        render_interface_table(frame, app, main_vertical_sections[1]);
    }

    render_footer_bar(frame, app, main_vertical_sections[2]);

    // Render the active modal overlay on top of the main table
    match app.current_view {
        CurrentView::InterfaceList | CurrentView::L2vpnList => {}
        CurrentView::ViewConfig => render_view_config_modal(frame, app),
        CurrentView::EditInterface => render_edit_interface_modal(frame, app),
        CurrentView::EditL2vpn => render_edit_l2vpn_modal(frame, app),
        CurrentView::ConfirmAction => render_confirm_action_modal(frame, app),
        CurrentView::ConnectionModal => render_connection_modal(frame, app),
        CurrentView::CommandRunner => render_command_runner_modal(frame, app),
        CurrentView::ActionLogs => render_action_logs_modal(frame, app),
        CurrentView::Help => render_help_modal(frame),
    }
}

fn render_header_banner(frame: &mut Frame, app: &App, header_area: Rect) {
    let total_interfaces = app.interfaces.len();
    let up_interface_count = app
        .interfaces
        .iter()
        .filter(|entry| entry.status.eq_ignore_ascii_case("up"))
        .count();
    let admin_down_count = app
        .interfaces
        .iter()
        .filter(|entry| entry.status.to_lowercase().contains("admin"))
        .count();
    let down_interface_count =
        total_interfaces.saturating_sub(up_interface_count + admin_down_count);

    let (connection_badge_text, connection_badge_color) = if app.is_loading {
        (" [WORKING...] ", Color::Yellow)
    } else if app.is_connected {
        (" [CONNECTED] ", Color::Green)
    } else {
        (" [DISCONNECTED] ", Color::Red)
    };

    let banner_line = Line::from(vec![
        Span::styled(
            " Cisco Port TUI ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            connection_badge_text,
            Style::default()
                .fg(connection_badge_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                " Device: {} ({}) ",
                app.connected_host,
                app.connected_os.display_name()
            ),
            Style::default().fg(Color::White),
        ),
        Span::styled(" | ", Style::default().fg(Color::DarkGray)),
        Span::styled(
            format!("Total: {} ", total_interfaces),
            Style::default().fg(Color::White),
        ),
        Span::styled(
            format!("(Up: {} ", up_interface_count),
            Style::default().fg(Color::Green),
        ),
        Span::styled(
            format!("Down: {} ", down_interface_count),
            Style::default().fg(Color::LightRed),
        ),
        Span::styled(
            format!("AdminDown: {})", admin_down_count),
            Style::default().fg(Color::Yellow),
        ),
    ]);

    let header_paragraph = Paragraph::new(banner_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Cisco Network Device Inspector "),
    );

    frame.render_widget(header_paragraph, header_area);
}

fn render_interface_table(frame: &mut Frame, app: &mut App, content_area: Rect) {
    // If a search filter is active, split a 3-line filter bar above the table
    let table_area = if app.is_filtering || !app.filter_query.is_empty() {
        let filter_and_table_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(5)])
            .split(content_area);

        let filter_prompt_text = if app.is_filtering {
            format!(
                " Search: [ {}_ ]  (Enter: keep filter, Esc: clear)",
                app.filter_query
            )
        } else {
            format!(
                " Active Filter: '{}'  (Press '/' to edit, Esc to clear)",
                app.filter_query
            )
        };

        let filter_bar_widget = Paragraph::new(filter_prompt_text)
            .style(Style::default().fg(Color::Yellow))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" Interface Filter "),
            );
        frame.render_widget(filter_bar_widget, filter_and_table_layout[0]);

        filter_and_table_layout[1]
    } else {
        content_area
    };

    let visible_interfaces: Vec<_> = app.filtered_interfaces().into_iter().cloned().collect();
    let l2vpn_services = app.l2vpn_services.clone();
    let total_interface_count = app.interfaces.len();
    let visible_interface_count = visible_interfaces.len();

    let sort_column_name = match app.sort_field {
        SortField::Name => "Name",
        SortField::Status => "Status",
        SortField::Protocol => "Protocol",
        SortField::Description => "Description",
    };
    let sort_direction_symbol = if app.sort_ascending { "▲" } else { "▼" };

    let table_block_title = if !app.filter_query.is_empty() {
        format!(
            " Interfaces (Showing {} of {}, Sorted by {} {}) | Press [w] for L2VPN Table ({}) ",
            visible_interface_count,
            total_interface_count,
            sort_column_name,
            sort_direction_symbol,
            l2vpn_services.len()
        )
    } else {
        format!(
            " Interfaces (Total {}, Sorted by {} {}) | Press [w] for L2VPN Table ({}) ",
            total_interface_count,
            sort_column_name,
            sort_direction_symbol,
            l2vpn_services.len()
        )
    };

    let table_rows: Vec<Row> = visible_interfaces
        .iter()
        .map(|interface_entry| {
            let physical_status_style = match interface_entry.status.to_lowercase().as_str() {
                "up" => Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
                status_text if status_text.contains("admin") => Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
                _ => Style::default().fg(Color::Red),
            };

            let line_protocol_style = if interface_entry.protocol.eq_ignore_ascii_case("up") {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Red)
            };

            // Highlight subinterfaces (containing a dot) in cyan so they stand out visually
            let interface_name_style = if interface_entry.name.contains('.') {
                Style::default().fg(Color::Cyan)
            } else {
                Style::default().fg(Color::White)
            };

            let (l2vpn_label, l2vpn_style) =
                if let Some((service, label)) =
                    find_l2vpn_for_interface(&interface_entry.name, &l2vpn_services)
                {
                    let color = match service.service_type {
                        L2vpnServiceType::XconnectP2p => Color::Magenta,
                        L2vpnServiceType::BridgeDomain => Color::Cyan,
                    };
                    (label, Style::default().fg(color))
                } else {
                    (String::new(), Style::default().fg(Color::DarkGray))
                };

            Row::new(vec![
                Cell::from(interface_entry.name.clone()).style(interface_name_style),
                Cell::from(interface_entry.status.to_uppercase()).style(physical_status_style),
                Cell::from(interface_entry.protocol.to_uppercase()).style(line_protocol_style),
                Cell::from(l2vpn_label).style(l2vpn_style),
                Cell::from(interface_entry.description.clone())
                    .style(Style::default().fg(Color::Gray)),
            ])
        })
        .collect();

    let interface_table_widget = Table::new(
        table_rows,
        [
            Constraint::Percentage(20),
            Constraint::Percentage(14),
            Constraint::Percentage(11),
            Constraint::Percentage(23),
            Constraint::Percentage(32),
        ],
    )
    .header(
        Row::new(vec![
            "Interface",
            "Physical Status",
            "Line Protocol",
            "L2VPN Binding",
            "Description",
        ])
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(1),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(table_block_title),
    )
    .highlight_style(
        Style::default()
            .bg(Color::Rgb(30, 45, 60))
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(">> ");

    frame.render_stateful_widget(interface_table_widget, table_area, &mut app.table_state);
}

/// Renders the dedicated L2VPN (`xconnect group` & `bridge group / bridge-domain`) Table View (`w`).
fn render_l2vpn_table(frame: &mut Frame, app: &mut App, content_area: Rect) {
    let table_area = if app.l2vpn_is_filtering || !app.l2vpn_filter_query.is_empty() {
        let filter_and_table_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(5)])
            .split(content_area);

        let filter_prompt_text = if app.l2vpn_is_filtering {
            format!(
                " Search L2VPN: [ {}_ ]  (Enter: keep filter, Esc: clear)",
                app.l2vpn_filter_query
            )
        } else {
            format!(
                " Active L2VPN Filter: '{}'  (Press '/' to edit, Esc to clear)",
                app.l2vpn_filter_query
            )
        };

        let filter_bar_widget = Paragraph::new(filter_prompt_text)
            .style(Style::default().fg(Color::Yellow))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .title(" L2VPN Filter "),
            );
        frame.render_widget(filter_bar_widget, filter_and_table_layout[0]);

        filter_and_table_layout[1]
    } else {
        content_area
    };

    let visible_services: Vec<_> = app.filtered_l2vpn_services().into_iter().cloned().collect();
    let total_count = app.l2vpn_services.len();
    let visible_count = visible_services.len();

    let table_title = format!(
        " L2VPN Services — Xconnects & Bridge-Domains (Showing {} of {}) | Press [w/Esc] for Interfaces ",
        visible_count, total_count
    );

    let rows: Vec<Row> = visible_services
        .iter()
        .map(|service| {
            let (type_badge, type_color) = match service.service_type {
                L2vpnServiceType::BridgeDomain => ("Bridge-Domain", Color::Cyan),
                L2vpnServiceType::XconnectP2p => ("Xconnect P2P", Color::Magenta),
            };

            let interfaces_summary = if service.interfaces.is_empty() {
                "(none)".to_string()
            } else {
                service
                    .interfaces
                    .iter()
                    .map(|interface_attachment| {
                        let short_name =
                            abbreviate_interface_name(&interface_attachment.interface_name);
                        if interface_attachment.split_horizon_group {
                            format!("{}[SHG]", short_name)
                        } else {
                            short_name
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            };

            let mut peers_and_bvi_parts = Vec::new();
            if !service.routed_bvi.is_empty() {
                peers_and_bvi_parts.push(service.routed_bvi.clone());
            }
            for neighbor in &service.neighbors {
                peers_and_bvi_parts
                    .push(format!("{} (pw:{})", neighbor.peer_ipv4, neighbor.pw_id));
            }
            if !service.mtu.is_empty() {
                peers_and_bvi_parts.push(format!("MTU:{}", service.mtu));
            }
            let peers_summary = peers_and_bvi_parts.join(" | ");

            Row::new(vec![
                Cell::from(type_badge).style(
                    Style::default()
                        .fg(type_color)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(service.group_name.clone()).style(Style::default().fg(Color::Yellow)),
                Cell::from(service.service_name.clone()).style(
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(interfaces_summary).style(Style::default().fg(Color::Cyan)),
                Cell::from(peers_summary).style(Style::default().fg(Color::Green)),
            ])
        })
        .collect();

    let l2vpn_table_widget = Table::new(
        rows,
        [
            Constraint::Percentage(13),
            Constraint::Percentage(17),
            Constraint::Percentage(18),
            Constraint::Percentage(32),
            Constraint::Percentage(20),
        ],
    )
    .header(
        Row::new(vec![
            "Type",
            "Group Name",
            "BD / P2P Name",
            "Attached Interfaces ([SHG]=Split-Horizon)",
            "BVI / VFI Neighbors",
        ])
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(1),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Magenta))
            .title(table_title),
    )
    .highlight_style(
        Style::default()
            .bg(Color::Rgb(45, 30, 60))
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol(">> ");

    frame.render_stateful_widget(l2vpn_table_widget, table_area, &mut app.l2vpn_table_state);
}

fn render_footer_bar(frame: &mut Frame, app: &App, footer_area: Rect) {
    let footer_line = if app.current_view == CurrentView::L2vpnList {
        Line::from(vec![
            Span::styled(
                format!(" {} ", app.status_message),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(" | "),
            Span::styled("[Enter/e]", Style::default().fg(Color::Yellow)),
            Span::raw(" Edit L2VPN "),
            Span::styled("[n]", Style::default().fg(Color::Magenta)),
            Span::raw(" New BD/XC "),
            Span::styled("[x/Del]", Style::default().fg(Color::LightRed)),
            Span::raw(" Del L2VPN "),
            Span::styled("[/]", Style::default().fg(Color::Yellow)),
            Span::raw(" Filter "),
            Span::styled("[w/Esc]", Style::default().fg(Color::Cyan)),
            Span::raw(" Interfaces "),
            Span::styled("[r]", Style::default().fg(Color::Yellow)),
            Span::raw(" Refresh "),
            Span::styled("[?]", Style::default().fg(Color::Yellow)),
            Span::raw(" Help "),
            Span::styled("[q]", Style::default().fg(Color::Yellow)),
            Span::raw(" Logout"),
        ])
    } else {
        Line::from(vec![
            Span::styled(
                format!(" {} ", app.status_message),
                Style::default().fg(Color::Cyan),
            ),
            Span::raw(" | "),
            Span::styled("[Enter/e]", Style::default().fg(Color::Yellow)),
            Span::raw(" Edit "),
            Span::styled("[n]", Style::default().fg(Color::Magenta)),
            Span::raw(" Subport "),
            Span::styled("[b]", Style::default().fg(Color::Cyan)),
            Span::raw(" Bind L2VPN "),
            Span::styled("[w]", Style::default().fg(Color::Magenta)),
            Span::raw(" L2VPN "),
            Span::styled("[x]", Style::default().fg(Color::LightRed)),
            Span::raw(" Del "),
            Span::styled("[v]", Style::default().fg(Color::Yellow)),
            Span::raw(" Config "),
            Span::styled("[u/d]", Style::default().fg(Color::Green)),
            Span::raw(" Up/Dn "),
            Span::styled("[/]", Style::default().fg(Color::Yellow)),
            Span::raw(" Filter "),
            Span::styled("[?]", Style::default().fg(Color::Yellow)),
            Span::raw(" Help "),
            Span::styled("[q/Esc]", Style::default().fg(Color::Yellow)),
            Span::raw(" Logout"),
        ])
    };

    let footer_paragraph = Paragraph::new(footer_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded),
    );

    frame.render_widget(footer_paragraph, footer_area);
}

/// Renders the read-only `show running-config interface <name>` viewer modal
/// (also used to display detailed router error reports when a config push fails).
fn render_view_config_modal(frame: &mut Frame, app: &App) {
    let modal_area = centered_percentage_rect(82, 82, frame.size());
    frame.render_widget(Clear, modal_area);

    let sanitized_content = sanitize_pty_output(&app.config_content);
    let is_error_report = app.config_interface.starts_with("PUSH FAILED");

    let formatted_lines: Vec<Line> = sanitized_content
        .lines()
        .skip(app.config_scroll)
        .map(|raw_line| {
            let trimmed_line = raw_line.trim_start();
            let line_style = if trimmed_line.starts_with("!!")
                || trimmed_line.starts_with('%')
                || trimmed_line.contains("Failed")
                || trimmed_line.contains("ERROR")
                || trimmed_line.contains("REJECTED")
            {
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD)
            } else if trimmed_line.starts_with("> ") {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else if trimmed_line.starts_with("Pushed Commands")
                || trimmed_line.starts_with("---")
                || trimmed_line.starts_with("interface ")
            {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else if trimmed_line.starts_with("shutdown") {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else if trimmed_line.starts_with("no shutdown") {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else if trimmed_line.starts_with("description ") {
                Style::default().fg(Color::Yellow)
            } else if trimmed_line.starts_with("encapsulation ")
                || trimmed_line.starts_with("rewrite ")
            {
                Style::default().fg(Color::Magenta)
            } else if trimmed_line.starts_with("ipv4 ")
                || trimmed_line.starts_with("ip address ")
                || trimmed_line.starts_with("ipv6 ")
            {
                Style::default().fg(Color::Blue)
            } else if trimmed_line.starts_with('!') {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default().fg(Color::White)
            };
            Line::from(Span::styled(format!(" {}", raw_line), line_style))
        })
        .collect();

    let total_line_count = sanitized_content.lines().count().max(1);
    let (modal_title, border_color) = if is_error_report {
        (
            format!(
                " {} (Line {}/{} - [↑/↓/PgUp/PgDn] Scroll | [Esc/q] Close) ",
                app.config_interface,
                app.config_scroll + 1,
                total_line_count
            ),
            Color::LightRed,
        )
    } else {
        (
            format!(
                " Running Config: {} (Line {}/{} - [↑/↓/PgUp/PgDn] Scroll | [Esc/q] Close) ",
                app.config_interface,
                app.config_scroll + 1,
                total_line_count
            ),
            Color::Cyan,
        )
    };

    let config_paragraph = Paragraph::new(formatted_lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(border_color))
                .title(modal_title),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(config_paragraph, modal_area);
}

/// Renders the Unified Port Configuration Editor Modal.
///
/// Field layout (left-to-right, top-to-bottom):
/// - Row 1: [0] Interface Name (42%)       | [1] Port State: ENABLED vs ADMIN DOWN (58%)
/// - Row 2: [2] Interface Description (100%)
/// - Row 3: [3] IPv4 Primary (46%)         | [4] IPv4 Secondary (comma-separated) (54%)
/// - Row 4: [5] Port Mode L2/L3 (36%)      | [6] Dot1Q VLAN ID (26%) | [7] Rewrite Ingress (38%)
/// - Row 5: [8] Jumbo MTU Optional (32%)   | Quick tips for subports and /slash masks (68%)
fn render_edit_interface_modal(frame: &mut Frame, app: &App) {
    let modal_area = centered_exact_rect(94, 29, frame.size());
    frame.render_widget(Clear, modal_area);

    let modal_sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(15), // 5 rows of 3-line bordered input boxes
            Constraint::Min(8),     // Live Cisco CLI preview box
            Constraint::Length(2),  // Bottom navigation hints
        ])
        .margin(1)
        .split(modal_area);

    let outer_modal_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::Magenta))
        .title(format!(
            " Configure / Edit Port: {} ({}) ",
            app.editor_form.interface,
            app.connected_os.display_name()
        ));
    frame.render_widget(outer_modal_block, modal_area);

    // Split the 15-line form area into 5 equal rows of height 3 so every input box has room for borders + text
    let form_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Row 1: [0] Interface Name & [1] Port State
            Constraint::Length(3), // Row 2: [2] Interface Description
            Constraint::Length(3), // Row 3: [3] Primary IPv4 & [4] Secondary IPv4
            Constraint::Length(3), // Row 4: [5] L2Transport, [6] Dot1Q VLAN ID, [7] Rewrite Ingress
            Constraint::Length(3), // Row 5: [8] Jumbo MTU (Optional) & Subport/Mask Helper Note
        ])
        .split(modal_sections[0]);

    let focused_border_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let unfocused_border_style = Style::default().fg(Color::Gray);

    // -----------------------------------------------------------------------
    // Row 1: Field [0] Interface Name (Left) & Field [1] Port State (Right)
    // -----------------------------------------------------------------------
    let row_one_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(form_rows[0]);

    // Field 0: Interface Name
    let interface_name_border = if app.editor_active_field == 0 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let interface_name_cursor = if app.editor_active_field == 0 {
        "_"
    } else {
        ""
    };
    let interface_name_widget = Paragraph::new(format!(
        " {}{}",
        app.editor_form.interface, interface_name_cursor
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(interface_name_border)
            .title(" Interface Name (.vlan) "),
    );
    frame.render_widget(interface_name_widget, row_one_columns[0]);

    // Field 1: Port State (3-state selector: Omit/Inherit vs ENABLED vs ADMIN DOWN)
    let port_state_border = if app.editor_active_field == 1 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let port_state_line = if app.editor_form.omit_port_state {
        Line::from(vec![
            Span::styled(
                " (•) Omit [Inherit]",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  ( ) ENABLED", Style::default().fg(Color::DarkGray)),
            Span::styled("  ( ) DOWN", Style::default().fg(Color::DarkGray)),
        ])
    } else if app.editor_form.port_enabled {
        Line::from(vec![
            Span::styled(" ( ) Omit  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "(•) ENABLED [no shut]",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  ( ) DOWN", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" ( ) Omit  ", Style::default().fg(Color::DarkGray)),
            Span::styled("( ) ENABLED  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "(•) ADMIN DOWN [shut]",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
        ])
    };
    let port_state_widget = Paragraph::new(port_state_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(port_state_border)
            .title(" Port State (Press Space to cycle) "),
    );
    frame.render_widget(port_state_widget, row_one_columns[1]);

    // -----------------------------------------------------------------------
    // Row 2: Field [2] Interface Description
    // -----------------------------------------------------------------------
    let description_border = if app.editor_active_field == 2 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let description_cursor = if app.editor_active_field == 2 {
        "_"
    } else {
        ""
    };
    let description_widget = Paragraph::new(format!(
        " {}{}",
        app.editor_form.description, description_cursor
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(description_border)
            .title(" Interface Description "),
    );
    frame.render_widget(description_widget, form_rows[1]);

    // -----------------------------------------------------------------------
    // Row 3: Field [3] IPv4 Primary & Field [4] IPv4 Secondary
    // -----------------------------------------------------------------------
    let row_three_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(form_rows[2]);

    // Field 3: Primary IPv4
    let primary_ip_border = if app.editor_active_field == 3 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let primary_ip_cursor = if app.editor_active_field == 3 {
        "_"
    } else {
        ""
    };
    let primary_ip_widget = Paragraph::new(format!(
        " {}{}",
        app.editor_form.primary_ip, primary_ip_cursor
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(primary_ip_border)
            .title(" IPv4 Primary (e.g. 10.1.1.1/24) "),
    );
    frame.render_widget(primary_ip_widget, row_three_columns[0]);

    // Field 4: Secondary IPv4 (supports multiple comma-separated addresses)
    let secondary_ip_border = if app.editor_active_field == 4 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let secondary_ip_cursor = if app.editor_active_field == 4 {
        "_"
    } else {
        ""
    };
    let secondary_ip_widget = Paragraph::new(format!(
        " {}{}",
        app.editor_form.secondary_ip, secondary_ip_cursor
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(secondary_ip_border)
            .title(" IPv4 Secondary (comma-sep: 10.2.1.1/24) "),
    );
    frame.render_widget(secondary_ip_widget, row_three_columns[1]);

    // -----------------------------------------------------------------------
    // Row 4: [5] Port Mode, [6] Outer Dot1Q, [7] 2nd Dot1Q (Opt), [8] Rewrite Tag
    // -----------------------------------------------------------------------
    let row_four_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(29),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(31),
        ])
        .split(form_rows[3]);

    // Field 5: L2Transport vs L3 Routed Mode Toggle
    let l2transport_border = if app.editor_active_field == 5 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let l2transport_line = if app.editor_form.l2transport {
        Line::from(vec![
            Span::styled(
                " (•) L2Trans",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  ( ) L3", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" ( ) L2Trans", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "  (•) L3",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    };
    let l2transport_widget = Paragraph::new(l2transport_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(l2transport_border)
            .title(" Mode (Space) "),
    );
    frame.render_widget(l2transport_widget, row_four_columns[0]);

    // Field 6: Outer Dot1Q VLAN ID
    let vlan_id_border = if app.editor_active_field == 6 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let vlan_id_cursor = if app.editor_active_field == 6 {
        "_"
    } else {
        ""
    };
    let vlan_id_widget =
        Paragraph::new(format!(" {}{}", app.editor_form.vlan_id, vlan_id_cursor)).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(vlan_id_border)
                .title(" Dot1Q VLAN "),
        );
    frame.render_widget(vlan_id_widget, row_four_columns[1]);

    // Field 7: Optional 2nd Dot1Q VLAN ID (second-dot1q for QinQ 2-tag circuits)
    let second_vlan_border = if app.editor_active_field == 7 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let second_vlan_cursor = if app.editor_active_field == 7 {
        "_"
    } else {
        ""
    };
    let second_vlan_widget = Paragraph::new(format!(
        " {}{}",
        app.editor_form.second_vlan_id, second_vlan_cursor
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(second_vlan_border)
            .title(" 2nd VLAN (Opt) "),
    );
    frame.render_widget(second_vlan_widget, row_four_columns[2]);

    // Field 8: Rewrite Ingress Tag Toggle (cycles: pop 1 symmetric -> pop 2 symmetric -> none)
    let rewrite_border = if app.editor_active_field == 8 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let active_tag_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD);
    let inactive_tag_style = Style::default().fg(Color::DarkGray);

    let rewrite_line = match app.editor_form.rewrite_ingress_pop {
        1 => Line::from(vec![
            Span::styled(" (•)pop1", active_tag_style),
            Span::styled(" ( )pop2", inactive_tag_style),
            Span::styled(" ( )none", inactive_tag_style),
        ]),
        2 => Line::from(vec![
            Span::styled(" ( )pop1", inactive_tag_style),
            Span::styled(" (•)pop2", active_tag_style),
            Span::styled(" ( )none", inactive_tag_style),
        ]),
        _ => Line::from(vec![
            Span::styled(" ( )pop1", inactive_tag_style),
            Span::styled(" ( )pop2", inactive_tag_style),
            Span::styled(
                " (•)none",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    };
    let rewrite_widget = Paragraph::new(rewrite_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(rewrite_border)
            .title(" Rewrite Tag (Space) "),
    );
    frame.render_widget(rewrite_widget, row_four_columns[3]);

    // -----------------------------------------------------------------------
    // Row 5: Field [9] Jumbo MTU, Field [10] Negotiation Auto & Helper Note
    // -----------------------------------------------------------------------
    let row_five_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(28),
            Constraint::Percentage(34),
            Constraint::Percentage(38),
        ])
        .split(form_rows[4]);

    // Field 9: Jumbo MTU (Optional)
    let mtu_border = if app.editor_active_field == 9 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let mtu_cursor = if app.editor_active_field == 9 {
        "_"
    } else {
        ""
    };
    let mtu_display_text = if app.editor_form.mtu.is_empty() && app.editor_active_field != 9 {
        Span::styled(
            " (blank = omit)",
            Style::default().fg(Color::DarkGray),
        )
    } else {
        Span::styled(
            format!(" {}{}", app.editor_form.mtu, mtu_cursor),
            Style::default().fg(Color::White),
        )
    };
    let mtu_widget = Paragraph::new(Line::from(mtu_display_text)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(mtu_border)
            .title(" Jumbo MTU (Optional) "),
    );
    frame.render_widget(mtu_widget, row_five_columns[0]);

    // Field 10: Negotiation Auto (Toggle with Spacebar, Off by default)
    let negotiation_border = if app.editor_active_field == 10 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let negotiation_line = if app.editor_form.negotiation_auto {
        Line::from(vec![
            Span::styled(
                " (•) negotiation auto",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  ( ) Off", Style::default().fg(Color::DarkGray)),
        ])
    } else {
        Line::from(vec![
            Span::styled(" ( ) auto  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "(•) Off (Default)",
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    };
    let negotiation_widget = Paragraph::new(negotiation_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(negotiation_border)
            .title(" Negotiation (Space) "),
    );
    frame.render_widget(negotiation_widget, row_five_columns[1]);

    let first_helper_line = if let Some(ref pending_l2vpn) = app.editor_form.pending_l2vpn {
        Span::styled(
            format!(" • {} [Ctrl+W]", pending_l2vpn.summary_badge()),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        )
    } else if let Some((_, existing_label)) =
        find_l2vpn_for_interface(&app.editor_form.interface, &app.l2vpn_services)
    {
        Span::styled(
            format!(" • {} [Ctrl+W: Edit]", existing_label),
            Style::default().fg(Color::Cyan),
        )
    } else {
        Span::styled(
            " • [Ctrl+W]: Attach L2VPN (BD/XC)",
            Style::default().fg(Color::Cyan),
        )
    };

    let second_helper_line = if app.editor_form.interface.contains('.') {
        Span::styled(
            " • [Ctrl+X]: Delete .vlan subport",
            Style::default().fg(Color::LightRed),
        )
    } else {
        Span::styled(
            " • /slash (/24, /30) auto-mask",
            Style::default().fg(Color::Gray),
        )
    };

    let helper_notes = Paragraph::new(vec![
        Line::from(first_helper_line),
        Line::from(second_helper_line),
    ]);
    frame.render_widget(helper_notes, row_five_columns[2]);

    // -----------------------------------------------------------------------
    // Live Cisco CLI Script Preview Box
    // -----------------------------------------------------------------------
    let preview_commands = build_unified_interface_script(&app.editor_form, app.connected_os);
    let has_inner_subcommands = preview_commands
        .iter()
        .any(|command_line| command_line.starts_with(' '));

    let mut preview_lines: Vec<Line> = Vec::new();
    for command_line in &preview_commands {
        let trimmed_command = command_line.trim();
        let line_style = if command_line.starts_with("configure")
            || command_line.starts_with("interface")
            || command_line == "l2vpn"
        {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else if trimmed_command.starts_with("bridge ")
            || trimmed_command.starts_with("bridge-domain ")
            || trimmed_command.starts_with("xconnect ")
            || trimmed_command.starts_with("p2p ")
            || trimmed_command.starts_with("vfi ")
            || trimmed_command == "split-horizon group"
        {
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD)
        } else if trimmed_command == "shutdown" {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else if trimmed_command == "no shutdown" {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else if trimmed_command.starts_with("no ") {
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD)
        } else if command_line.contains("address") || trimmed_command.starts_with("neighbor ") {
            Style::default().fg(Color::Yellow)
        } else if command_line.contains("commit") || command_line == "end" {
            Style::default().fg(Color::Blue)
        } else {
            Style::default().fg(Color::White)
        };
        preview_lines.push(Line::from(Span::styled(
            format!("  {}", command_line),
            line_style,
        )));

        if command_line.starts_with("interface ") && !has_inner_subcommands {
            preview_lines.push(Line::from(Span::styled(
                "   ! (No changes modified yet — existing router config is kept as-is)",
                Style::default().fg(Color::DarkGray),
            )));
        }
    }

    for ipv4_warning in check_ipv4_warnings(&app.editor_form) {
        preview_lines.push(Line::from(Span::styled(
            format!("  {}", ipv4_warning),
            Style::default()
                .fg(Color::LightRed)
                .add_modifier(Modifier::BOLD),
        )));
    }

    let preview_widget = Paragraph::new(preview_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Yellow))
            .title(format!(
                " Live CLI Script Preview ({} | Ctrl+O: Switch OS | Ctrl+W: L2VPN) ",
                app.connected_os.display_name()
            )),
    );
    frame.render_widget(preview_widget, modal_sections[1]);

    // Footer Hints (kept compact so it never clips on 80-column terminals)
    let modal_footer_hints = Paragraph::new(
        "[Tab/Arrows]: Move  [Space]: Toggle  [Ctrl+W]: L2VPN  [Enter]: Review & Push  [Esc]: Cancel",
    )
    .alignment(Alignment::Center)
    .style(Style::default().fg(Color::Yellow));
    frame.render_widget(modal_footer_hints, modal_sections[2]);
}

/// Renders the L2VPN (`xconnect group / p2p` & `bridge group / bridge-domain`) Configuration Editor Modal.
///
/// Field layout (left-to-right, top-to-bottom):
/// - Row 1: [0] Service Type (BD vs Xconnect) (38%) | [1] Existing Group/BD Picker (Space/Arrows) (62%)
/// - Row 2: [2] Group Name (48%)                    | [3] Service Name (BD / P2P) (52%)
/// - Row 3: [4] Target Interface (48%)              | [5] Interface Action & Split-Horizon Group (52%)
/// - Row 4: [6] Pseudowire Neighbors (`<IP> <pw-id>`, comma-separated) (100%)
/// - Row 5: [7] Routed Interface BVI (Opt) (36%)    | [8] BD MTU (Opt) (28%) | Member Summary (36%)
fn render_edit_l2vpn_modal(frame: &mut Frame, app: &App) {
    let modal_area = centered_exact_rect(96, 30, frame.size());
    frame.render_widget(Clear, modal_area);

    let modal_sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(15), // 5 rows of 3-line bordered input boxes
            Constraint::Min(8),     // Live L2VPN CLI preview box
            Constraint::Length(2),  // Bottom navigation hints
        ])
        .margin(1)
        .split(modal_area);

    let mode_context = if app.l2vpn_form.return_to_port_editor {
        "Attach to Port Editor (Single Atomic Commit)"
    } else {
        "Direct L2VPN Configuration"
    };

    let outer_modal_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::Cyan))
        .title(format!(
            " Configure L2VPN ({}) — {} ",
            app.l2vpn_form.service_type.display_name(),
            mode_context
        ));
    frame.render_widget(outer_modal_block, modal_area);

    let form_rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Row 1: [0] Service Type & [1] Existing Group/BD Picker
            Constraint::Length(3), // Row 2: [2] Group Name & [3] Service (BD/P2P) Name
            Constraint::Length(3), // Row 3: [4] Target Interface & [5] Action / Split-Horizon
            Constraint::Length(3), // Row 4: [6] Pseudowire Neighbors (IP pw-id, comma-sep)
            Constraint::Length(3), // Row 5: [7] Routed BVI, [8] BD MTU, & Member Summary
        ])
        .split(modal_sections[0]);

    let focused_border_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let unfocused_border_style = Style::default().fg(Color::Gray);

    // Row 1: [0] Service Type (Left) & [1] Existing Group/BD Picker (Right)
    let row_one_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(38), Constraint::Percentage(62)])
        .split(form_rows[0]);

    let type_border = if app.l2vpn_active_field == 0 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let type_line = match app.l2vpn_form.service_type {
        L2vpnServiceType::BridgeDomain => Line::from(vec![
            Span::styled(
                " (•) Bridge-Domain",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled("  ( ) Xconnect P2P", Style::default().fg(Color::DarkGray)),
        ]),
        L2vpnServiceType::XconnectP2p => Line::from(vec![
            Span::styled(" ( ) Bridge-Domain  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                "(•) Xconnect P2P",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
    };
    let type_widget = Paragraph::new(type_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(type_border)
            .title(" [0] L2VPN Type (Space) "),
    );
    frame.render_widget(type_widget, row_one_columns[0]);

    // Field 1: Existing Group / Bridge-Domain Picker
    let picker_border = if app.l2vpn_active_field == 1 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let matching_count = app
        .l2vpn_services
        .iter()
        .filter(|service| service.service_type == app.l2vpn_form.service_type)
        .count();
    let picker_label = if !app.l2vpn_form.group_name.is_empty()
        && !app.l2vpn_form.service_name.is_empty()
    {
        format!(
            " ◄ {} / {} ► ({} on router — Space to cycle)",
            app.l2vpn_form.group_name, app.l2vpn_form.service_name, matching_count
        )
    } else if matching_count > 0 {
        format!(
            " ◄ Press Space to pick from {} existing {}s ►",
            matching_count,
            app.l2vpn_form.service_type.short_label()
        )
    } else {
        " (No existing services cached — type Group & Name below)".to_string()
    };
    let picker_widget = Paragraph::new(Span::styled(
        picker_label,
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(picker_border)
            .title(" [1] Existing Group / BD Picker (Space / Backspace) "),
    );
    frame.render_widget(picker_widget, row_one_columns[1]);

    // Row 2: [2] Group Name & [3] Service Name (bridge-domain / p2p)
    let row_two_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(48), Constraint::Percentage(52)])
        .split(form_rows[1]);

    let group_border = if app.l2vpn_active_field == 2 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let group_cursor = if app.l2vpn_active_field == 2 { "_" } else { "" };
    let group_title = match app.l2vpn_form.service_type {
        L2vpnServiceType::BridgeDomain => " [2] Bridge Group (e.g. CORP_GROUP) ",
        L2vpnServiceType::XconnectP2p => " [2] Xconnect Group (e.g. METRO_XC) ",
    };
    let group_widget = Paragraph::new(format!(
        " {}{}",
        app.l2vpn_form.group_name, group_cursor
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(group_border)
            .title(group_title),
    );
    frame.render_widget(group_widget, row_two_columns[0]);

    let service_border = if app.l2vpn_active_field == 3 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let service_cursor = if app.l2vpn_active_field == 3 { "_" } else { "" };
    let service_title = match app.l2vpn_form.service_type {
        L2vpnServiceType::BridgeDomain => " [3] Bridge-Domain Name (e.g. VLAN_10) ",
        L2vpnServiceType::XconnectP2p => " [3] P2P Circuit Name (e.g. SITE_A_PW) ",
    };
    let service_widget = Paragraph::new(format!(
        " {}{}",
        app.l2vpn_form.service_name, service_cursor
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(service_border)
            .title(service_title),
    );
    frame.render_widget(service_widget, row_two_columns[1]);

    // Row 3: [4] Target Interface & [5] Interface Action / Split-Horizon
    let row_three_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(form_rows[2]);

    let interface_border = if app.l2vpn_active_field == 4 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let interface_cursor = if app.l2vpn_active_field == 4 { "_" } else { "" };
    let interface_widget = Paragraph::new(format!(
        " {}{}",
        app.l2vpn_form.target_interface, interface_cursor
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(interface_border)
            .title(" [4] Target Port (Space: Pick Port | GI/Te/BE auto-expands) "),
    );
    frame.render_widget(interface_widget, row_three_columns[0]);

    let action_border = if app.l2vpn_active_field == 5 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let action_line = match app.l2vpn_form.service_type {
        L2vpnServiceType::BridgeDomain => match app.l2vpn_form.interface_action {
            1 => Line::from(vec![
                Span::styled(
                    " (•) +split-horizon",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" ( ) No SHG", Style::default().fg(Color::DarkGray)),
                Span::styled(" ( ) Remove", Style::default().fg(Color::DarkGray)),
            ]),
            0 => Line::from(vec![
                Span::styled(" ( ) +SHG ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "(•) Attach (No SHG)",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" ( ) Remove", Style::default().fg(Color::DarkGray)),
            ]),
            _ => Line::from(vec![
                Span::styled(" ( ) +SHG ", Style::default().fg(Color::DarkGray)),
                Span::styled("( ) No SHG ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "(•) Remove (no intf)",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ]),
        },
        L2vpnServiceType::XconnectP2p => match app.l2vpn_form.interface_action {
            2 => Line::from(vec![
                Span::styled(" ( ) Attach  ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    "(•) Remove (no interface)",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ]),
            _ => Line::from(vec![
                Span::styled(
                    " (•) Attach Interface",
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled("  ( ) Remove", Style::default().fg(Color::DarkGray)),
            ]),
        },
    };
    let action_widget = Paragraph::new(action_line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(action_border)
            .title(" [5] Interface Action / Split-Horizon (Space) "),
    );
    frame.render_widget(action_widget, row_three_columns[1]);

    // Row 4: [6] Pseudowire Neighbors (`<IP> <pw-id>`, comma-separated)
    let neighbors_border = if app.l2vpn_active_field == 6 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let neighbors_cursor = if app.l2vpn_active_field == 6 { "_" } else { "" };
    let neighbors_title = match app.l2vpn_form.service_type {
        L2vpnServiceType::BridgeDomain => {
            " [6] VFI Neighbors (Optional, comma-sep '<IP> <pw-id>': e.g. 10.0.0.1 10) "
        }
        L2vpnServiceType::XconnectP2p => {
            " [6] P2P Neighbor ('<IP> <pw-id>': e.g. 10.0.0.2 100) "
        }
    };
    let neighbors_widget = Paragraph::new(format!(
        " {}{}",
        app.l2vpn_form.neighbors_input, neighbors_cursor
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(neighbors_border)
            .title(neighbors_title),
    );
    frame.render_widget(neighbors_widget, form_rows[3]);

    // Row 5: [7] Routed Interface BVI, [8] BD MTU, & Member Summary
    let row_five_columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(26),
            Constraint::Percentage(40),
        ])
        .split(form_rows[4]);

    let bvi_border = if app.l2vpn_active_field == 7 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let bvi_cursor = if app.l2vpn_active_field == 7 { "_" } else { "" };
    let bvi_widget = Paragraph::new(format!(" {}{}", app.l2vpn_form.routed_bvi, bvi_cursor))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(bvi_border)
                .title(" [7] Routed BVI (Opt: e.g. BVI10) "),
        );
    frame.render_widget(bvi_widget, row_five_columns[0]);

    let bridge_domain_mtu_border = if app.l2vpn_active_field == 8 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let bridge_domain_mtu_cursor = if app.l2vpn_active_field == 8 { "_" } else { "" };
    let bridge_domain_mtu_widget = Paragraph::new(format!(
        " {}{}",
        app.l2vpn_form.mtu, bridge_domain_mtu_cursor
    ))
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(bridge_domain_mtu_border)
            .title(" [8] BD MTU (Opt: 9100) "),
    );
    frame.render_widget(bridge_domain_mtu_widget, row_five_columns[1]);

    let existing_member_count = app
        .l2vpn_form
        .original_service
        .as_ref()
        .map(|service| service.interfaces.len())
        .unwrap_or(0);
    let helper_summary = Paragraph::new(vec![
        Line::from(Span::styled(
            format!(" • Existing member ports: {}", existing_member_count),
            Style::default().fg(Color::Cyan),
        )),
        Line::from(Span::styled(
            " • [Ctrl+T]: Cycle member interfaces",
            Style::default().fg(Color::Gray),
        )),
    ]);
    frame.render_widget(helper_summary, row_five_columns[2]);

    // Live L2VPN CLI Script Preview
    let preview_commands = build_l2vpn_service_script(&app.l2vpn_form, app.connected_os);
    let preview_lines: Vec<Line> = preview_commands
        .iter()
        .map(|command_line| {
            let trimmed = command_line.trim();
            let style = if command_line.starts_with("configure") || command_line == "l2vpn" {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else if trimmed.starts_with("no ") {
                Style::default()
                    .fg(Color::LightRed)
                    .add_modifier(Modifier::BOLD)
            } else if trimmed.starts_with("bridge ")
                || trimmed.starts_with("bridge-domain ")
                || trimmed.starts_with("xconnect ")
                || trimmed.starts_with("p2p ")
                || trimmed.starts_with("vfi ")
            {
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD)
            } else if trimmed.starts_with("neighbor ") || trimmed.starts_with("routed interface ") {
                Style::default().fg(Color::Yellow)
            } else if trimmed == "split-horizon group" {
                Style::default().fg(Color::Green)
            } else if command_line == "commit" || command_line == "end" {
                Style::default().fg(Color::Blue)
            } else {
                Style::default().fg(Color::White)
            };
            Line::from(Span::styled(format!("  {}", command_line), style))
        })
        .collect();

    let preview_box = Paragraph::new(preview_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Yellow))
            .title(" Live L2VPN CLI Script Preview (Delta-Only Mode) "),
    );
    frame.render_widget(preview_box, modal_sections[1]);

    let footer_text = if app.l2vpn_form.return_to_port_editor {
        "[Tab/Arrows]: Move  [Space]: Cycle/Toggle  [Ctrl+T]: Next Member  [Enter]: Attach to Port  [Esc]: Back"
    } else {
        "[Tab/Arrows]: Move  [Space]: Cycle/Toggle  [Ctrl+T]: Next Member  [Enter]: Review & Push  [Esc]: Cancel"
    };
    let footer_widget = Paragraph::new(footer_text)
        .alignment(Alignment::Center)
        .style(Style::default().fg(Color::Yellow));
    frame.render_widget(footer_widget, modal_sections[2]);
}

/// Renders the final safety confirmation popup before pushing CLI commands to the router.
fn render_confirm_action_modal(frame: &mut Frame, app: &App) {
    let modal_area = centered_exact_rect(76, 18, frame.size());
    frame.render_widget(Clear, modal_area);

    let modal_sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // Warning header
            Constraint::Min(8),    // CLI command list
            Constraint::Length(3), // Enter / Esc action prompt
        ])
        .margin(1)
        .split(modal_area);

    let outer_modal_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
        .title(format!(
            " CONFIRM ROUTER CONFIGURATION PUSH: {} ",
            app.confirm_title
        ));
    frame.render_widget(outer_modal_block, modal_area);

    let warning_paragraph = Paragraph::new(
        " The following commands will be sent to the Cisco router configuration session:",
    )
    .style(
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );
    frame.render_widget(warning_paragraph, modal_sections[0]);

    let command_lines: Vec<Line> = app
        .confirm_commands
        .iter()
        .map(|command_line| {
            Line::from(Span::styled(
                format!("  {}", command_line),
                Style::default().fg(Color::Yellow),
            ))
        })
        .collect();

    let commands_box = Paragraph::new(command_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .title(format!(
                " Commands Payload ({}) ",
                app.connected_os.display_name()
            )),
    );
    frame.render_widget(commands_box, modal_sections[1]);

    let action_prompt = Paragraph::new(Line::from(vec![
        Span::styled(
            " Press [Enter] to PUSH CONFIG to router ",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" | "),
        Span::styled(
            " Press [Esc] to Go Back ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ),
    ]))
    .alignment(Alignment::Center);
    frame.render_widget(action_prompt, modal_sections[2]);
}

/// Renders the initial SSH connection login dialog.
fn render_connection_modal(frame: &mut Frame, app: &App) {
    let modal_area = centered_exact_rect(70, 20, frame.size());
    frame.render_widget(Clear, modal_area);

    let modal_sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Device IP or Hostname
            Constraint::Length(3), // SSH Username
            Constraint::Length(3), // SSH Password
            Constraint::Length(3), // SSH Port
            Constraint::Length(3), // Status / Auto-detect note
            Constraint::Length(2), // Keyboard hints
        ])
        .margin(1)
        .split(modal_area);

    let outer_modal_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::Cyan))
        .title(" Connect to Cisco Router ");
    frame.render_widget(outer_modal_block, modal_area);

    let focused_border_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let unfocused_border_style = Style::default().fg(Color::Gray);

    // Field 0: Device IP or Hostname
    let host_border = if app.connection_active_field == 0 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let host_cursor = if app.connection_active_field == 0 {
        "_"
    } else {
        ""
    };
    let host_display_span = if app.connection_host.is_empty() && app.connection_active_field != 0 {
        Span::styled(
            " (e.g. 192.168.1.1, router.lab, or 'demo')",
            Style::default().fg(Color::DarkGray),
        )
    } else {
        Span::styled(
            format!(" {}{}", app.connection_host, host_cursor),
            Style::default().fg(Color::White),
        )
    };
    let host_input_widget = Paragraph::new(Line::from(host_display_span)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(host_border)
            .title(" Device IP or Hostname "),
    );
    frame.render_widget(host_input_widget, modal_sections[0]);

    // Field 1: SSH Username
    let username_border = if app.connection_active_field == 1 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let username_cursor = if app.connection_active_field == 1 {
        "_"
    } else {
        ""
    };
    let username_display_span =
        if app.connection_username.is_empty() && app.connection_active_field != 1 {
            Span::styled(
                " (e.g. admin or neteng)",
                Style::default().fg(Color::DarkGray),
            )
        } else {
            Span::styled(
                format!(" {}{}", app.connection_username, username_cursor),
                Style::default().fg(Color::White),
            )
        };
    let username_input_widget = Paragraph::new(Line::from(username_display_span)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(username_border)
            .title(" SSH Username "),
    );
    frame.render_widget(username_input_widget, modal_sections[1]);

    // Field 2: SSH Password
    let password_border = if app.connection_active_field == 2 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let password_cursor = if app.connection_active_field == 2 {
        "_"
    } else {
        ""
    };
    let masked_or_plain_password = if app.connection_show_password {
        app.connection_password.clone()
    } else {
        "•".repeat(app.connection_password.len())
    };
    let password_display_span =
        if app.connection_password.is_empty() && app.connection_active_field != 2 {
            Span::styled(" (enter password)", Style::default().fg(Color::DarkGray))
        } else {
            Span::styled(
                format!(" {}{}", masked_or_plain_password, password_cursor),
                Style::default().fg(Color::White),
            )
        };
    let password_box_title = if app.connection_show_password {
        " SSH Password (Ctrl+P: Mask) "
    } else {
        " SSH Password (Ctrl+P: Show) "
    };
    let password_input_widget = Paragraph::new(Line::from(password_display_span)).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(password_border)
            .title(password_box_title),
    );
    frame.render_widget(password_input_widget, modal_sections[2]);

    // Field 3: SSH Port
    let port_border = if app.connection_active_field == 3 {
        focused_border_style
    } else {
        unfocused_border_style
    };
    let port_cursor = if app.connection_active_field == 3 {
        "_"
    } else {
        ""
    };
    let port_input_widget =
        Paragraph::new(format!(" {}{}", app.connection_port, port_cursor)).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(port_border)
                .title(" SSH Port (Default: 22) "),
        );
    frame.render_widget(port_input_widget, modal_sections[3]);

    // Status message & OS auto-probe note
    let status_text_color = if app.is_loading {
        Color::Yellow
    } else if app.status_message.starts_with("Connection error")
        || app.status_message.starts_with("Error")
        || app.status_message.starts_with("Please")
    {
        Color::LightRed
    } else {
        Color::Cyan
    };

    let status_paragraph = Paragraph::new(vec![
        Line::from(Span::styled(
            " Router OS (IOS / IOS-XE vs IOS-XR) is automatically detected on login.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            format!(" Status: {}", app.status_message),
            Style::default()
                .fg(status_text_color)
                .add_modifier(Modifier::BOLD),
        )),
    ]);
    frame.render_widget(status_paragraph, modal_sections[4]);

    let escape_key_label = if app.is_connected {
        "[Esc]: Back"
    } else {
        "[Esc]: Quit App"
    };
    let connection_hints = Paragraph::new(format!(
        " [Enter]: Next / Connect    [Tab/↓]: Next    [↑]: Prev    [Ctrl+D]: Demo Mode    {}",
        escape_key_label
    ))
    .alignment(Alignment::Center)
    .style(Style::default().fg(Color::Yellow));
    frame.render_widget(connection_hints, modal_sections[5]);
}

/// Renders the custom CLI show/exec command runner modal.
fn render_command_runner_modal(frame: &mut Frame, app: &App) {
    let modal_area = centered_percentage_rect(75, 75, frame.size());
    frame.render_widget(Clear, modal_area);

    let modal_sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Command input box
            Constraint::Min(6),    // Router output viewer
            Constraint::Length(2), // Shortcut hints
        ])
        .margin(1)
        .split(modal_area);

    let outer_modal_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::Yellow))
        .title(" Execute Cisco CLI Command ");
    frame.render_widget(outer_modal_block, modal_area);

    let command_input_widget = Paragraph::new(format!("Router# {}_", app.command_input))
        .style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .block(
            Block::default().borders(Borders::ALL).title(
                " Command (e.g. 'show ip int brief', 'show ipv4 int brief', 'show version') ",
            ),
        );
    frame.render_widget(command_input_widget, modal_sections[0]);

    let output_lines: Vec<Line> = app
        .command_output
        .lines()
        .skip(app.command_scroll)
        .map(|output_line| Line::from(Span::styled(output_line, Style::default().fg(Color::Cyan))))
        .collect();

    let command_output_widget = Paragraph::new(output_lines)
        .block(
            Block::default().borders(Borders::ALL).title(format!(
                " Command Output (Line {}) ",
                app.command_scroll + 1
            )),
        )
        .wrap(Wrap { trim: false });
    frame.render_widget(command_output_widget, modal_sections[1]);

    let runner_hints =
        Paragraph::new(" [Enter]: Execute Command | [↑/↓]: Scroll Output | [Esc]: Close")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Yellow));
    frame.render_widget(runner_hints, modal_sections[2]);
}

/// Renders the session audit and event log viewer modal.
fn render_action_logs_modal(frame: &mut Frame, app: &App) {
    let modal_area = centered_percentage_rect(88, 84, frame.size());
    frame.render_widget(Clear, modal_area);

    let mut formatted_log_lines: Vec<Line> = Vec::new();
    for log_entry in app.logs.iter().skip(app.logs_scroll) {
        let (severity_label, severity_color) = match log_entry.level {
            LogLevel::Info => ("INFO", Color::Cyan),
            LogLevel::Success => ("SUCCESS", Color::Green),
            LogLevel::Warning => ("WARN", Color::Yellow),
            LogLevel::Error => ("ERROR", Color::Red),
        };

        formatted_log_lines.push(Line::from(vec![
            Span::styled(
                format!("[{}] ", log_entry.timestamp),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(
                format!("[{:<7}] ", severity_label),
                Style::default()
                    .fg(severity_color)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(&log_entry.message, Style::default().fg(Color::White)),
        ]));

        if let Some(ref detailed_output) = log_entry.output {
            for detail_line in detailed_output.lines() {
                let detail_trimmed = detail_line.trim();
                if detail_trimmed.is_empty() {
                    continue;
                }
                let detail_style = if detail_trimmed.starts_with("!!")
                    || detail_trimmed.starts_with('%')
                    || detail_trimmed.contains("Failed")
                    || detail_trimmed.contains("ERROR")
                {
                    Style::default().fg(Color::LightRed)
                } else {
                    Style::default().fg(Color::Gray)
                };
                formatted_log_lines.push(Line::from(Span::styled(
                    format!("    {}", detail_line),
                    detail_style,
                )));
            }
        }
    }

    let total_log_count = app.logs.len();
    let logs_modal_title = format!(
        " Router Event & Action Audit Logs (Total: {}, Entry: {}) - [↑/↓/PgUp/PgDn] Scroll | [Esc] Close ",
        total_log_count,
        app.logs_scroll + 1
    );

    let logs_paragraph = Paragraph::new(formatted_log_lines)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Double)
                .border_style(Style::default().fg(Color::Cyan))
                .title(logs_modal_title),
        );

    frame.render_widget(logs_paragraph, modal_area);
}

/// Renders the keyboard shortcut reference sheet modal.
fn render_help_modal(frame: &mut Frame) {
    let modal_area = centered_exact_rect(82, 28, frame.size());
    frame.render_widget(Clear, modal_area);

    let help_reference_text = r#"
  Cisco Router TUI - Keyboard Shortcuts & Quick Guide

  [Table Navigation]
   • ↑ / k, ↓ / j        : Move selection up / down through interfaces or L2VPNs
   • PageUp / PageDown    : Scroll table by page   |   Home / End : Jump to top / bottom
   • /                    : Filter by name, description, status, or L2VPN binding
   • s                    : Cycle sort column (Name, Status, Protocol, Description)

  [Port Configuration & L2VPN Operations]
   • Enter or e           : Open Unified Port Editor (State, Desc, IPs, VLANs, MTU)
   • n                    : Create Subinterface / L2Transport on selected port
   • b                    : Bind / Edit L2VPN (Bridge-Domain or Xconnect) for selected port
   • w                    : Switch between Interfaces Table and L2VPN Table View
   • Ctrl+W (in Editor)   : Attach / Edit L2VPN together with Subinterface in 1 commit
   • x or Delete          : Delete selected Subinterface (auto-cleans L2VPN binding)
   • v                    : View current running-config of selected interface
   • u / d                : Quick Enable ('no shutdown') / Admin Disable ('shutdown')
   • o                    : Toggle CLI syntax between Cisco IOS/IOS-XE and IOS-XR

  [Session & Diagnostics]
   • c     : Connection Dialog   |  r : Refresh Router Data  |  : : Custom CLI Command
   • q/Esc : Logout to Login     |  L : Audit & Push Logs    |  Ctrl+Q : Quit App

  Press [Esc] or [?] to close this help window.
"#;

    let help_paragraph = Paragraph::new(help_reference_text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Double)
            .border_style(Style::default().fg(Color::Yellow))
            .title(" Help & Keyboard Shortcuts "),
    );

    frame.render_widget(help_paragraph, modal_area);
}

/// Computes a centered rectangle occupying `percent_width` x `percent_height` of `container_area`.
fn centered_percentage_rect(
    percent_width: u16,
    percent_height: u16,
    container_area: Rect,
) -> Rect {
    let vertical_bands = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_height) / 2),
            Constraint::Percentage(percent_height),
            Constraint::Percentage((100 - percent_height) / 2),
        ])
        .split(container_area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_width) / 2),
            Constraint::Percentage(percent_width),
            Constraint::Percentage((100 - percent_width) / 2),
        ])
        .split(vertical_bands[1])[1]
}

/// Computes a centered rectangle of at most `target_width` x `target_height` cells,
/// clamping gracefully if the terminal window is smaller.
fn centered_exact_rect(target_width: u16, target_height: u16, container_area: Rect) -> Rect {
    let clamped_width = target_width.min(container_area.width);
    let clamped_height = target_height.min(container_area.height);

    let vertical_margin = container_area.height.saturating_sub(clamped_height) / 2;
    let horizontal_margin = container_area.width.saturating_sub(clamped_width) / 2;

    let vertical_sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(vertical_margin),
            Constraint::Length(clamped_height),
            Constraint::Min(0),
        ])
        .split(container_area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(horizontal_margin),
            Constraint::Length(clamped_width),
            Constraint::Min(0),
        ])
        .split(vertical_sections[1])[1]
}
