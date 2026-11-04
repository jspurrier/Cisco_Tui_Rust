# Cisco TUI

Terminal user interface built in Rust (`ratatui`, `tokio`, `russh`) for inspecting and configuring Cisco routers (`IOS`, `IOS-XE`, and `IOS-XR`) over SSH.

## Features

- **Interface & Subinterface Table**:
  - Polls and parses `show interfaces description` and `show running-config l2vpn`.
  - Displays physical state (`UP`, `DOWN`, `ADMIN DOWN`), line protocol, L2VPN binding (`XC` / `BD`), and circuit description.
  - Real-time search (`/`) across interface names, descriptions, status, and L2VPN bindings, plus column sorting (`s`).
- **Unified Port Configuration Editor (`Enter` / `e` / `n`)**:
  - Edit or create physical interfaces and `.vlan` subinterfaces in a single form:
    - Port state (`Omit [Inherit]` for subports, `ENABLED [no shutdown]`, or `ADMIN DOWN [shutdown]`).
    - Description, Primary IPv4, and comma-separated Secondary IPv4 addresses (supports `/slash` CIDR conversion and warns on network/broadcast host addresses).
    - `l2transport` vs L3 routed mode, single-tag (`encapsulation dot1q <vlan>`) and double-tagged QinQ (`second-dot1q <inner_vlan>`), and ingress tag rewrite (`pop 1 symmetric`, `pop 2 symmetric`, or `none`).
    - Optional Jumbo MTU and `negotiation auto`.
  - **Delta-Only CLI Generation**: Compares edits against the router's current `running-config` for that port, omitting unchanged lines and automatically emitting `no ...` statements for modified or cleared fields.
- **L2VPN (`xconnect` & `bridge-domain`) Management (`w` / `b` / `Ctrl+W`)**:
  - Dedicated L2VPN table view (`w`) listing all `xconnect group` (`p2p`) and `bridge group` (`bridge-domain`) services, attached subinterfaces, `split-horizon group` flags, `vfi` pseudowire neighbors, and `routed interface BVI` bindings.
  - Bind a subinterface to an existing or new Bridge-Domain / Xconnect directly from the Port Editor (`Ctrl+W`) so both the subinterface and L2VPN stanza commit in a single atomic transaction.
  - Automatic L2VPN cleanup when deleting a `.vlan` subinterface (`x` / `Delete`).
- **Safety & Diagnostics**:
  - Every configuration push displays the exact CLI commands in a confirmation modal before sending.
  - On Cisco IOS-XR, if a `commit` is rejected, automatically captures `show configuration failed` and aborts the uncommitted buffer.
  - Automatic return to the Login screen when pressing `q` / `Esc` or when the router's SSH `exec-timeout` closes the session.
  - Built-in offline simulator (`demo` host or `--demo` flag) for testing without hardware.

## Keyboard Shortcuts

| Key | Action |
| :--- | :--- |
| `↑` / `k`, `↓` / `j` | Move selection up or down |
| `PgUp` / `PgDn`, `Home` / `End` | Page scroll or jump to top/bottom |
| `/` | Filter interfaces or L2VPN services |
| `s` | Cycle sort column (Name, Status, Protocol, Description) |
| `Enter` or `e` | Open Port Configuration Editor (or L2VPN Editor in L2VPN view) |
| `n` | Create a new `.vlan` subinterface (or new L2VPN service in L2VPN view) |
| `b` | Bind or edit L2VPN (`bridge-domain` / `xconnect`) for the selected port |
| `w` | Toggle between Interfaces Table and L2VPN Table View |
| `Ctrl+W` (in Port Editor) | Attach/edit L2VPN alongside the subinterface in one commit |
| `x` or `Delete` | Delete selected `.vlan` subinterface (refuses physical ports; cleans up L2VPN) |
| `v` | View `show running-config interface` for the selected port |
| `u` / `d` | Quick `no shutdown` / `shutdown` with confirmation preview |
| `o` | Toggle CLI syntax mode (`Cisco IOS / IOS-XE` vs `Cisco IOS-XR`) |
| `r` | Refresh interface and L2VPN tables from router |
| `:` | Open custom CLI command runner |
| `L` | View session audit and commit logs |
| `?` | Open keyboard shortcut help |
| `q` or `Esc` | Disconnect to Login screen (or quit from Login screen) |

## Building & Running

```bash
cargo build --release
```

The compiled executable is placed at `./target/release/cisco-tui` (or `target\release\cisco-tui.exe` on Windows).

- **Portable Execution**: Uses pure-Rust SSH (`russh`) with LTO and static C runtime flags in `.cargo/config.toml` so the binary can be copied between machines and launched directly (including double-clicking from a desktop file manager).
- **Offline Demo Mode**: Enter `demo` as the hostname on the login screen, press `Ctrl+D`, or run `cisco-tui --demo`.
