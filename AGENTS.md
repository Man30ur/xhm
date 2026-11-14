# XHM Workspace Instructions (`AGENTS.md`)

## 1. Live Connection Safety Standard (Mandatory)

1. **Never disrupt the active tunnel**: Before testing or syncing, verify whether XHM is active (`ps -ef | grep -E 'xray|sing-box|xhm|server\.py'`). Never kill, restart, toggle, or send disconnecting CLI/API calls to running `xray`, `sing-box` (`xhm-tun`), `ssh`/`sshpass`/`xhm_ssh_dialer.py`, `web/server.py`, or GNOME `org.gnome.system.proxy`.
2. **Never write to user runtime/data files during tests**: `/tmp/xhm/*`, `~/.local/share/xhm/{custom_configs.json,subscriptions.json,traffic.db,saved_system_proxy.json,proxy_env.sh}`, and live ports (`10850`, `10851`, `10852`, `10855`, `18501`) are production user state.
3. **Always run tests in full isolation**:
   ```bash
   python3 -m unittest discover -s tests -v
   ```
   Tests must redirect all module path constants to `tempfile.TemporaryDirectory()`, mock `subprocess`/`gsettings`/socket bind calls as needed, and bind any test HTTP server only to port `0`.
4. **Sync without restarting daemons**: Use `/home/mansour/.gemini/config/skills/xhm/scripts/sync.sh` (code/asset copy only). Never `pkill` a live `server.py` or proxy core unless explicitly requested; tell the user if a backend change requires restarting `xhm-gui`.

## 2. Repository Structure & Conventions

- `lib/xhm_core.py`: Core proxy/TUN manager, protocol parsers, config builders (`Xray` / `Sing-box`), `CustomConfigStore`, and `TrafficTracker` (SQLite).
- `lib/xhm_ssh_dialer.py`: Interface-bound TCP/TLS dialer for SSH `ProxyCommand`.
- `lib/xhm_tun_helper.py`: Privileged `pkexec` helper for starting/stopping `xhm-tun` when `cap_net_admin` is not granted.
- `bin/xhm`: Curses TUI & CLI delegating to `lib/xhm_core.py` (prioritizes repo `../lib` over `~/.local/lib` when invoked from repo).
- `bin/xhm-gui`: Desktop launcher that ensures `web/server.py` is running on `127.0.0.1:18501` and opens app window.
- `web/server.py` & `web/index.html`: Local Web API (`127.0.0.1:18501`) and single-page UI. Keep `web/index.html` backwards-compatible with an already-running `server.py` where feasible.
- `tests/`: Isolated unit/integration test suite (uses `xray -test` / `sing-box check` only on temporary config files).
