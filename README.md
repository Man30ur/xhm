# XHM (Xray Proxy Manager)

A modern Linux proxy client featuring both a standalone web-based Desktop GUI and an interactive Terminal UI (TUI).

## Features
- **Multi-Protocol Support:** VLESS, VMess, Trojan, Shadowsocks, SOCKS, and SSH Tunnels (`npvt-ssh://`, `ssh://`).
- **Dual Interface:**
  - Modern Desktop GUI (`xhm-gui`)
  - Interactive Terminal Menu (`xhm`)
- **System Integration:** One-click GNOME desktop system proxy toggling with full standard bypasses.
- **Built-in Full System TUN Mode (`xhm-tun`):** Self-contained system-wide routing via `sing-box` through whichever active server you select (no external VPN scripts or systemd services required).
- **Real-Time Traffic:** Live download/upload speed and total bandwidth tracking.
- **Ping Engine:** Parallel low-latency ping test for all proxy nodes.
- **Configuration Manager:** Add, edit, test, and delete proxy nodes and subscriptions.

## Requirements
All dependencies are installed automatically by `./install.sh` on Ubuntu/Debian, Fedora, Arch, and openSUSE:
- Python 3.8+, `curl`, `unzip`, `tar`, `sshpass`, `openssl`, `iproute2`
- `xray` core & `sing-box` core (automatically downloaded to `~/.local/bin` if missing)

## Installation
```bash
git clone https://github.com/<your-username>/xhm.git
cd xhm
./install.sh
```

> **Install flags:**
> - Passwordless TUN is the default: grants `cap_net_admin` on `sing-box` and installs a polkit rule so TUN DNS works without repeated sudo prompts.
> - `./install.sh --no-grant-tun-cap` — skip those grants (not recommended).
> - `./install.sh --no-deps` — skip automatic dependency installation and copy XHM files only.

## Usage
- **Launch GUI:**
  ```bash
  xhm-gui
  ```
- **Launch Terminal UI:**
  ```bash
  xhm
  ```
