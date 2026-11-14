#!/usr/bin/env bash
# XHM Installation Script (with automatic dependency & core installation)
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GRANT_TUN_CAP=1
SKIP_DEPS=0
LINK_SYSTEM_BIN=1

for arg in "$@"; do
    case "$arg" in
        --grant-tun-cap) GRANT_TUN_CAP=1 ;;
        --no-grant-tun-cap) GRANT_TUN_CAP=0 ;;
        --no-deps) SKIP_DEPS=1 ;;
        --user-only|--no-system-link) LINK_SYSTEM_BIN=0 ;;
        -h|--help)
            echo "Usage: ./install.sh [--no-grant-tun-cap] [--no-deps] [--user-only]"
            echo "  --grant-tun-cap     Grant cap_net_admin to sing-box (default) for passwordless TUN"
            echo "  --no-grant-tun-cap  Skip granting capabilities (TUN toggles may need pkexec)"
            echo "  --no-deps           Skip automatic package and core installation"
            echo "  --user-only         Install to ~/.local only without /usr/local/bin symlinks"
            exit 0
            ;;
    esac
done

run_priv() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

# Self-bootstrap when invoked standalone (e.g. bash -c "$(curl -fsSL ...)")
if [ ! -f "$SCRIPT_DIR/lib/xhm_core.py" ]; then
    XHM_REPO_URL="${XHM_REPO_URL:-https://github.com/Man30ur/xhm.git}"
    XHM_REPO_DIR="${XHM_REPO_DIR:-$HOME/.local/share/xhm/repo}"
    echo "==> Bootstrapping XHM from $XHM_REPO_URL..."

    if ! command -v git >/dev/null 2>&1; then
        echo "==> Installing git..."
        if command -v apt-get >/dev/null 2>&1; then
            run_priv apt-get update -qq && run_priv apt-get install -y git
        elif command -v dnf >/dev/null 2>&1; then
            run_priv dnf install -y git
        elif command -v pacman >/dev/null 2>&1; then
            run_priv pacman -Sy --noconfirm --needed git
        elif command -v zypper >/dev/null 2>&1; then
            run_priv zypper install -y git
        else
            echo "❌ git is required to bootstrap XHM. Please install git and retry."
            exit 1
        fi
    fi

    if [ -d "$XHM_REPO_DIR/.git" ]; then
        echo "==> Updating existing repository at $XHM_REPO_DIR..."
        if ! git -C "$XHM_REPO_DIR" pull --ff-only; then
            echo "⚠️  Could not fast-forward $XHM_REPO_DIR; installing from local repository state."
        fi
    else
        mkdir -p "$(dirname "$XHM_REPO_DIR")"
        git clone "$XHM_REPO_URL" "$XHM_REPO_DIR"
    fi

    export XHM_BOOTSTRAPPED=1
    exec bash "$XHM_REPO_DIR/install.sh" "$@"
fi

echo "==> Installing XHM..."

mkdir -p "$HOME/.local/bin" "$HOME/.local/lib" "$HOME/.local/share/xhm/web"
export PATH="$HOME/.local/bin:$PATH"

install_system_packages() {
    local missing_cmds=()
    command -v python3 >/dev/null 2>&1 || missing_cmds+=("python3")
    command -v curl >/dev/null 2>&1 || missing_cmds+=("curl")
    command -v unzip >/dev/null 2>&1 || missing_cmds+=("unzip")
    command -v tar >/dev/null 2>&1 || missing_cmds+=("tar")
    command -v sshpass >/dev/null 2>&1 || missing_cmds+=("sshpass")
    command -v ssh >/dev/null 2>&1 || missing_cmds+=("ssh")
    command -v openssl >/dev/null 2>&1 || missing_cmds+=("openssl")
    command -v ip >/dev/null 2>&1 || missing_cmds+=("ip")
    if [ "$GRANT_TUN_CAP" -eq 1 ] && ! command -v setcap >/dev/null 2>&1 && [ ! -x /sbin/setcap ] && [ ! -x /usr/sbin/setcap ]; then
        missing_cmds+=("setcap")
    fi

    if [ "${#missing_cmds[@]}" -eq 0 ]; then
        echo "✔ System packages already installed."
        return 0
    fi

    echo "==> Installing missing system packages (for: ${missing_cmds[*]})..."
    if command -v apt-get >/dev/null 2>&1; then
        local pkgs=()
        for c in "${missing_cmds[@]}"; do
            case "$c" in
                ssh) pkgs+=("openssh-client") ;;
                ip) pkgs+=("iproute2") ;;
                setcap) pkgs+=("libcap2-bin") ;;
                *) pkgs+=("$c") ;;
            esac
        done
        run_priv apt-get update -qq
        run_priv apt-get install -y "${pkgs[@]}"
    elif command -v dnf >/dev/null 2>&1; then
        local pkgs=()
        for c in "${missing_cmds[@]}"; do
            case "$c" in
                ssh) pkgs+=("openssh-clients") ;;
                ip) pkgs+=("iproute") ;;
                setcap) pkgs+=("libcap") ;;
                *) pkgs+=("$c") ;;
            esac
        done
        run_priv dnf install -y "${pkgs[@]}"
    elif command -v pacman >/dev/null 2>&1; then
        local pkgs=()
        for c in "${missing_cmds[@]}"; do
            case "$c" in
                python3) pkgs+=("python") ;;
                ssh) pkgs+=("openssh") ;;
                ip) pkgs+=("iproute2") ;;
                setcap) pkgs+=("libcap") ;;
                *) pkgs+=("$c") ;;
            esac
        done
        run_priv pacman -Sy --noconfirm --needed "${pkgs[@]}"
    elif command -v zypper >/dev/null 2>&1; then
        local pkgs=()
        for c in "${missing_cmds[@]}"; do
            case "$c" in
                ssh) pkgs+=("openssh") ;;
                ip) pkgs+=("iproute2") ;;
                *) pkgs+=("$c") ;;
            esac
        done
        run_priv zypper install -y "${pkgs[@]}"
    else
        echo "⚠️  Unsupported package manager. Please install manually: ${missing_cmds[*]}"
    fi
}

find_xray_bin() {
    command -v xray 2>/dev/null || {
        for p in "$HOME/.local/bin/xray" "/usr/local/bin/xray" "/usr/bin/xray" "$HOME/xray/xray"; do
            [ -x "$p" ] && { echo "$p"; return 0; }
        done
        return 1
    }
}

find_singbox_bin() {
    command -v sing-box 2>/dev/null || {
        for p in "$HOME/.local/bin/sing-box" "/usr/local/bin/sing-box" "/usr/bin/sing-box"; do
            [ -x "$p" ] && { echo "$p"; return 0; }
        done
        return 1
    }
}

install_xray_core() {
    if find_xray_bin >/dev/null 2>&1; then
        echo "✔ Xray core already installed ($(find_xray_bin))."
        return 0
    fi

    local arch xray_asset
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) xray_asset="Xray-linux-64.zip" ;;
        aarch64|arm64) xray_asset="Xray-linux-arm64-v8a.zip" ;;
        *)
            echo "⚠️  Unsupported architecture '$arch' for automatic Xray download."
            return 1
            ;;
    esac

    local tmpdir
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' RETURN

    echo "==> Downloading latest Xray core ($xray_asset)..."
    curl -fsSL --retry 3 "https://github.com/XTLS/Xray-core/releases/latest/download/${xray_asset}" -o "$tmpdir/xray.zip"
    unzip -q "$tmpdir/xray.zip" -d "$tmpdir/xray"
    if [ ! -f "$tmpdir/xray/xray" ]; then
        echo "❌ Failed to extract xray binary."
        return 1
    fi
    install -m 0755 "$tmpdir/xray/xray" "$HOME/.local/bin/xray"
    for dat in geoip.dat geosite.dat; do
        [ -f "$tmpdir/xray/$dat" ] && install -m 0644 "$tmpdir/xray/$dat" "$HOME/.local/bin/$dat"
    done
    "$HOME/.local/bin/xray" version >/dev/null
    echo "✔ Installed Xray core to $HOME/.local/bin/xray"
}

install_singbox_core() {
    if find_singbox_bin >/dev/null 2>&1; then
        echo "✔ sing-box core already installed ($(find_singbox_bin))."
        return 0
    fi

    local arch sb_arch
    arch="$(uname -m)"
    case "$arch" in
        x86_64|amd64) sb_arch="amd64" ;;
        aarch64|arm64) sb_arch="arm64" ;;
        *)
            echo "⚠️  Unsupported architecture '$arch' for automatic sing-box download."
            return 1
            ;;
    esac

    local tmpdir latest_url tag ver sb_asset
    tmpdir="$(mktemp -d)"
    trap 'rm -rf "$tmpdir"' RETURN

    echo "==> Resolving latest sing-box release..."
    latest_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/SagerNet/sing-box/releases/latest")"
    tag="${latest_url##*/}"
    ver="${tag#v}"
    if [ -z "$tag" ] || [ "$tag" = "latest" ]; then
        echo "❌ Could not resolve latest sing-box release tag."
        return 1
    fi

    sb_asset="sing-box-${ver}-linux-${sb_arch}.tar.gz"
    echo "==> Downloading sing-box $tag ($sb_asset)..."
    curl -fsSL --retry 3 "https://github.com/SagerNet/sing-box/releases/download/${tag}/${sb_asset}" -o "$tmpdir/singbox.tar.gz"
    tar -xzf "$tmpdir/singbox.tar.gz" -C "$tmpdir"
    local extracted_bin
    extracted_bin="$(find "$tmpdir" -type f -name sing-box | head -n 1)"
    if [ -z "$extracted_bin" ]; then
        echo "❌ Failed to extract sing-box binary."
        return 1
    fi
    install -m 0755 "$extracted_bin" "$HOME/.local/bin/sing-box"
    "$HOME/.local/bin/sing-box" version >/dev/null
    echo "✔ Installed sing-box to $HOME/.local/bin/sing-box"
}

if [ "$SKIP_DEPS" -eq 0 ]; then
    install_system_packages
    install_xray_core
    install_singbox_core
fi

# 2. Copy Core Libraries
cp "$SCRIPT_DIR/lib/xhm_core.py" "$HOME/.local/lib/xhm_core.py"
if [ -f "$SCRIPT_DIR/lib/xhm_ssh_dialer.py" ]; then
    cp "$SCRIPT_DIR/lib/xhm_ssh_dialer.py" "$HOME/.local/lib/xhm_ssh_dialer.py"
    chmod +x "$HOME/.local/lib/xhm_ssh_dialer.py"
fi
if [ -f "$SCRIPT_DIR/lib/xhm_tun_helper.py" ]; then
    cp "$SCRIPT_DIR/lib/xhm_tun_helper.py" "$HOME/.local/lib/xhm_tun_helper.py"
    chmod +x "$HOME/.local/lib/xhm_tun_helper.py"
fi

# 3. Copy Web Assets & Version
cp -r "$SCRIPT_DIR/web/"* "$HOME/.local/share/xhm/web/"
if [ -f "$SCRIPT_DIR/VERSION" ]; then
    cp "$SCRIPT_DIR/VERSION" "$HOME/.local/share/xhm/VERSION"
fi

# 4. Copy Binaries & Permissions
cp "$SCRIPT_DIR/bin/xhm" "$HOME/.local/bin/xray-menu"
cp "$SCRIPT_DIR/bin/xhm-gui" "$HOME/.local/bin/xhm-gui"
ln -sf "$HOME/.local/bin/xray-menu" "$HOME/.local/bin/xhm"
chmod +x "$HOME/.local/bin/xray-menu" "$HOME/.local/bin/xhm" "$HOME/.local/bin/xhm-gui"

# 4b. Record installation metadata for automatic Git update checks
if command -v python3 >/dev/null 2>&1; then
    XHM_META_SCRIPT_DIR="$SCRIPT_DIR" XHM_META_DEST="$HOME/.local/share/xhm/install_meta.json" XHM_BOOTSTRAPPED="${XHM_BOOTSTRAPPED:-0}" python3 - <<'PY' || true
import datetime
import json
import os
import subprocess

repo_dir = os.path.realpath(os.environ["XHM_META_SCRIPT_DIR"])
dest_file = os.environ["XHM_META_DEST"]
version = "1.0.0"
version_file = os.path.join(repo_dir, "VERSION")
if os.path.isfile(version_file):
    try:
        with open(version_file, "r", encoding="utf-8") as f:
            val = f.read().strip()
            if val:
                version = val
    except OSError:
        pass

def _git(*args):
    try:
        out = subprocess.check_output(
            ["git", "-C", repo_dir, *args],
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return out.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""

commit = _git("rev-parse", "HEAD")
short_commit = _git("rev-parse", "--short", "HEAD")
branch = _git("rev-parse", "--abbrev-ref", "HEAD")
if branch == "HEAD":
    branch = ""
remote_url = _git("remote", "get-url", "origin") or "https://github.com/Man30ur/xhm.git"

meta = {
    "version": version,
    "commit": commit,
    "short_commit": short_commit,
    "branch": branch or "main",
    "remote_url": remote_url,
    "repo_dir": repo_dir,
    "installed_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "bootstrap_mode": os.environ.get("XHM_BOOTSTRAPPED") == "1",
}
with open(dest_file, "w", encoding="utf-8") as f:
    json.dump(meta, f, indent=2)
PY
fi

# 5. Initialize sample configs if not present
if [ ! -f "$HOME/.local/share/xhm/custom_configs.json" ]; then
    cp "$SCRIPT_DIR/custom_configs.example.json" "$HOME/.local/share/xhm/custom_configs.json"
fi

# 6. Install Desktop Entry for GNOME / Desktop Application Launcher
DESKTOP_DIR="$HOME/.local/share/applications"
mkdir -p "$DESKTOP_DIR"
cat <<EOF > "$DESKTOP_DIR/xhm-gui.desktop"
[Desktop Entry]
Name=XHM Manager
Comment=Modern Linux Proxy & VPN Client (Xray / Sing-box / SSH)
Exec="$HOME/.local/bin/xhm-gui"
Icon=$HOME/.local/share/xhm/web/icon-512.png
Terminal=false
Type=Application
Categories=Network;Proxy;VPN;
StartupWMClass=xhm-gui
Keywords=xray;v2ray;vpn;proxy;vless;vmess;ssh;
EOF

if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
fi

# 7. Passwordless TUN: capabilities + polkit rule for resolved DNS writes
SING_BOX_PATH="$(find_singbox_bin || true)"
GETCAP_BIN="$(command -v getcap || ls /sbin/getcap /usr/sbin/getcap 2>/dev/null | head -n 1 || true)"
SETCAP_BIN="$(command -v setcap || ls /sbin/setcap /usr/sbin/setcap 2>/dev/null | head -n 1 || echo setcap)"
POLKIT_RULE_SRC="$SCRIPT_DIR/packaging/polkit/50-xhm-resolved.rules"
POLKIT_RULE_DST="/etc/polkit-1/rules.d/50-xhm-resolved.rules"

if [ "$GRANT_TUN_CAP" -eq 1 ]; then
    if [ -n "$SING_BOX_PATH" ]; then
        if [ -z "$GETCAP_BIN" ] || ! "$GETCAP_BIN" "$SING_BOX_PATH" 2>/dev/null | grep -q "cap_net_admin"; then
            run_priv "$SETCAP_BIN" cap_net_admin,cap_net_bind_service=+ep "$SING_BOX_PATH"
            echo "✔ Granted cap_net_admin to $SING_BOX_PATH for passwordless TUN Mode."
        else
            echo "✔ sing-box already has cap_net_admin."
        fi
    fi
    if [ -f "$POLKIT_RULE_SRC" ]; then
        if [ ! -f "$POLKIT_RULE_DST" ] || ! cmp -s "$POLKIT_RULE_SRC" "$POLKIT_RULE_DST"; then
            run_priv cp "$POLKIT_RULE_SRC" "$POLKIT_RULE_DST"
            run_priv chmod 644 "$POLKIT_RULE_DST"
            echo "✔ Installed polkit rule for passwordless TUN DNS (systemd-resolved)."
        else
            echo "✔ polkit TUN DNS rule already installed."
        fi
    fi
else
    echo "ℹ️  Skipped TUN privilege grant. Re-run with default flags (or --grant-tun-cap) for passwordless TUN."
fi

# 8. Ensure global CLI symlinks (/usr/local/bin) & PATH availability
link_system_cmd() {
    local name="$1"
    local target="$HOME/.local/bin/$name"
    local dest="/usr/local/bin/$name"
    if [ -L "$dest" ] && [ "$(readlink -f "$dest" 2>/dev/null || true)" = "$(readlink -f "$target" 2>/dev/null || true)" ]; then
        return 0
    fi
    if [ -w "/usr/local/bin" ]; then
        ln -sf "$target" "$dest"
    else
        run_priv ln -sf "$target" "$dest" 2>/dev/null || return 1
    fi
}

if [ "$LINK_SYSTEM_BIN" -eq 1 ] && [ -d "/usr/local/bin" ]; then
    if link_system_cmd "xhm" && link_system_cmd "xhm-gui"; then
        echo "✔ Linked 'xhm' and 'xhm-gui' into /usr/local/bin for immediate shell access."
    fi
fi

if ! command -v xhm >/dev/null 2>&1 && [[ ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    echo "ℹ️  Add ~/.local/bin to your PATH if not already configured:"
    echo "   export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

if pgrep -f "/.local/share/xhm/web/server.py" >/dev/null 2>&1; then
    echo "ℹ️  An active XHM web server daemon is running; restart xhm-gui when convenient to load updated code."
fi

echo "==> Installation complete!"
echo "Run 'xhm' for Terminal UI or 'xhm-gui' for Desktop GUI."
