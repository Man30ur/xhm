#!/usr/bin/env python3
"""
XHM Core Engine: Proxy Link Parsers, Config Management, and Core Controller.
Supports VLESS (Reality/TLS/WS/gRPC), VMess, Trojan, Shadowsocks, and Subscriptions.
"""

import os
import sys
import json
import time
import socket
import urllib.parse
import urllib.request
import base64
import shutil
import sqlite3
import signal
import subprocess
import unicodedata
import ssl
import gzip
import datetime
import calendar
import contextlib
import shlex
import hashlib
import threading
import ipaddress
import tempfile
from typing import Optional, List, Dict, Tuple

# --- Paths & Constants ---
XHM_DATA_DIR = os.path.expanduser("~/.local/share/xhm")
CUSTOM_CONFIGS_FILE = os.path.join(XHM_DATA_DIR, "custom_configs.json")
SUBSCRIPTIONS_FILE = os.path.join(XHM_DATA_DIR, "subscriptions.json")
TRAFFIC_DB_FILE = os.path.join(XHM_DATA_DIR, "traffic.db")
ENV_SCRIPT_FILE = os.path.join(XHM_DATA_DIR, "proxy_env.sh")
SAVED_SYSTEM_PROXY_FILE = os.path.join(XHM_DATA_DIR, "saved_system_proxy.json")
INSTALL_META_FILE = os.path.join(XHM_DATA_DIR, "install_meta.json")
UPDATE_CACHE_FILE = os.path.join(XHM_DATA_DIR, "update_cache.json")
DEFAULT_REPO_URL = "https://github.com/Man30ur/xhm.git"

RUNTIME_DIR = "/tmp/xhm"
STATE_FILE = os.path.join(RUNTIME_DIR, "state.json")
RUN_CONFIG_FILE = os.path.join(RUNTIME_DIR, "run.json")
XRAY_CONFIG_FILE = os.path.join(RUNTIME_DIR, "xray.json")
LOG_FILE = os.path.join(RUNTIME_DIR, "core.log")
TUN_MANAGED_FILE = os.path.join(RUNTIME_DIR, "tun_managed")
TUN_IFACE = "xhm-tun"
TUN_PID_FILE = os.path.join(RUNTIME_DIR, "tun.pid")
TUN_CONFIG_FILE = os.path.join(RUNTIME_DIR, "singbox-tun.json")
TUN_LOG_FILE = os.path.join(RUNTIME_DIR, "tun.log")
TUN_HELPER_BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xhm_tun_helper.py")
SSH_DIALER_BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xhm_ssh_dialer.py")

XRAY_BIN = (
    shutil.which("xray")
    or next((p for p in (os.path.expanduser("~/.local/bin/xray"), "/usr/local/bin/xray", "/usr/bin/xray", os.path.expanduser("~/xray/xray")) if os.path.exists(p)), "/usr/local/bin/xray")
)
SING_BOX_BIN = (
    shutil.which("sing-box")
    or next((p for p in (os.path.expanduser("~/.local/bin/sing-box"), "/usr/local/bin/sing-box", "/usr/bin/sing-box") if os.path.exists(p)), "")
)
SINGBOX_CONFIG_FILE = os.path.join(RUNTIME_DIR, "singbox.json")
DEFAULT_PROXY_PORT = 10850

os.makedirs(XHM_DATA_DIR, exist_ok=True)
os.makedirs(RUNTIME_DIR, exist_ok=True)


# --- Helper Utilities ---
def is_port_in_use(port: int) -> bool:
    """Check if local TCP port is already open/listening."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.25)
        return s.connect_ex(("127.0.0.1", port)) == 0


def format_duration(seconds: int) -> str:
    """Format seconds into HH:MM:SS."""
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def format_bytes(b: int) -> str:
    """Format bytes into readable units (B, KB, MB, GB)."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    else:
        return f"{b / (1024 * 1024 * 1024):.2f} GB"


def format_speed(bps: float) -> str:
    """Format byte transfer rate into speed string."""
    return f"{format_bytes(int(bps))}/s"


def get_gnome_proxy_state() -> bool:
    """Check if GNOME system proxy mode is set to manual."""
    try:
        res = subprocess.run(
            ["gsettings", "get", "org.gnome.system.proxy", "mode"],
            capture_output=True,
            text=True,
            timeout=1,
        )
        return "manual" in res.stdout
    except Exception:
        return False


STANDARD_NO_PROXY = "localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,*.local"
STANDARD_IGNORE_HOSTS = "['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '*.local']"


def get_current_gnome_proxy() -> dict:
    """Read current GNOME proxy configuration."""
    def get_val(schema: str, key: str) -> str:
        try:
            r = subprocess.run(["gsettings", "get", schema, key], capture_output=True, text=True, timeout=1)
            return r.stdout.strip().strip("'\"")
        except Exception:
            return ""
    return {
        "mode": get_val("org.gnome.system.proxy", "mode"),
        "http_host": get_val("org.gnome.system.proxy.http", "host"),
        "http_port": get_val("org.gnome.system.proxy.http", "port"),
        "https_host": get_val("org.gnome.system.proxy.https", "host"),
        "https_port": get_val("org.gnome.system.proxy.https", "port"),
        "socks_host": get_val("org.gnome.system.proxy.socks", "host"),
        "socks_port": get_val("org.gnome.system.proxy.socks", "port"),
    }


def _write_proxy_env_script(enable: bool, socks_port: int, http_port: int):
    """Write ~/.local/share/xhm/proxy_env.sh (bash/zsh/POSIX compatible) with standard no_proxy."""
    ports_pattern = "|".join(
        f"*:{p}*" for p in sorted({10850, 10851, int(socks_port), int(http_port)})
    )
    if enable:
        env_content = f"""# Managed by XHM — safe to re-source anytime (bash / zsh / POSIX sh).
# Applies proxy env only while the local XHM port is actually listening.
_XHM_SOCKS_PORT={int(socks_port)}
_XHM_HTTP_PORT={int(http_port)}

_xhm_port_open() {{
  local port="$1"
  if [ -n "${{BASH_VERSION:-}}" ]; then
    (exec 3<>/dev/tcp/127.0.0.1/"$port") 2>/dev/null || return 1
    exec 3<&-; exec 3>&-
    return 0
  elif command -v nc >/dev/null 2>&1; then
    nc -z 127.0.0.1 "$port" >/dev/null 2>&1
    return $?
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(0.2); sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1])))==0 else 1)' "$port" >/dev/null 2>&1
    return $?
  fi
  return 1
}}

_xhm_clear_xhm_proxy() {{
  local _var _val
  for _var in http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY; do
    eval "_val=\\"\\${{${{_var}}:-}}\\""
    case "$_val" in
      {ports_pattern}) unset "$_var" ;;
    esac
  done
}}

if _xhm_port_open "$_XHM_HTTP_PORT" || _xhm_port_open "$_XHM_SOCKS_PORT"; then
  export http_proxy="http://127.0.0.1:${{_XHM_HTTP_PORT}}"
  export https_proxy="http://127.0.0.1:${{_XHM_HTTP_PORT}}"
  export HTTP_PROXY="$http_proxy"
  export HTTPS_PROXY="$https_proxy"
  export all_proxy="socks5://127.0.0.1:${{_XHM_SOCKS_PORT}}"
  export ALL_PROXY="$all_proxy"
  export no_proxy="{STANDARD_NO_PROXY}"
  export NO_PROXY="{STANDARD_NO_PROXY}"
else
  _xhm_clear_xhm_proxy
  export no_proxy="{STANDARD_NO_PROXY}"
  export NO_PROXY="{STANDARD_NO_PROXY}"
fi
unset -f _xhm_port_open _xhm_clear_xhm_proxy 2>/dev/null || true
unset _XHM_SOCKS_PORT _XHM_HTTP_PORT
"""
    else:
        env_content = f"""# Managed by XHM — safe to re-source anytime (bash / zsh / POSIX sh).
# Clears only stale XHM proxy vars. Does not touch other proxies.
_xhm_clear_xhm_proxy() {{
  local _var _val
  for _var in http_proxy https_proxy all_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY; do
    eval "_val=\\"\\${{${{_var}}:-}}\\""
    case "$_val" in
      {ports_pattern}) unset "$_var" ;;
    esac
  done
}}
_xhm_clear_xhm_proxy
unset -f _xhm_clear_xhm_proxy 2>/dev/null || true
export no_proxy="{STANDARD_NO_PROXY}"
export NO_PROXY="{STANDARD_NO_PROXY}"
"""
    os.makedirs(os.path.dirname(ENV_SCRIPT_FILE) or ".", exist_ok=True)
    with open(ENV_SCRIPT_FILE, "w", encoding="utf-8") as f:
        f.write(env_content)


def verify_http_proxy_live(http_port: int, timeout: float = 3.0) -> bool:
    """Verify real HTTPS connectivity through a local HTTP proxy port."""
    if not http_port or not is_port_in_use(http_port):
        return False
    proxy_handler = urllib.request.ProxyHandler({
        "http": f"http://127.0.0.1:{http_port}",
        "https": f"http://127.0.0.1:{http_port}",
    })
    opener = urllib.request.build_opener(proxy_handler)
    for url in (
        "https://www.google.com/generate_204",
        "https://cp.cloudflare.com/generate_204",
    ):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})
            with opener.open(req, timeout=timeout) as resp:
                if resp.status in (200, 204):
                    return True
        except Exception:
            continue
    return False


def _parse_positive_port(val) -> int:
    try:
        p = int(str(val or "").strip())
        return p if p > 0 else 0
    except (TypeError, ValueError):
        return 0


def set_gnome_proxy(enable: bool, port: int = DEFAULT_PROXY_PORT, http_port: Optional[int] = None):
    """Enable or disable GNOME desktop system proxy with full standard bypasses and state restoration."""
    h_port = http_port if http_port is not None else port
    try:
        subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "ignore-hosts", STANDARD_IGNORE_HOSTS], check=False)

        if enable:
            current = get_current_gnome_proxy()
            if current.get("mode") == "manual":
                curr_h_port = _parse_positive_port(current.get("http_port"))
                curr_s_port = _parse_positive_port(current.get("socks_port"))
                probe_port = curr_h_port or curr_s_port
                if probe_port and probe_port not in (int(port), int(h_port)):
                    is_healthy = (
                        verify_http_proxy_live(curr_h_port, timeout=2.0)
                        if curr_h_port > 0
                        else is_port_in_use(curr_s_port)
                    )
                    if is_healthy:
                        try:
                            os.makedirs(os.path.dirname(SAVED_SYSTEM_PROXY_FILE) or ".", exist_ok=True)
                            with open(SAVED_SYSTEM_PROXY_FILE, "w", encoding="utf-8") as f:
                                json.dump(current, f, indent=2)
                        except Exception:
                            pass
                    elif os.path.exists(SAVED_SYSTEM_PROXY_FILE):
                        try:
                            os.remove(SAVED_SYSTEM_PROXY_FILE)
                        except Exception:
                            pass

            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.socks", "host", "127.0.0.1"], check=False)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.socks", "port", str(port)], check=False)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.http", "host", "127.0.0.1"], check=False)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.http", "port", str(h_port)], check=False)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.https", "host", "127.0.0.1"], check=False)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.https", "port", str(h_port)], check=False)
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"], check=False)
            _write_proxy_env_script(True, port, h_port)
        else:
            # On disable: restore previous proxy ONLY if its HTTP/SOCKS port is alive and verified working!
            restored = False
            if os.path.exists(SAVED_SYSTEM_PROXY_FILE):
                try:
                    with open(SAVED_SYSTEM_PROXY_FILE, "r", encoding="utf-8") as f:
                        saved = json.load(f)
                    if saved.get("mode") == "manual":
                        saved_http_port = _parse_positive_port(saved.get("http_port"))
                        saved_https_port = _parse_positive_port(saved.get("https_port"))
                        saved_socks_port = _parse_positive_port(saved.get("socks_port"))
                        own_ports = {int(port), int(h_port)}
                        if (
                            saved_http_port > 0
                            and saved.get("http_host")
                            and saved_http_port not in own_ports
                            and verify_http_proxy_live(saved_http_port, timeout=2.5)
                        ):
                            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.http", "host", str(saved.get("http_host", "127.0.0.1"))], check=False)
                            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.http", "port", str(saved_http_port)], check=False)
                            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.https", "host", str(saved.get("https_host") or saved.get("http_host") or "127.0.0.1")], check=False)
                            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.https", "port", str(saved_https_port or saved_http_port)], check=False)
                            if saved_socks_port > 0:
                                subprocess.run(["gsettings", "set", "org.gnome.system.proxy.socks", "host", str(saved.get("socks_host") or "127.0.0.1")], check=False)
                                subprocess.run(["gsettings", "set", "org.gnome.system.proxy.socks", "port", str(saved_socks_port)], check=False)
                            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"], check=False)
                            restored = True
                        elif (
                            saved_http_port == 0
                            and saved_socks_port > 0
                            and saved.get("socks_host")
                            and saved_socks_port not in own_ports
                            and is_port_in_use(saved_socks_port)
                        ):
                            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.http", "host", str(saved.get("http_host") or "")], check=False)
                            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.http", "port", "0"], check=False)
                            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.https", "host", str(saved.get("https_host") or "")], check=False)
                            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.https", "port", str(saved_https_port)], check=False)
                            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.socks", "host", str(saved.get("socks_host", "127.0.0.1"))], check=False)
                            subprocess.run(["gsettings", "set", "org.gnome.system.proxy.socks", "port", str(saved_socks_port)], check=False)
                            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"], check=False)
                            restored = True
                except Exception:
                    pass
                try:
                    os.remove(SAVED_SYSTEM_PROXY_FILE)
                except Exception:
                    pass

            if not restored:
                subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "none"], check=False)

            _write_proxy_env_script(False, port, h_port)
    except Exception:
        pass


_phys_iface_lock = threading.Lock()
_cached_physical_ip: Optional[str] = None
_cached_physical_iface: Optional[str] = None
_last_ip_check: float = 0.0


def get_physical_interface() -> Tuple[Optional[str], Optional[str]]:
    """Find physical IP and network device name (e.g. ('192.168.1.111', 'wlo1')) to bypass tun0."""
    global _cached_physical_ip, _cached_physical_iface, _last_ip_check
    with _phys_iface_lock:
        now = time.time()
        if _cached_physical_ip and _cached_physical_iface and (now - _last_ip_check < 30):
            return _cached_physical_ip, _cached_physical_iface

        try:
            res = subprocess.run(
                ["ip", "route", "show", "table", "main"],
                capture_output=True,
                text=True,
                timeout=1,
            )
            for line in res.stdout.splitlines():
                if line.startswith("default "):
                    parts = line.split()
                    iface = parts[parts.index("dev") + 1] if "dev" in parts else None
                    if not iface or iface.startswith(("tun", "xray", "xhm", "wg", "proton", "nord")):
                        continue
                    candidate_ip = None
                    if "src" in parts:
                        src_ip = parts[parts.index("src") + 1]
                        if not src_ip.startswith(("172.19.", "127.")):
                            candidate_ip = src_ip
                    if not candidate_ip:
                        res2 = subprocess.run(
                            ["ip", "-4", "addr", "show", "dev", iface],
                            capture_output=True,
                            text=True,
                            timeout=1,
                        )
                        for line2 in res2.stdout.splitlines():
                            line2 = line2.strip()
                            if line2.startswith("inet "):
                                ip_val = line2.split()[1].split("/")[0]
                                if not ip_val.startswith(("172.19.", "127.")):
                                    candidate_ip = ip_val
                                    break
                    if candidate_ip:
                        _cached_physical_iface = iface
                        _cached_physical_ip = candidate_ip
                        _last_ip_check = now
                        return _cached_physical_ip, _cached_physical_iface
        except Exception:
            pass

        return _cached_physical_ip, _cached_physical_iface


def get_physical_interface_ip() -> Optional[str]:
    ip, _ = get_physical_interface()
    return ip


def _connect_direct_tcp(host: str, port: int, timeout: float = 2.2) -> socket.socket:
    """Open a TCP socket bound directly to the physical interface to bypass local TUN."""
    physical_ip, iface = get_physical_interface()
    so_bindtodevice = getattr(socket, "SO_BINDTODEVICE", 25)
    try:
        infos = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        infos = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)

    last_err: Optional[Exception] = None
    for family, socktype, proto, _, sockaddr in infos:
        sock = None
        try:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            if iface:
                try:
                    sock.setsockopt(socket.SOL_SOCKET, so_bindtodevice, iface.encode("utf-8") + b"\0")
                except OSError:
                    pass
            if physical_ip and family == socket.AF_INET:
                try:
                    sock.bind((physical_ip, 0))
                except OSError:
                    pass
            sock.connect(sockaddr)
            return sock
        except Exception as exc:
            last_err = exc
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    if last_err is not None:
        raise last_err
    raise OSError(f"Could not resolve {host}:{port}")


def test_tcp_ping(host: str, port: int, timeout=2.2, sni: Optional[str] = None) -> Optional[int]:
    """
    Test real TCP or TLS handshake ping latency in milliseconds directly to remote server,
    bypassing local VPN / TUN interceptor (xhm-tun/tun0).
    """
    port = int(port)
    start = time.perf_counter()

    if sni:
        raw_sock = None
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw_sock = _connect_direct_tcp(host, port, timeout=timeout)
            with ctx.wrap_socket(raw_sock, server_hostname=sni) as ss:
                raw_sock = None
                _ = ss
                return round((time.perf_counter() - start) * 1000)
        except Exception:
            if raw_sock is not None:
                try:
                    raw_sock.close()
                except OSError:
                    pass
            return None

    try:
        with _connect_direct_tcp(host, port, timeout=timeout):
            return round((time.perf_counter() - start) * 1000)
    except Exception:
        return None


def safe_b64decode(content: str) -> str:
    """Robust base64 decoder supporting standard and URL-safe base64 with missing padding."""
    s = content.strip().replace("-", "+").replace("_", "/")
    missing_pad = len(s) % 4
    if missing_pad:
        s += "=" * (4 - missing_pad)
    try:
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return ""


# --- Tun Mode & Routing Management ---
def _ensure_user_writable_file(path: str) -> str:
    """Ensure a runtime file is writable without sudo/pkexec.

    Root-owned leftovers from older privileged TUN runs are replaced when possible;
    otherwise a user-owned sibling path is used so toggles never prompt for a password.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    target = path
    if os.path.exists(path) and not os.access(path, os.W_OK):
        try:
            os.remove(path)
        except PermissionError:
            target = f"{path}.{os.getuid()}"
    try:
        with open(target, "a", encoding="utf-8"):
            pass
        os.chmod(target, 0o644)
    except OSError:
        pass
    return target


def _tun_dns_ready() -> bool:
    """Return True when systemd-resolved is already using the sing-box TUN DNS stub."""
    if not shutil.which("resolvectl") or not _is_iface_up(TUN_IFACE):
        return False
    try:
        st = subprocess.run(
            ["resolvectl", "status", TUN_IFACE],
            capture_output=True,
            text=True,
            timeout=3,
        )
        out = st.stdout or ""
        return "172.19.0.2" in out and "Default Route: yes" in out
    except Exception:
        return False


def _configure_system_tun_dns() -> None:
    """Point resolved at 172.19.0.2 without pkexec.

    On stock Ubuntu these resolvectl writes need polkit auth unless the XHM
    polkit rule from install.sh is present (packaging/polkit/50-xhm-resolved.rules).
    Timeouts stay short so a missing rule cannot hang the UI.
    """
    if not shutil.which("resolvectl") or not _is_iface_up(TUN_IFACE):
        return
    if _tun_dns_ready():
        return
    try:
        for args in (
            ["resolvectl", "dns", TUN_IFACE, "172.19.0.2"],
            ["resolvectl", "domain", TUN_IFACE, "~."],
            ["resolvectl", "default-route", TUN_IFACE, "true"],
        ):
            subprocess.run(args, capture_output=True, text=True, timeout=2.5)
        subprocess.run(["resolvectl", "flush-caches"], capture_output=True, text=True, timeout=2.5)
    except Exception:
        pass


def _wait_for_tun_dns(timeout: float = 3.0) -> bool:
    """Wait for TUN DNS, then apply a passwordless resolvectl configure if needed."""
    deadline = time.time() + max(0.4, timeout)
    while time.time() < deadline:
        if _tun_dns_ready():
            return True
        time.sleep(0.2)
    _configure_system_tun_dns()
    return _tun_dns_ready()


def _revert_system_tun_dns() -> None:
    """Best-effort cache flush after TUN teardown (no polkit writes)."""
    if not shutil.which("resolvectl"):
        return
    try:
        subprocess.run(["resolvectl", "flush-caches"], capture_output=True, text=True, timeout=2.5)
    except Exception:
        pass


def _is_pid_running(pid: int) -> bool:
    if not pid or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # On Linux, verify process is not a zombie (<defunct>)
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("State:"):
                    return "Z" not in line.split()[1]
    except OSError:
        return False
    return True


def _tun_pid_paths() -> List[str]:
    return [TUN_PID_FILE, f"{TUN_PID_FILE}.{os.getuid()}"]


def _read_tun_pid_with_path() -> Tuple[Optional[int], Optional[str]]:
    for path in _tun_pid_paths():
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                pid = int(f.read().strip())
            if _is_pid_running(pid):
                return pid, path
        except Exception:
            continue
    return None, None


def _read_tun_pid() -> Optional[int]:
    pid, _ = _read_tun_pid_with_path()
    return pid


def _is_iface_up(iface: str) -> bool:
    try:
        res = subprocess.run(
            ["ip", "link", "show", "dev", iface],
            capture_output=True,
            text=True,
            timeout=1,
        )
        return res.returncode == 0 and ("UP" in res.stdout or "LOWER_UP" in res.stdout)
    except Exception:
        return False


def is_tun_supported() -> bool:
    """Return True if sing-box binary is available for built-in TUN Mode."""
    return bool(SING_BOX_BIN and os.path.isfile(SING_BOX_BIN) and os.access(SING_BOX_BIN, os.X_OK))


def is_legacy_xray_tun_active() -> bool:
    """Return True if an external legacy xray-tun systemd service is active."""
    try:
        res = subprocess.run(
            ["systemctl", "is-active", "xray-tun"],
            capture_output=True,
            text=True,
            timeout=1,
        )
        return res.stdout.strip() == "active"
    except Exception:
        return False


def is_tun_active() -> bool:
    """Check if XHM's built-in full system TUN interface (xhm-tun) is running."""
    return _is_iface_up(TUN_IFACE)


def has_external_tun() -> Optional[str]:
    """Return conflicting external TUN/WireGuard interface name (excluding xhm-tun and legacy xray-tun)."""
    try:
        res = subprocess.run(["ip", "link", "show"], capture_output=True, text=True, timeout=1)
        for line in res.stdout.splitlines():
            if (": tun" in line or ": wg" in line) and TUN_IFACE not in line and "xray-tun" not in line and "UP" in line:
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    return parts[1].strip().split("@")[0]
                return "tun0"
    except Exception:
        pass
    return None


def verify_tun_live(timeout: float = 3.0) -> bool:
    """Verify xhm-tun is up and traffic can flow.

    Do not use curl --interface: sing-box gvisor TUN does not support
    SO_BINDTODEVICE, which caused false negatives and automatic rollback.
    With auto_route, a plain HTTPS probe (proxy env cleared) exercises the
    system path through xhm-tun; fall back to the local proxy TUN forwards to.
    """
    if not is_tun_active():
        return False

    curl_bin = shutil.which("curl")
    if curl_bin:
        env = os.environ.copy()
        for key in (
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
        ):
            env.pop(key, None)
        for url in (
            "https://www.google.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
        ):
            try:
                res = subprocess.run(
                    [
                        curl_bin,
                        "-fsS",
                        "--max-time",
                        str(timeout),
                        "-o",
                        "/dev/null",
                        "-w",
                        "%{http_code}",
                        url,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=timeout + 1.5,
                    env=env,
                )
                if res.returncode == 0 and res.stdout.strip() in ("200", "204"):
                    return True
            except Exception:
                continue

    # Fallback: interface is up and the SOCKS/HTTP core TUN detours to is live.
    proxy_port, _ = _find_active_proxy_context()
    http_port = int(proxy_port or DEFAULT_PROXY_PORT) + 1
    if verify_http_proxy_live(http_port, timeout=timeout):
        return True
    return False


def _singbox_has_tun_caps(singbox_bin: str) -> bool:
    if os.geteuid() == 0:
        return True
    getcap_bin = shutil.which("getcap") or next(
        (p for p in ("/sbin/getcap", "/usr/sbin/getcap") if os.path.exists(p)),
        None,
    )
    if not getcap_bin:
        return False
    try:
        res = subprocess.run([getcap_bin, singbox_bin], capture_output=True, text=True, timeout=2)
        return "cap_net_admin" in (res.stdout or "")
    except Exception:
        return False


def _resolve_server_cidrs(host: str) -> List[str]:
    if not host:
        return []
    cidrs: List[str] = []
    try:
        ip_obj = ipaddress.ip_address(host.strip("[]"))
        if not ip_obj.is_private and not ip_obj.is_loopback:
            suffix = "/32" if ip_obj.version == 4 else "/128"
            cidrs.append(f"{ip_obj}{suffix}")
        return cidrs
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        seen = set()
        for info in infos:
            addr = info[4][0].split("%")[0]
            try:
                ip_obj = ipaddress.ip_address(addr)
                if ip_obj.is_private or ip_obj.is_loopback:
                    continue
                suffix = "/32" if ip_obj.version == 4 else "/128"
                cidr = f"{ip_obj}{suffix}"
                if cidr not in seen:
                    seen.add(cidr)
                    cidrs.append(cidr)
            except ValueError:
                continue
    except Exception:
        pass
    return cidrs


def _has_ipv6_enabled() -> bool:
    """Return True if kernel IPv6 stack is enabled on the host."""
    try:
        with open("/proc/sys/net/ipv6/conf/all/disable_ipv6", "r", encoding="utf-8") as f:
            return f.read().strip() == "0"
    except OSError:
        return False


def build_singbox_tun_config(proxy_port: int, active_node: Optional[dict] = None) -> dict:
    """Build self-contained sing-box TUN config routing system traffic via active XHM core."""
    _, phys_iface = get_physical_interface()
    ipv6_enabled = _has_ipv6_enabled()
    exclude_cidrs = [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "fc00::/7",
    ]
    if ipv6_enabled:
        exclude_cidrs.extend(["::1/128", "fe80::/10"])
    if active_node:
        for cidr in _resolve_server_cidrs(str(active_node.get("server") or "")):
            if cidr not in exclude_cidrs:
                exclude_cidrs.append(cidr)

    direct_ob = {"type": "direct", "tag": "direct"}
    if phys_iface:
        direct_ob["bind_interface"] = phys_iface

    tun_addrs = ["172.19.0.1/30", "fdfe:dcba:9876::1/126"] if ipv6_enabled else ["172.19.0.1/30"]

    return {
        "log": {"level": "warn"},
        "dns": {
            "servers": [
                {
                    # DoH via SOCKS: plain DNS/53 through the local SOCKS core often hangs
                    # under TUN and leaves systemd-resolved with a dead 172.19.0.2 stub.
                    "type": "https",
                    "tag": "dns-remote",
                    "server": "8.8.8.8",
                    "detour": "xhm-socks",
                },
                {
                    "type": "udp",
                    "tag": "dns-direct",
                    "server": "1.1.1.1",
                    "detour": "direct",
                },
            ],
            "rules": [
                {
                    "domain_suffix": [".ir", "localhost", ".local", "local"],
                    "server": "dns-direct",
                },
            ],
            "strategy": "prefer_ipv4",
            "final": "dns-remote",
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun-in",
                "interface_name": TUN_IFACE,
                "address": tun_addrs,
                "mtu": 1400,
                "auto_route": True,
                "strict_route": False,
                "stack": "gvisor",
                # Let sing-box publish TUN DNS to resolved itself (no resolvectl/polkit prompts).
                "dns_mode": "hijack",
                "route_exclude_address": exclude_cidrs,
            }
        ],
        "outbounds": [
            {
                "type": "socks",
                "tag": "xhm-socks",
                "server": "127.0.0.1",
                "server_port": int(proxy_port),
            },
            direct_ob,
            {"type": "direct", "tag": "direct-local"},
        ],
        "route": {
            "default_domain_resolver": "dns-direct",
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": "direct-local"},
                {"domain_suffix": [".ir", "localhost", ".local", "local"], "outbound": "direct"},
            ],
            "final": "xhm-socks",
            "auto_detect_interface": True,
        },
    }


def _find_active_proxy_context(manager=None) -> Tuple[Optional[int], Optional[dict]]:
    if manager is not None and getattr(manager, "connected", False):
        p = int(getattr(manager, "proxy_port", DEFAULT_PROXY_PORT) or DEFAULT_PROXY_PORT)
        if is_port_in_use(p):
            return p, getattr(manager, "active_node", None)
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                st = json.load(f)
            pid = st.get("pid")
            p = int(st.get("proxy_port") or DEFAULT_PROXY_PORT)
            if pid and _is_pid_running(int(pid)) and is_port_in_use(p):
                return p, st.get("node")
        except Exception:
            pass
    return None, None


def _run_privileged(cmd_args: List[str], timeout: int = 45) -> subprocess.CompletedProcess:
    if os.geteuid() == 0:
        return subprocess.run(cmd_args, capture_output=True, text=True, timeout=timeout)

    has_display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    pkexec_bin = shutil.which("pkexec")
    sudo_bin = shutil.which("sudo")

    if pkexec_bin and (has_display or not sys.stdin.isatty()):
        return subprocess.run([pkexec_bin, *cmd_args], capture_output=True, text=True, timeout=timeout)
    if sudo_bin:
        return subprocess.run([sudo_bin, *cmd_args], capture_output=True, text=True, timeout=timeout)
    if pkexec_bin:
        return subprocess.run([pkexec_bin, *cmd_args], capture_output=True, text=True, timeout=timeout)
    raise RuntimeError("Neither pkexec nor sudo is available for TUN privileges.")


def _cleanup_tun_runtime_files():
    for path in (*_tun_pid_paths(), TUN_MANAGED_FILE):
        if os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass


def _stop_xhm_tun() -> Tuple[bool, str]:
    """Stop xhm-tun without password prompts when sing-box is user-owned (cap_net_admin)."""
    pid, pid_path = _read_tun_pid_with_path()
    need_privileged = False
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
            # Give sing-box time to remove ip rules / table 2022 / xhm-tun.
            for _ in range(60):
                if not _is_pid_running(pid) and not _is_iface_up(TUN_IFACE):
                    break
                time.sleep(0.1)
            if _is_pid_running(pid):
                os.kill(pid, signal.SIGKILL)
                for _ in range(30):
                    if not _is_pid_running(pid) and not _is_iface_up(TUN_IFACE):
                        break
                    time.sleep(0.1)
        except PermissionError:
            need_privileged = True
        except ProcessLookupError:
            pass
    elif _is_iface_up(TUN_IFACE):
        need_privileged = True

    # Wait for kernel teardown after a successful user-level kill — do NOT
    # pkexec just because the iface lingers for a moment (that caused multi-password prompts).
    if not need_privileged:
        for _ in range(40):
            if not _is_iface_up(TUN_IFACE):
                break
            time.sleep(0.1)

    # Privileged stop only when we literally cannot signal the process (root-owned) or orphan iface remains.
    if need_privileged and os.path.exists(TUN_HELPER_BIN):
        res = _run_privileged([sys.executable, TUN_HELPER_BIN, "stop", pid_path or TUN_PID_FILE, "--iface", TUN_IFACE])
        if res.returncode != 0:
            err = (res.stderr or res.stdout or "Failed to stop xhm-tun").strip()
            _cleanup_tun_runtime_files()
            _revert_system_tun_dns()
            return False, err

    _cleanup_tun_runtime_files()
    _revert_system_tun_dns()
    return True, "Full System TUN Mode Disabled"


def set_tun_mode_detailed(enable: bool, manager=None) -> Tuple[bool, str]:
    """Enable or disable XHM's self-contained Full System TUN Mode (xhm-tun) via active server."""
    try:
        if not enable:
            return _stop_xhm_tun()

        if not is_tun_supported():
            return False, "sing-box binary is required for built-in TUN Mode."

        ext_iface = has_external_tun()
        if ext_iface:
            return False, f"External VPN/TUN ({ext_iface}) is already active; stop it before enabling TUN Mode."

        proxy_port, active_node = _find_active_proxy_context(manager)
        if not proxy_port:
            return False, "Connect to a server in XHM first before enabling TUN Mode."

        if is_tun_active():
            if verify_tun_live(timeout=3.0):
                tag = (active_node or {}).get("tag", "active server")
                return True, f"Full System TUN Mode Enabled (via {tag})"
            _stop_xhm_tun()

        tun_cfg = build_singbox_tun_config(proxy_port, active_node=active_node)
        with open(TUN_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(tun_cfg, f, indent=2, ensure_ascii=False)

        chk = subprocess.run([SING_BOX_BIN, "check", "-c", TUN_CONFIG_FILE], capture_output=True, text=True, timeout=5)
        if chk.returncode != 0:
            err_msg = (chk.stderr or chk.stdout or "Invalid TUN config").strip()
            return False, f"TUN config error: {err_msg[:120]}"

        legacy_active = is_legacy_xray_tun_active()
        has_caps = _singbox_has_tun_caps(SING_BOX_BIN)
        if has_caps:
            if legacy_active:
                # Avoid pkexec stop of legacy service on every toggle; ask user once.
                return False, "Stop legacy xray-tun service first: systemctl stop xray-tun"

            log_path = _ensure_user_writable_file(TUN_LOG_FILE)
            pid_path = _ensure_user_writable_file(TUN_PID_FILE)
            with open(log_path, "a", encoding="utf-8") as log_fp:
                proc = subprocess.Popen(
                    [SING_BOX_BIN, "run", "-c", TUN_CONFIG_FILE],
                    stdout=log_fp,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )
            with open(pid_path, "w", encoding="utf-8") as f:
                f.write(str(proc.pid))
            # Keep canonical pid path in sync when a uid-sibling fallback was used.
            if pid_path != TUN_PID_FILE:
                try:
                    with open(TUN_PID_FILE, "w", encoding="utf-8") as f:
                        f.write(str(proc.pid))
                except OSError:
                    pass
            for _ in range(40):
                if proc.poll() is not None:
                    _stop_xhm_tun()
                    return False, f"xhm-tun exited unexpectedly; check {log_path}"
                if _is_iface_up(TUN_IFACE):
                    break
                time.sleep(0.1)
        elif os.path.exists(TUN_HELPER_BIN) and (os.geteuid() == 0 or shutil.which("pkexec") or shutil.which("sudo")):
            cmd = [
                sys.executable,
                TUN_HELPER_BIN,
                "start",
                SING_BOX_BIN,
                TUN_CONFIG_FILE,
                TUN_PID_FILE,
                TUN_LOG_FILE,
                "--iface",
                TUN_IFACE,
            ]
            if legacy_active:
                cmd.append("--stop-legacy")
            res = _run_privileged(cmd, timeout=60)
            if res.returncode != 0:
                err = (res.stderr or res.stdout or "").strip()
                hint = (
                    "TUN privilege prompt failed or was cancelled. For passwordless TUN, run: "
                    f"sudo setcap cap_net_admin,cap_net_bind_service=+ep {SING_BOX_BIN}"
                )
                return False, (f"{err} ({hint})" if err else hint)
        else:
            return False, (
                "Passwordless TUN Mode needs one-time setup: "
                "sudo setcap cap_net_admin,cap_net_bind_service=+ep "
                f"{SING_BOX_BIN}   (or re-run ./install.sh --grant-tun-cap)"
            )

        # sing-box itself publishes 172.19.0.2 to resolved — wait, don't resolvectl-write (polkit).
        _wait_for_tun_dns(timeout=4.0)

        if not verify_tun_live(timeout=4.5):
            _stop_xhm_tun()
            return False, "xhm-tun failed live connectivity check and was rolled back to protect internet."

        _wait_for_tun_dns(timeout=2.0)

        os.makedirs(RUNTIME_DIR, exist_ok=True)
        with open(TUN_MANAGED_FILE, "w", encoding="utf-8") as f:
            f.write(str(time.time()))
        tag = (active_node or {}).get("tag", "active server")
        return True, f"Full System TUN Mode Enabled (via {tag})"
    except Exception as e:
        return False, f"Error toggling TUN mode: {e}"


def set_tun_mode(enable: bool, manager=None) -> bool:
    """Enable or disable XHM's built-in Full System TUN Mode (xhm-tun)."""
    ok, _ = set_tun_mode_detailed(enable, manager=manager)
    return ok


# --- Universal Proxy Link Parsers ---
def _format_host_for_uri(host: str) -> str:
    h = str(host or "").strip()
    if ":" in h and not h.startswith("["):
        return f"[{h}]"
    return h


def _parse_query_bool(qs: dict, *keys: str) -> bool:
    for k in keys:
        vals = qs.get(k)
        if vals and str(vals[0]).strip().lower() in ("1", "true", "yes"):
            return True
    return False


def _parse_transport_from_qs(qs: dict, tr_type: str) -> dict:
    tp: Dict = {"type": tr_type}
    if tr_type in ("ws", "httpupgrade"):
        tp["path"] = urllib.parse.unquote(qs.get("path", ["/"])[0] or "/")
        h = urllib.parse.unquote(qs.get("host", [""])[0] or "")
        if h:
            tp["headers"] = {"Host": h}
    elif tr_type in ("xhttp", "splithttp"):
        tp["path"] = urllib.parse.unquote(qs.get("path", ["/"])[0] or "/")
        h = urllib.parse.unquote(qs.get("host", [""])[0] or "")
        if h:
            tp["host"] = h
            tp["headers"] = {"Host": h}
        mode = (qs.get("mode", [""])[0] or "").strip()
        if mode:
            tp["mode"] = mode
        extra = (qs.get("extra", [""])[0] or "").strip()
        if extra:
            tp["extra"] = urllib.parse.unquote(extra)
    elif tr_type == "grpc":
        srv_name = urllib.parse.unquote(qs.get("serviceName", [""])[0] or qs.get("service", [""])[0] or qs.get("path", [""])[0] or "")
        tp["service_name"] = srv_name
        mode = (qs.get("mode", [""])[0] or "").strip()
        if mode:
            tp["mode"] = mode
    elif tr_type in ("http", "h2"):
        tp["path"] = urllib.parse.unquote(qs.get("path", ["/"])[0] or "/")
        h = urllib.parse.unquote(qs.get("host", [""])[0] or "")
        if h:
            tp["host"] = [x.strip() for x in h.split(",") if x.strip()]
    elif tr_type == "tcp":
        hdr_type = (qs.get("headerType", [""])[0] or "").strip().lower()
        if hdr_type == "http":
            tp["header_type"] = "http"
            h = urllib.parse.unquote(qs.get("host", [""])[0] or "")
            p = urllib.parse.unquote(qs.get("path", [""])[0] or "")
            if h:
                tp["headers"] = {"Host": h}
            if p:
                tp["path"] = p
    return tp


def _extract_raw_userinfo(url_str: str) -> str:
    """Return raw decoded userinfo from scheme://userinfo@host:port without losing embedded ':'."""
    after_scheme = url_str.split("://", 1)[1]
    authority = after_scheme.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" not in authority:
        return ""
    return urllib.parse.unquote(authority.rsplit("@", 1)[0])


def _apply_tls_from_qs(tls_obj: dict, qs: dict, host: str, sec: str, default_fp: str = "") -> dict:
    if _parse_query_bool(qs, "allowInsecure", "insecure"):
        tls_obj["insecure"] = True
    if sec == "reality":
        pbk = urllib.parse.unquote(qs.get("pbk", [""])[0] or qs.get("publicKey", [""])[0] or "")
        sid = urllib.parse.unquote(qs.get("sid", [""])[0] or qs.get("shortId", [""])[0] or "")
        spx = urllib.parse.unquote(qs.get("spx", [""])[0] or qs.get("spiderx", [""])[0] or "")
        reality_dict = {
            "enabled": True,
            "public_key": pbk,
            "short_id": sid,
        }
        if spx:
            reality_dict["spider_x"] = spx
        tls_obj["reality"] = reality_dict

    sni = urllib.parse.unquote(qs.get("sni", [""])[0] or qs.get("serverName", [""])[0] or "")
    if tls_obj.get("enabled") or sni:
        tls_obj["server_name"] = sni or host

    fp = urllib.parse.unquote(qs.get("fp", [""])[0] or qs.get("fingerprint", [""])[0] or "") or (default_fp if tls_obj.get("enabled") else "")
    if fp:
        tls_obj["utls"] = {"enabled": True, "fingerprint": fp}

    alpn_raw = qs.get("alpn", [""])[0]
    if alpn_raw:
        alpn_list = [a.strip() for a in urllib.parse.unquote(alpn_raw).split(",") if a.strip()]
        if alpn_list:
            tls_obj["alpn"] = alpn_list
    return tls_obj


def parse_proxy_link(link: str, default_tag: str = "") -> Optional[Dict]:
    """Parse vless, vmess, trojan, ss, hy2/hysteria2, tuic, socks, npvt-ssh, or ssh URI into outbound dict."""
    link = link.strip()
    if not link:
        return None

    try:
        lower = link.lower()
        if lower.startswith("vless://"):
            u = urllib.parse.urlparse(link)
            uuid = urllib.parse.unquote(u.username or "").strip()
            host = (u.hostname or "").strip()
            port = int(u.port or 443)
            if not uuid or not host:
                return None
            qs = urllib.parse.parse_qs(u.query)
            tag = urllib.parse.unquote(u.fragment).strip() if u.fragment else (default_tag or f"VLESS-{host}:{port}")
            sec = (qs.get("security", ["none"])[0] or "none").lower()
            flow = urllib.parse.unquote(qs.get("flow", [""])[0] or "").strip()
            enc = urllib.parse.unquote(qs.get("encryption", ["none"])[0] or "none").strip()
            tr_type = (qs.get("type", ["tcp"])[0] or "tcp").lower()

            tls_obj: Dict = {"enabled": sec in ("tls", "reality")}
            _apply_tls_from_qs(tls_obj, qs, host, sec, default_fp="chrome")

            ob = {
                "type": "vless",
                "tag": tag,
                "server": host,
                "server_port": port,
                "uuid": uuid,
                "flow": flow,
                "tls": tls_obj,
                "transport": _parse_transport_from_qs(qs, tr_type),
            }
            if enc and enc != "none":
                ob["encryption"] = enc
            return ob

        elif lower.startswith("vmess://"):
            raw = link[8:].strip()
            decoded = safe_b64decode(raw)
            if not decoded:
                return None
            d = json.loads(decoded)
            srv = str(d.get("add", "") or "").strip()
            prt = int(str(d.get("port") or 443).strip() or 443)
            uuid = str(d.get("id", "") or "").strip()
            if not srv or not uuid:
                return None
            tag = str(d.get("ps") or "").strip() or (default_tag or f"VMess-{srv}:{prt}")
            is_tls = str(d.get("tls", "")).lower() == "tls"
            net = str(d.get("net", "tcp") or "tcp").lower()
            tls_dict: Dict = {"enabled": is_tls}
            if is_tls or d.get("sni"):
                tls_dict["server_name"] = str(d.get("sni") or d.get("host") or srv)
            if d.get("verify_cert") is False or str(d.get("allowInsecure", "")).lower() in ("1", "true"):
                tls_dict["insecure"] = True
            if d.get("fp"):
                tls_dict["utls"] = {"enabled": True, "fingerprint": str(d.get("fp"))}
            if d.get("alpn"):
                alpn_list = [a.strip() for a in str(d.get("alpn")).split(",") if a.strip()]
                if alpn_list:
                    tls_dict["alpn"] = alpn_list

            aid_raw = str(d.get("aid") if d.get("aid") not in (None, "") else "0").strip()
            aid = int(aid_raw) if aid_raw.isdigit() else 0

            tp: Dict = {"type": net}
            if net in ("ws", "httpupgrade"):
                tp["path"] = str(d.get("path") or "/")
                if d.get("host"):
                    tp["headers"] = {"Host": str(d.get("host"))}
            elif net == "grpc":
                tp["service_name"] = str(d.get("path") or d.get("serviceName") or "")
            elif net in ("http", "h2"):
                tp["path"] = str(d.get("path") or "/")
                if d.get("host"):
                    tp["host"] = [h.strip() for h in str(d.get("host")).split(",") if h.strip()]
            elif net == "tcp" and str(d.get("type", "")).lower() == "http":
                tp["header_type"] = "http"
                if d.get("host"):
                    tp["headers"] = {"Host": str(d.get("host"))}
                if d.get("path"):
                    tp["path"] = str(d.get("path"))

            return {
                "type": "vmess",
                "tag": tag,
                "server": srv,
                "server_port": prt,
                "uuid": uuid,
                "alter_id": aid,
                "security": str(d.get("scy") or "auto"),
                "tls": tls_dict,
                "transport": tp,
            }

        elif lower.startswith("trojan://"):
            u = urllib.parse.urlparse(link)
            pwd = _extract_raw_userinfo(link) or urllib.parse.unquote(u.username or "")
            host = (u.hostname or "").strip()
            port = int(u.port or 443)
            if not pwd or not host:
                return None
            qs = urllib.parse.parse_qs(u.query)
            tag = urllib.parse.unquote(u.fragment).strip() if u.fragment else (default_tag or f"Trojan-{host}:{port}")
            sec = (qs.get("security", ["tls"])[0] or "tls").lower()
            tr_type = (qs.get("type", ["tcp"])[0] or "tcp").lower()

            tls_dict: Dict = {"enabled": sec != "none"}
            _apply_tls_from_qs(tls_dict, qs, host, sec)

            return {
                "type": "trojan",
                "tag": tag,
                "server": host,
                "server_port": port,
                "password": pwd,
                "tls": tls_dict,
                "transport": _parse_transport_from_qs(qs, tr_type),
            }

        elif lower.startswith("ss://"):
            rest = link[5:]
            tag = default_tag or ""
            if "#" in rest:
                rest, raw_tag = rest.split("#", 1)
                tag = urllib.parse.unquote(raw_tag).strip() or tag
            if "?" in rest:
                rest, query_str = rest.split("?", 1)
            else:
                query_str = ""

            if "@" in rest:
                user_info, host_port = rest.rsplit("@", 1)
                user_info_unquoted = urllib.parse.unquote(user_info)
                if ":" in user_info_unquoted:
                    method, pwd = user_info_unquoted.split(":", 1)
                else:
                    decoded = safe_b64decode(user_info)
                    if ":" not in decoded:
                        return None
                    method, pwd = decoded.split(":", 1)
            else:
                decoded = safe_b64decode(rest.split("/", 1)[0])
                if "@" not in decoded:
                    return None
                user_info, host_port = decoded.rsplit("@", 1)
                method, pwd = user_info.split(":", 1)

            if "/" in host_port:
                host_port = host_port.split("/", 1)[0]
            if ":" not in host_port:
                return None
            host, port_s = host_port.rsplit(":", 1)
            host = host.strip("[]").strip()
            port = int(port_s)
            if not host or not method:
                return None

            ob: Dict = {
                "type": "shadowsocks",
                "tag": tag or f"SS-{host}:{port}",
                "server": host,
                "server_port": port,
                "method": method,
                "password": pwd,
            }
            if query_str:
                qs = urllib.parse.parse_qs(query_str)
                if qs.get("plugin"):
                    raw_plugin = urllib.parse.unquote(qs["plugin"][0]).strip()
                    if ";" in raw_plugin:
                        pname, popts = raw_plugin.split(";", 1)
                        ob["plugin"] = pname.strip()
                        if popts.strip():
                            ob["plugin_opts"] = popts.strip()
                    elif raw_plugin:
                        ob["plugin"] = raw_plugin
            return ob

        elif lower.startswith(("hy2://", "hysteria2://")):
            u = urllib.parse.urlparse(link)
            pwd = _extract_raw_userinfo(link) or urllib.parse.unquote(u.username or "")
            host = (u.hostname or "").strip()
            port = int(u.port or 443)
            if not host or not pwd:
                return None
            qs = urllib.parse.parse_qs(u.query)
            tag = urllib.parse.unquote(u.fragment).strip() if u.fragment else (default_tag or f"Hysteria2-{host}:{port}")

            tls_dict: Dict = {
                "enabled": True,
                "server_name": urllib.parse.unquote(qs.get("sni", [""])[0] or qs.get("serverName", [""])[0] or host),
            }
            if _parse_query_bool(qs, "insecure", "allowInsecure"):
                tls_dict["insecure"] = True
            if qs.get("alpn"):
                tls_dict["alpn"] = [a.strip() for a in urllib.parse.unquote(qs["alpn"][0]).split(",") if a.strip()]
            pin = urllib.parse.unquote(qs.get("pinSHA256", [""])[0] or "")

            ob = {
                "type": "hysteria2",
                "tag": tag,
                "server": host,
                "server_port": port,
                "password": pwd,
                "tls": tls_dict,
            }
            if pin:
                ob["pin_sha256"] = pin
            obfs_type = (qs.get("obfs", [""])[0] or "").strip()
            obfs_pw = urllib.parse.unquote(qs.get("obfs-password", [""])[0] or "")
            if obfs_type and obfs_type != "none":
                ob["obfs"] = {"type": obfs_type, "password": obfs_pw}
            for src_key, dst_key in (("upmbps", "up_mbps"), ("downmbps", "down_mbps"), ("up", "up_mbps"), ("down", "down_mbps")):
                if qs.get(src_key) and dst_key not in ob:
                    val_digits = "".join(ch for ch in str(qs[src_key][0]) if ch.isdigit())
                    if val_digits:
                        ob[dst_key] = int(val_digits)
            return ob

        elif lower.startswith("tuic://"):
            u = urllib.parse.urlparse(link)
            raw_ui = _extract_raw_userinfo(link)
            if ":" in raw_ui:
                uuid, pwd = raw_ui.split(":", 1)
            else:
                uuid, pwd = urllib.parse.unquote(u.username or ""), urllib.parse.unquote(u.password or "")
            host = (u.hostname or "").strip()
            port = int(u.port or 443)
            if not host or not uuid:
                return None
            qs = urllib.parse.parse_qs(u.query)
            tag = urllib.parse.unquote(u.fragment).strip() if u.fragment else (default_tag or f"TUIC-{host}:{port}")
            tls_dict: Dict = {
                "enabled": True,
                "server_name": urllib.parse.unquote(qs.get("sni", [""])[0] or host),
            }
            if _parse_query_bool(qs, "allowInsecure", "insecure", "allow_insecure"):
                tls_dict["insecure"] = True
            alpn_raw = qs.get("alpn", ["h3"])[0]
            tls_dict["alpn"] = [a.strip() for a in urllib.parse.unquote(alpn_raw).split(",") if a.strip()] or ["h3"]
            return {
                "type": "tuic",
                "tag": tag,
                "server": host,
                "server_port": port,
                "uuid": uuid,
                "password": pwd,
                "congestion_control": (qs.get("congestion_control", ["bbr"])[0] or "bbr").lower(),
                "udp_relay_mode": (qs.get("udp_relay_mode", ["native"])[0] or "native").lower(),
                "tls": tls_dict,
            }

        elif lower.startswith(("socks://", "socks5://", "socks4://", "socks4a://")):
            scheme = link.split("://", 1)[0].lower()
            u = urllib.parse.urlparse(link)
            host = (u.hostname or "").strip()
            port = int(u.port or 1080)
            if not host:
                return None
            raw_ui = _extract_raw_userinfo(link)
            user = ""
            pwd = ""
            if raw_ui:
                if ":" in raw_ui:
                    user, pwd = raw_ui.split(":", 1)
                else:
                    decoded_ui = safe_b64decode(raw_ui)
                    if ":" in decoded_ui:
                        user, pwd = decoded_ui.split(":", 1)
                    else:
                        user = raw_ui
            tag = urllib.parse.unquote(u.fragment).strip() if u.fragment else (default_tag or f"SOCKS-{host}:{port}")
            ob = {
                "type": "socks",
                "tag": tag,
                "server": host,
                "server_port": port,
            }
            if scheme in ("socks4", "socks4a"):
                ob["version"] = "4" if scheme == "socks4" else "4a"
            else:
                ob["version"] = "5"
            if user:
                ob["username"] = user
            if pwd:
                ob["password"] = pwd
            return ob

        elif lower.startswith("npvt-ssh://"):
            raw = link[11:].strip()
            decoded = safe_b64decode(raw)
            if not decoded:
                return None
            d = json.loads(decoded)
            host = str(d.get("sshHost", "") or "").strip()
            port = int(d.get("sshPort") or 22)
            user = str(d.get("sshUsername", "") or "").strip()
            password = str(d.get("sshPassword", "") or "").strip()
            if not host:
                return None
            tag = str(d.get("remarks", "") or "").strip() or (default_tag or f"SSH-{host}:{port}")
            cfg_type = str(d.get("sshConfigType", "SSH-Direct") or "SSH-Direct").strip()
            sni = str(d.get("sni", "") or "").strip()

            return {
                "type": "ssh",
                "tag": tag,
                "server": host,
                "server_port": port,
                "user": user,
                "password": password,
                "ssh_config_type": cfg_type,
                "sni": sni,
                "link": link,
            }

        elif lower.startswith("ssh://"):
            u = urllib.parse.urlparse(link)
            host = (u.hostname or "").strip()
            port = int(u.port or 22)
            if not host:
                return None
            raw_ui = _extract_raw_userinfo(link)
            if ":" in raw_ui:
                user, password = raw_ui.split(":", 1)
            else:
                user = urllib.parse.unquote(u.username or "")
                password = urllib.parse.unquote(u.password or "")
            qs = urllib.parse.parse_qs(u.query)
            tag = urllib.parse.unquote(u.fragment).strip() if u.fragment else (default_tag or f"SSH-{host}:{port}")
            ob = {
                "type": "ssh",
                "tag": tag,
                "server": host,
                "server_port": port,
                "user": user.strip(),
                "password": password.strip(),
                "link": link,
            }
            if qs.get("sshConfigType") or qs.get("cfg"):
                ob["ssh_config_type"] = urllib.parse.unquote((qs.get("sshConfigType") or qs.get("cfg"))[0]).strip()
            if qs.get("sni"):
                ob["sni"] = urllib.parse.unquote(qs["sni"][0]).strip()
            return ob
    except Exception:
        return None
    return None


_SUPPORTED_SUB_TYPES = {
    "vless", "vmess", "trojan", "shadowsocks", "ss",
    "hysteria2", "hy2", "tuic", "socks", "ssh",
}


def _is_ssl_verify_error(exc: Exception) -> bool:
    if isinstance(exc, (ssl.SSLError, ssl.CertificateError)):
        return True
    reason = getattr(exc, "reason", None)
    return isinstance(reason, (ssl.SSLError, ssl.CertificateError))


def fetch_subscription(url: str, default_name: str = "Subscription") -> List[Dict]:
    """Fetch subscription URL and decode URI lists, base64 blobs, or Sing-box JSON profiles."""
    nodes = []
    headers = {
        "User-Agent": "XHM/1.0 (Linux; Xray)",
        "Accept": "*/*",
    }
    req = urllib.request.Request(url, headers=headers)
    ctx = ssl.create_default_context()
    try:
        try:
            resp = urllib.request.urlopen(req, context=ctx, timeout=12)
        except Exception as exc:
            if not _is_ssl_verify_error(exc):
                raise
            # Personal-use convenience: allow self-signed subscription panels on TLS cert failure only.
            unverified_ctx = ssl._create_unverified_context()
            resp = urllib.request.urlopen(req, context=unverified_ctx, timeout=12)

        with resp as response:
            raw_bytes = response.read()

        # Handle gzip compressed stream
        if len(raw_bytes) > 2 and raw_bytes[:2] == b"\x1f\x8b":
            try:
                raw_bytes = gzip.decompress(raw_bytes)
            except Exception:
                pass

        content = raw_bytes.decode("utf-8", errors="ignore").strip()

        # Support Sing-box JSON subscription responses
        if content.startswith("{"):
            try:
                sb_doc = json.loads(content)
                if isinstance(sb_doc, dict) and isinstance(sb_doc.get("outbounds"), list):
                    for ob in sb_doc["outbounds"]:
                        if not isinstance(ob, dict):
                            continue
                        otype = str(ob.get("type") or "").lower()
                        if otype in ("direct", "block", "dns", "selector", "urltest"):
                            continue
                        if otype not in _SUPPORTED_SUB_TYPES or not ob.get("server"):
                            continue
                        if otype == "ss":
                            ob = {**ob, "type": "shadowsocks"}
                        elif otype == "hy2":
                            ob = {**ob, "type": "hysteria2"}
                        node = {
                            "profile_id": "subscription",
                            "profile": default_name,
                            "subscription_url": url,
                            "is_custom": False,
                            "tag": str(ob.get("tag") or f"{otype.upper()}-{ob.get('server')}:{ob.get('server_port', 0)}"),
                            "type": ob["type"],
                            "server": ob["server"],
                            "port": int(ob.get("server_port") or 0),
                            "raw": ob,
                            "ping": None,
                        }
                        node["link"] = outbound_to_link(node)
                        node["id"] = get_node_identity(node)
                        nodes.append(node)
                    return nodes
            except Exception:
                pass

        decoded_text = content
        decoded_b64 = safe_b64decode(content)
        if decoded_b64 and "://" in decoded_b64:
            decoded_text = decoded_b64

        for line in decoded_text.splitlines():
            line = line.strip()
            if not line:
                continue
            ob = parse_proxy_link(line)
            if ob:
                node = {
                    "profile_id": "subscription",
                    "profile": default_name,
                    "subscription_url": url,
                    "is_custom": False,
                    "tag": ob["tag"],
                    "type": ob["type"],
                    "server": ob["server"],
                    "port": ob["server_port"],
                    "raw": ob,
                    "link": line,
                    "ping": None,
                }
                node["id"] = get_node_identity(node)
                nodes.append(node)
    except Exception as e:
        raise RuntimeError(f"Subscription fetch error: {e}")
    return nodes


def get_node_identity(node: dict) -> str:
    """Compute a stable 16-char hex ID distinguishing credentials and transport, not just host:port."""
    if not isinstance(node, dict):
        return ""
    raw = node.get("raw") if isinstance(node.get("raw"), dict) else {}
    transport = raw.get("transport") if isinstance(raw.get("transport"), dict) else {}
    tls = raw.get("tls") if isinstance(raw.get("tls"), dict) else {}
    reality = tls.get("reality") if isinstance(tls.get("reality"), dict) else {}

    ptype = str(node.get("type") or raw.get("type") or "").lower()
    server = str(node.get("server") or raw.get("server") or "").strip().lower()
    try:
        port = int(node.get("port") or raw.get("server_port") or 0)
    except (ValueError, TypeError):
        port = 0

    user = str(raw.get("user") or raw.get("username") or node.get("user") or "")
    password = str(raw.get("password") or node.get("password") or "")
    uuid = str(raw.get("uuid") or node.get("uuid") or "")
    method = str(raw.get("method") or node.get("method") or "")
    sni = str(raw.get("sni") or tls.get("server_name") or node.get("sni") or "")
    ssh_cfg = str(raw.get("ssh_config_type") or node.get("ssh_config_type") or "")
    path = str(raw.get("path") or transport.get("path") or node.get("path") or "")
    net = str(transport.get("type") or raw.get("net") or "")
    flow = str(raw.get("flow") or "")

    parts = [ptype, server, str(port), user, password, uuid, method, sni, ssh_cfg, path, net, flow]
    extra = [
        str(transport.get("service_name") or ""),
        str((transport.get("headers") or {}).get("Host") or transport.get("host") or ""),
        str(transport.get("mode") or ""),
        str(reality.get("public_key") or ""),
        str(reality.get("short_id") or ""),
        str(raw.get("encryption") or ""),
    ]
    if any(extra):
        parts.extend(extra)
    payload = "|".join(parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def is_same_node(node_a: Optional[dict], node_b: Optional[dict]) -> bool:
    """Check whether two node dicts refer to the same logical proxy configuration."""
    if not isinstance(node_a, dict) or not isinstance(node_b, dict):
        return False
    id_a = node_a.get("id") or (get_node_identity(node_a) if node_a.get("raw") else "")
    id_b = node_b.get("id") or (get_node_identity(node_b) if node_b.get("raw") else "")
    if id_a and id_b:
        return id_a == id_b
    try:
        same_endpoint = (
            str(node_a.get("server") or "") == str(node_b.get("server") or "")
            and int(node_a.get("port") or 0) == int(node_b.get("port") or 0)
        )
    except (ValueError, TypeError):
        same_endpoint = False
    if not same_endpoint:
        return False
    type_a = str(node_a.get("type") or "").lower()
    type_b = str(node_b.get("type") or "").lower()
    if type_a and type_b and type_a != type_b:
        return False
    tag_a = str(node_a.get("tag") or "")
    tag_b = str(node_b.get("tag") or "")
    if tag_a and tag_b:
        return tag_a == tag_b
    return True


_store_lock = threading.RLock()


def _atomic_write_json(path: str, data) -> None:
    parent = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=parent, prefix=".xhm_tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError:
                pass
        os.replace(tmp_path, path)
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass
        raise


def _infer_is_custom_node(node: dict, subs: Optional[List[Dict]] = None) -> bool:
    if node.get("subscription_url") or node.get("profile_id") == "subscription":
        return False
    if isinstance(node.get("is_custom"), bool):
        return node["is_custom"]
    prof = str(node.get("profile") or "")
    if not prof or prof == "Custom":
        return True
    sub_list = subs if subs is not None else CustomConfigStore.load_subscriptions()
    sub_names = {str(s.get("name") or "") for s in sub_list if s.get("name")}
    return prof not in sub_names


def _node_belongs_to_subscription(node: dict, url: str, name: str = "") -> bool:
    if node.get("subscription_url"):
        return node.get("subscription_url") == url
    if name and not node.get("is_custom", False) and node.get("profile") == name:
        return True
    return False


# --- Custom Config Storage ---
class CustomConfigStore:
    @staticmethod
    def load_nodes() -> List[Dict]:
        """Load custom nodes from JSON store."""
        with _store_lock:
            if not os.path.exists(CUSTOM_CONFIGS_FILE):
                return []
            try:
                with open(CUSTOM_CONFIGS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return data if isinstance(data, list) else []
            except Exception:
                return []

    @staticmethod
    def save_nodes(nodes: List[Dict]):
        """Save custom nodes to JSON store atomically."""
        with _store_lock:
            _atomic_write_json(CUSTOM_CONFIGS_FILE, nodes)

    @classmethod
    def add_node_from_link(cls, link: str, custom_name: str = "", replace_id: str = "") -> Optional[Dict]:
        """Parse proxy link and save to custom configs (optionally updating an existing node by ID)."""
        ob = parse_proxy_link(link, default_tag=custom_name)
        if not ob:
            return None

        node = {
            "profile_id": "custom",
            "profile": "Custom",
            "is_custom": True,
            "tag": custom_name or ob["tag"],
            "type": ob["type"],
            "server": ob["server"],
            "port": ob["server_port"],
            "raw": ob,
            "link": link,
            "ping": None,
        }
        node["id"] = get_node_identity(node)

        with _store_lock:
            nodes = cls.load_nodes()
            insert_idx = 0
            if replace_id:
                for idx, existing in enumerate(nodes):
                    if (existing.get("id") or get_node_identity(existing)) == replace_id:
                        insert_idx = idx
                        break
            nodes = [
                n for n in nodes
                if (n.get("id") or get_node_identity(n)) not in ({node["id"], replace_id} if replace_id else {node["id"]})
            ]
            insert_idx = min(insert_idx, len(nodes))
            nodes.insert(insert_idx, node)
            cls.save_nodes(nodes)
        return node

    @classmethod
    def add_multiple_nodes(cls, new_nodes: List[Dict]) -> int:
        """Batch append multiple nodes without duplicating exact IDs."""
        with _store_lock:
            existing = cls.load_nodes()
            seen = {n.get("id") or get_node_identity(n) for n in existing}
            added = 0
            for n in new_nodes:
                nid = n.get("id") or get_node_identity(n)
                n["id"] = nid
                if nid not in seen:
                    existing.append(n)
                    seen.add(nid)
                    added += 1
            cls.save_nodes(existing)
            return added

    @classmethod
    def _sync_subscription_nodes(cls, url: str, name: str, fresh_nodes: List[Dict]) -> Tuple[int, int]:
        """Replace a subscription's nodes cleanly while preserving custom nodes & ping caches."""
        with _store_lock:
            existing = cls.load_nodes()
            old_pings = {}
            kept = []
            for n in existing:
                nid = n.get("id") or get_node_identity(n)
                if _node_belongs_to_subscription(n, url, name):
                    if n.get("ping") is not None:
                        old_pings[nid] = n.get("ping")
                else:
                    kept.append(n)

            seen = {n.get("id") or get_node_identity(n) for n in kept}
            added_list = []
            new_count = 0
            for n in fresh_nodes:
                nid = n.get("id") or get_node_identity(n)
                n["id"] = nid
                n["profile_id"] = "subscription"
                n["profile"] = name
                n["subscription_url"] = url
                n["is_custom"] = False
                if n.get("ping") is None and nid in old_pings:
                    n["ping"] = old_pings[nid]
                if nid not in old_pings:
                    new_count += 1
                if nid not in seen:
                    seen.add(nid)
                    added_list.append(n)

            cls.save_nodes(kept + added_list)
            return len(added_list), new_count

    @classmethod
    def delete_node(cls, server: str, port: int, ptype: str, node_id: str = "") -> bool:
        """Delete a node by unique ID, falling back to (server, port, type)."""
        with _store_lock:
            nodes = cls.load_nodes()
            initial_len = len(nodes)
            if node_id:
                nodes = [n for n in nodes if (n.get("id") or get_node_identity(n)) != node_id]
            else:
                nodes = [n for n in nodes if not (n.get("server") == server and int(n.get("port", 0)) == int(port) and n.get("type", "").lower() == ptype.lower())]
            if len(nodes) < initial_len:
                cls.save_nodes(nodes)
                return True
            return False

    @classmethod
    def clear_all_nodes(cls) -> bool:
        """Clear manual/custom nodes while preserving subscription-managed nodes."""
        with _store_lock:
            subs = cls.load_subscriptions()
            nodes = cls.load_nodes()
            remaining = [n for n in nodes if not _infer_is_custom_node(n, subs)]
            cls.save_nodes(remaining)
            return True

    @staticmethod
    def load_subscriptions() -> List[Dict]:
        """Load saved subscription URLs."""
        with _store_lock:
            if not os.path.exists(SUBSCRIPTIONS_FILE):
                return []
            try:
                with open(SUBSCRIPTIONS_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return data if isinstance(data, list) else []
            except Exception:
                return []

    @staticmethod
    def save_subscriptions(subs: List[Dict]):
        """Save subscription URLs atomically."""
        with _store_lock:
            _atomic_write_json(SUBSCRIPTIONS_FILE, subs)

    @classmethod
    def add_subscription(cls, url: str, name: str = "") -> Tuple[int, str]:
        """Fetch subscription, sync its proxies, and save URL for future updates."""
        url = (url or "").strip()
        with _store_lock:
            subs = cls.load_subscriptions()
            existing_sub = next((s for s in subs if s.get("url") == url), None)
            if not name:
                if existing_sub and existing_sub.get("name"):
                    name = existing_sub["name"]
                else:
                    used_names = {str(s.get("name") or "") for s in subs}
                    idx = len(subs) + 1
                    while f"Subscription {idx}" in used_names:
                        idx += 1
                    name = f"Subscription {idx}"

        nodes = fetch_subscription(url, default_name=name)
        if not nodes:
            return 0, "No valid proxies found in this subscription."

        with _store_lock:
            total_synced, new_count = cls._sync_subscription_nodes(url, name, nodes)
            subs = cls.load_subscriptions()
            subs = [s for s in subs if s.get("url") != url]
            subs.append({
                "url": url,
                "name": name,
                "count": total_synced,
                "updated_at": time.strftime("%Y-%m-%d %H:%M"),
            })
            cls.save_subscriptions(subs)
        return total_synced, f"Successfully imported {total_synced} nodes ({new_count} new)."

    @classmethod
    def delete_subscription(cls, url: str) -> bool:
        """Delete a saved subscription and prune its synced nodes."""
        with _store_lock:
            subs = cls.load_subscriptions()
            target = next((s for s in subs if s.get("url") == url), None)
            if not target:
                return False
            sub_name = str(target.get("name") or "")
            subs = [s for s in subs if s.get("url") != url]
            cls.save_subscriptions(subs)

            nodes = cls.load_nodes()
            kept = [n for n in nodes if not _node_belongs_to_subscription(n, url, sub_name)]
            if len(kept) != len(nodes):
                cls.save_nodes(kept)
            return True

    @classmethod
    def update_all_subscriptions(cls) -> Tuple[int, str]:
        """Re-fetch all saved subscriptions, syncing additions, updates, and removals."""
        with _store_lock:
            subs = cls.load_subscriptions()
        if not subs:
            return 0, "No subscriptions saved."

        total_synced = 0
        total_new = 0
        failed = 0
        updated_subs = []
        for s in subs:
            url = s.get("url")
            name = s.get("name") or "Subscription"
            if not url:
                continue
            try:
                nodes = fetch_subscription(url, default_name=name)
                if nodes:
                    synced_cnt, new_cnt = cls._sync_subscription_nodes(url, name, nodes)
                    total_synced += synced_cnt
                    total_new += new_cnt
                    s["count"] = synced_cnt
                    s["updated_at"] = time.strftime("%Y-%m-%d %H:%M")
                else:
                    failed += 1
            except Exception:
                failed += 1
            updated_subs.append(s)

        with _store_lock:
            cls.save_subscriptions(updated_subs)

        msg = f"Updated {len(updated_subs)} subscriptions ({total_synced} active, {total_new} new)."
        if failed:
            msg += f" {failed} failed (cached nodes preserved)."
        return total_synced, msg


def _serialize_transport_params(params: dict, tp: dict) -> None:
    net = (tp.get("type") or "").strip().lower()
    if not net:
        return
    params["type"] = net
    if net in ("ws", "httpupgrade", "xhttp", "splithttp"):
        if tp.get("path"):
            params["path"] = tp["path"]
        host_hdr = (tp.get("headers") or {}).get("Host") or tp.get("host")
        if host_hdr:
            params["host"] = host_hdr if isinstance(host_hdr, str) else ",".join(host_hdr)
        if net in ("xhttp", "splithttp") and tp.get("mode"):
            params["mode"] = tp["mode"]
    elif net == "grpc":
        if tp.get("service_name"):
            params["serviceName"] = tp["service_name"]
        if tp.get("mode"):
            params["mode"] = tp["mode"]
    elif net in ("http", "h2"):
        if tp.get("path"):
            params["path"] = tp["path"]
        if tp.get("host"):
            params["host"] = ",".join(tp["host"]) if isinstance(tp["host"], list) else tp["host"]
    elif net == "tcp" and tp.get("header_type") == "http":
        params["headerType"] = "http"
        if (tp.get("headers") or {}).get("Host"):
            params["host"] = tp["headers"]["Host"]
        if tp.get("path"):
            params["path"] = tp["path"]


def outbound_to_link(node: dict) -> str:
    """Generate a shareable proxy URI link from a node dictionary if not present."""
    existing = node.get("link")
    if existing:
        return existing

    t = (node.get("type") or "").lower()
    raw = node.get("raw") if isinstance(node.get("raw"), dict) else node
    srv = _format_host_for_uri(node.get("server") or raw.get("server", ""))
    prt = node.get("port") or raw.get("server_port", 0)
    tag = node.get("tag") or node.get("server") or srv
    quoted_tag = urllib.parse.quote(str(tag), safe="")

    if t == "ssh":
        user = urllib.parse.quote(str(raw.get("user", "")), safe="")
        pw = urllib.parse.quote(str(raw.get("password", "")), safe="")
        auth = f"{user}:{pw}@" if (user or pw) else ""
        params = {}
        cfg_type = raw.get("ssh_config_type")
        if cfg_type and cfg_type != "SSH-Direct":
            params["sshConfigType"] = cfg_type
        if raw.get("sni"):
            params["sni"] = raw["sni"]
        q = ("?" + urllib.parse.urlencode(params)) if params else ""
        return f"ssh://{auth}{srv}:{prt}{q}#{quoted_tag}"

    elif t == "trojan":
        pw = urllib.parse.quote(str(raw.get("password", "")), safe="")
        params = {}
        tls = raw.get("tls") or {}
        if tls.get("enabled"):
            reality = tls.get("reality") or {}
            if reality.get("enabled"):
                params["security"] = "reality"
                if reality.get("public_key"):
                    params["pbk"] = reality["public_key"]
                if reality.get("short_id"):
                    params["sid"] = reality["short_id"]
                if reality.get("spider_x"):
                    params["spx"] = reality["spider_x"]
            else:
                params["security"] = "tls"
            if tls.get("server_name"):
                params["sni"] = tls["server_name"]
            if tls.get("utls", {}).get("fingerprint"):
                params["fp"] = tls["utls"]["fingerprint"]
            if tls.get("alpn"):
                params["alpn"] = ",".join(tls["alpn"])
            if tls.get("insecure"):
                params["allowInsecure"] = "1"
        elif tls:
            params["security"] = "none"
        _serialize_transport_params(params, raw.get("transport") or {})
        q = ("?" + urllib.parse.urlencode(params)) if params else ""
        return f"trojan://{pw}@{srv}:{prt}{q}#{quoted_tag}"

    elif t == "vless":
        uuid = urllib.parse.quote(str(raw.get("uuid", "")), safe="")
        params = {"encryption": raw.get("encryption") or "none"}
        tls = raw.get("tls") or {}
        if tls.get("enabled"):
            reality = tls.get("reality") or {}
            if reality.get("enabled"):
                params["security"] = "reality"
                if reality.get("public_key"):
                    params["pbk"] = reality["public_key"]
                if reality.get("short_id"):
                    params["sid"] = reality["short_id"]
                if reality.get("spider_x"):
                    params["spx"] = reality["spider_x"]
            else:
                params["security"] = "tls"
            if tls.get("server_name"):
                params["sni"] = tls["server_name"]
            if tls.get("utls", {}).get("fingerprint"):
                params["fp"] = tls["utls"]["fingerprint"]
            if tls.get("alpn"):
                params["alpn"] = ",".join(tls["alpn"])
            if tls.get("insecure"):
                params["allowInsecure"] = "1"
        else:
            params["security"] = "none"
        _serialize_transport_params(params, raw.get("transport") or {})
        flow = raw.get("flow")
        if flow:
            params["flow"] = flow
        q = "?" + urllib.parse.urlencode(params)
        return f"vless://{uuid}@{srv}:{prt}{q}#{quoted_tag}"

    elif t == "vmess":
        uuid = raw.get("uuid", "")
        tp = raw.get("transport") or {}
        tls = raw.get("tls") or {}
        net = tp.get("type", "tcp")
        vmess_dict = {
            "v": "2",
            "ps": str(tag),
            "add": node.get("server") or raw.get("server", ""),
            "port": prt,
            "id": uuid,
            "aid": raw.get("alter_id", 0),
            "scy": raw.get("security", "auto"),
            "net": net,
            "type": tp.get("header_type") or "none",
            "host": (tp.get("headers") or {}).get("Host") or (",".join(tp["host"]) if isinstance(tp.get("host"), list) else tp.get("host", "")),
            "path": tp.get("service_name") if net == "grpc" else tp.get("path", ""),
            "tls": "tls" if tls.get("enabled") else "",
            "sni": tls.get("server_name", ""),
        }
        if tls.get("utls", {}).get("fingerprint"):
            vmess_dict["fp"] = tls["utls"]["fingerprint"]
        if tls.get("alpn"):
            vmess_dict["alpn"] = ",".join(tls["alpn"])
        if tls.get("insecure"):
            vmess_dict["allowInsecure"] = 1
        b64 = base64.b64encode(json.dumps(vmess_dict).encode("utf-8")).decode("utf-8")
        return f"vmess://{b64}"

    elif t in ("shadowsocks", "ss"):
        method = raw.get("method", "")
        pw = raw.get("password", "")
        userinfo = base64.urlsafe_b64encode(f"{method}:{pw}".encode("utf-8")).decode("utf-8").rstrip("=")
        plugin_str = raw.get("plugin") or ""
        if plugin_str and raw.get("plugin_opts") and ";" not in plugin_str:
            plugin_str = f"{plugin_str};{raw['plugin_opts']}"
        q = ("?" + urllib.parse.urlencode({"plugin": plugin_str})) if plugin_str else ""
        return f"ss://{userinfo}@{srv}:{prt}{q}#{quoted_tag}"

    elif t in ("hysteria2", "hy2"):
        pw = urllib.parse.quote(str(raw.get("password", "")), safe="")
        params = {}
        tls = raw.get("tls") or {}
        if tls.get("server_name"):
            params["sni"] = tls["server_name"]
        if tls.get("insecure"):
            params["insecure"] = "1"
        if tls.get("alpn"):
            params["alpn"] = ",".join(tls["alpn"])
        if raw.get("pin_sha256"):
            params["pinSHA256"] = raw["pin_sha256"]
        obfs = raw.get("obfs") or {}
        if obfs.get("type"):
            params["obfs"] = obfs["type"]
            if obfs.get("password"):
                params["obfs-password"] = obfs["password"]
        if raw.get("up_mbps"):
            params["upmbps"] = str(raw["up_mbps"])
        if raw.get("down_mbps"):
            params["downmbps"] = str(raw["down_mbps"])
        q = ("?" + urllib.parse.urlencode(params)) if params else ""
        return f"hy2://{pw}@{srv}:{prt}{q}#{quoted_tag}"

    elif t == "tuic":
        uuid = urllib.parse.quote(str(raw.get("uuid", "")), safe="")
        pw = urllib.parse.quote(str(raw.get("password", "")), safe="")
        params = {}
        tls = raw.get("tls") or {}
        if tls.get("server_name"):
            params["sni"] = tls["server_name"]
        if tls.get("insecure"):
            params["allowInsecure"] = "1"
        if tls.get("alpn"):
            params["alpn"] = ",".join(tls["alpn"])
        if raw.get("congestion_control"):
            params["congestion_control"] = raw["congestion_control"]
        if raw.get("udp_relay_mode"):
            params["udp_relay_mode"] = raw["udp_relay_mode"]
        q = ("?" + urllib.parse.urlencode(params)) if params else ""
        return f"tuic://{uuid}:{pw}@{srv}:{prt}{q}#{quoted_tag}"

    elif t == "socks":
        user = urllib.parse.quote(str(raw.get("username") or raw.get("user") or ""), safe="")
        pw = urllib.parse.quote(str(raw.get("password", "")), safe="")
        auth = f"{user}:{pw}@" if (user or pw) else ""
        ver = str(raw.get("version") or "5")
        scheme = "socks4a" if ver == "4a" else ("socks4" if ver == "4" else "socks5")
        return f"{scheme}://{auth}{srv}:{prt}#{quoted_tag}"

    return ""


# --- Node Loader ---
def load_all_nodes() -> List[Dict]:
    """Extract valid proxy nodes from custom configs and subscriptions."""
    nodes = []
    seen_ids = set()
    subs = CustomConfigStore.load_subscriptions()

    custom_nodes = CustomConfigStore.load_nodes()
    for cn in custom_nodes:
        nid = cn.get("id") or get_node_identity(cn)
        if nid not in seen_ids:
            seen_ids.add(nid)
            cn["id"] = nid
            cn["is_custom"] = _infer_is_custom_node(cn, subs)
            if not cn.get("link"):
                cn["link"] = outbound_to_link(cn)
            nodes.append(cn)

    return nodes


# --- Proxy Config Builders & Converters ---
def _find_xray_asset_file(filename: str) -> Optional[str]:
    candidates = []
    if XRAY_BIN:
        candidates.append(os.path.join(os.path.dirname(os.path.abspath(XRAY_BIN)), filename))
    env_asset = os.environ.get("XRAY_LOCATION_ASSET")
    if env_asset:
        candidates.append(os.path.join(env_asset, filename))
    candidates.extend([
        os.path.expanduser(f"~/.local/share/xray/{filename}"),
        f"/usr/local/share/xray/{filename}",
        f"/usr/share/xray/{filename}",
    ])
    for p in candidates:
        if os.path.isfile(p):
            return p
    return None


def singbox_to_xray_outbound(sb: dict) -> dict:
    """Converts a sing-box outbound to an Xray compatible outbound."""
    t = sb.get("type", "").lower()
    server = sb.get("server")
    port = int(sb.get("server_port", 443))

    outbound = {
        "tag": sb.get("tag", "proxy"),
        "protocol": t,
        "settings": {},
        "streamSettings": {
            "network": "tcp",
            "security": "none",
        },
    }

    transport = sb.get("transport", {})
    tr_type = (transport.get("type") or "").lower()

    tls_cfg = sb.get("tls") if isinstance(sb.get("tls"), dict) else {}
    has_explicit_tls = "enabled" in tls_cfg
    is_tls = bool(tls_cfg.get("enabled")) if has_explicit_tls else (t == "trojan")
    reality_cfg = tls_cfg.get("reality", {}) if isinstance(tls_cfg.get("reality"), dict) else {}
    is_reality = bool(reality_cfg.get("enabled"))

    # Security: Reality, TLS, or None (never force TLS solely by port number)
    if is_reality:
        outbound["streamSettings"]["security"] = "reality"
        sni = tls_cfg.get("server_name") or transport.get("host") or server
        reality_settings = {
            "serverName": sni,
            "fingerprint": tls_cfg.get("utls", {}).get("fingerprint") or "chrome",
            "publicKey": reality_cfg.get("public_key", ""),
            "shortId": reality_cfg.get("short_id", ""),
            "show": False,
        }
        if reality_cfg.get("spider_x"):
            reality_settings["spiderX"] = reality_cfg.get("spider_x")
        outbound["streamSettings"]["realitySettings"] = reality_settings
    elif is_tls:
        outbound["streamSettings"]["security"] = "tls"
        sni = tls_cfg.get("server_name") or transport.get("host") or server
        tls_settings = {
            "serverName": sni,
            "fingerprint": tls_cfg.get("utls", {}).get("fingerprint") or "chrome",
        }
        if tls_cfg.get("alpn"):
            tls_settings["alpn"] = tls_cfg.get("alpn")
        if tls_cfg.get("insecure"):
            tls_settings["allowInsecure"] = True
        outbound["streamSettings"]["tlsSettings"] = tls_settings
    else:
        outbound["streamSettings"]["security"] = "none"

    if tr_type:
        if tr_type == "ws":
            outbound["streamSettings"]["network"] = "ws"
            ws_headers = transport.get("headers", {})
            host_hdr = ws_headers.get("Host", "") or transport.get("host", "")
            outbound["streamSettings"]["wsSettings"] = {
                "path": transport.get("path", "/"),
                "headers": {"Host": host_hdr} if host_hdr else {},
            }
        elif tr_type == "httpupgrade":
            outbound["streamSettings"]["network"] = "httpupgrade"
            hu_headers = transport.get("headers", {})
            host_hdr = hu_headers.get("Host", "") or transport.get("host", "")
            hu_settings = {"path": transport.get("path", "/")}
            if host_hdr:
                hu_settings["host"] = host_hdr
            outbound["streamSettings"]["httpupgradeSettings"] = hu_settings
        elif tr_type == "grpc":
            outbound["streamSettings"]["network"] = "grpc"
            grpc_cfg = {"serviceName": transport.get("service_name", "")}
            if str(transport.get("mode") or "").lower() == "multi":
                grpc_cfg["multiMode"] = True
            outbound["streamSettings"]["grpcSettings"] = grpc_cfg
        elif tr_type in ("xhttp", "splithttp"):
            outbound["streamSettings"]["network"] = "xhttp"
            host_hdr = transport.get("host", "") or (transport.get("headers") or {}).get("Host", "")
            outbound["streamSettings"]["xhttpSettings"] = {
                "mode": transport.get("mode", "auto"),
                "host": host_hdr,
                "path": transport.get("path", "/"),
            }
        elif tr_type in ("http", "h2"):
            host_val = transport.get("host", "")
            hosts = host_val if isinstance(host_val, list) else ([host_val] if host_val else [])
            outbound["streamSettings"]["network"] = "tcp" if tr_type == "http" else "xhttp"
            outbound["streamSettings"]["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "version": "1.1",
                        "method": transport.get("method", "GET"),
                        "path": [transport.get("path", "/")],
                        "headers": {"Host": hosts} if hosts else {},
                    },
                }
            }
        elif tr_type == "tcp" and transport.get("header_type") == "http":
            host_hdr = (transport.get("headers") or {}).get("Host", "") or transport.get("host", "")
            outbound["streamSettings"]["network"] = "tcp"
            outbound["streamSettings"]["tcpSettings"] = {
                "header": {
                    "type": "http",
                    "request": {
                        "version": "1.1",
                        "method": "GET",
                        "path": [transport.get("path", "/")],
                        "headers": {"Host": [host_hdr]} if host_hdr else {},
                    },
                }
            }

    if t == "trojan":
        outbound["settings"] = {
            "servers": [{
                "address": server,
                "port": port,
                "password": sb.get("password", ""),
            }]
        }
    elif t == "vmess":
        outbound["settings"] = {
            "vnext": [{
                "address": server,
                "port": port,
                "users": [{
                    "id": sb.get("uuid", ""),
                    "alterId": int(sb.get("alter_id", 0)),
                    "security": sb.get("security", "auto"),
                }],
            }]
        }
    elif t == "vless":
        outbound["settings"] = {
            "vnext": [{
                "address": server,
                "port": port,
                "users": [{
                    "id": sb.get("uuid", ""),
                    "encryption": sb.get("encryption") or "none",
                    "flow": sb.get("flow", ""),
                }],
            }]
        }
    elif t == "shadowsocks":
        outbound["settings"] = {
            "servers": [{
                "address": server,
                "port": port,
                "method": sb.get("method", ""),
                "password": sb.get("password", ""),
            }]
        }
    elif t == "socks":
        user = sb.get("username") or sb.get("user") or ""
        pw = sb.get("password") or ""
        users = [{"user": user, "pass": pw}] if (user or pw) else []
        outbound["settings"] = {
            "servers": [{
                "address": server,
                "port": port,
                "users": users,
            }]
        }

    return outbound


def build_singbox_run_config(node_raw: dict, proxy_port: int, api_port: int, allow_lan: bool = False) -> dict:
    """Build complete runnable sing-box config for Sing-box core with DNS and internal network bypass."""
    listen_addr = "0.0.0.0" if allow_lan else "127.0.0.1"
    tag = node_raw.get("tag") or "proxy"
    raw_copy = dict(node_raw)

    # Clean out internal XHM metadata before passing outbound to sing-box
    for k in ("link", "ping", "profile", "profile_id", "subscription_url", "is_custom", "id", "ssh_config_type", "sni"):
        raw_copy.pop(k, None)

    _, phys_iface = get_physical_interface()
    if raw_copy.get("type") == "ssh":
        clean_outbound = {
            "type": "ssh",
            "tag": tag,
            "server": raw_copy.get("server"),
            "server_port": int(raw_copy.get("server_port") or raw_copy.get("port") or 22),
            "user": raw_copy.get("user", ""),
            "password": raw_copy.get("password", ""),
        }
    else:
        clean_outbound = raw_copy
        clean_outbound["tag"] = tag
        if clean_outbound.get("type") == "hy2":
            clean_outbound["type"] = "hysteria2"
        if clean_outbound.get("type") == "ss":
            clean_outbound["type"] = "shadowsocks"

    if phys_iface and not clean_outbound.get("bind_interface"):
        clean_outbound["bind_interface"] = phys_iface

    direct_ob = {"type": "direct", "tag": "direct"}
    if phys_iface:
        direct_ob["bind_interface"] = phys_iface

    return {
        "log": {"level": "warn"},
        "dns": {
            "servers": [
                {
                    "type": "https",
                    "tag": "dns-remote",
                    "server": "8.8.8.8",
                    "detour": tag,
                },
                {
                    "type": "udp",
                    "tag": "dns-direct",
                    "server": "1.1.1.1",
                    "detour": "direct",
                },
            ],
            "rules": [
                {
                    "domain_suffix": [".ir", "localhost", ".local", "local"],
                    "server": "dns-direct",
                },
            ],
            "strategy": "prefer_ipv4",
            "final": "dns-remote",
        },
        "inbounds": [
            {
                "type": "mixed",
                "tag": "mixed-in",
                "listen": listen_addr,
                "listen_port": proxy_port,
            },
            {
                "type": "http",
                "tag": "http-in",
                "listen": listen_addr,
                "listen_port": proxy_port + 1,
            }
        ],
        "outbounds": [
            clean_outbound,
            direct_ob,
            {"type": "direct", "tag": "direct-local"},
            {"type": "block", "tag": "block"},
        ],
        "route": {
            "default_domain_resolver": "dns-direct",
            "rules": [
                {"action": "sniff"},
                {"protocol": "dns", "action": "hijack-dns"},
                {"ip_is_private": True, "outbound": "direct-local"},
                {"domain_suffix": [".ir", "localhost", ".local", "local"], "outbound": "direct"},
            ],
            "final": tag,
            "auto_detect_interface": True,
        },
        "experimental": {
            "clash_api": {
                "external_controller": f"127.0.0.1:{api_port}",
            }
        },
    }


def build_xray_config(outbound: dict, proxy_port: int, api_port: int, allow_lan: bool = False, domain_strategy: str = "IPIfNonMatch") -> dict:
    """Build complete runnable Xray config with stats API, leak-free DNS, and internal network bypass."""
    listen_addr = "0.0.0.0" if allow_lan else "127.0.0.1"
    is_ssh = outbound.get("tag") == "ssh-tunnel"
    strategy = "AsIs" if is_ssh else domain_strategy
    _, phys_iface = get_physical_interface()

    outbound_copy = dict(outbound)
    if phys_iface and not is_ssh:
        stream_settings = dict(outbound_copy.get("streamSettings") or {})
        sockopt = dict(stream_settings.get("sockopt") or {})
        if not sockopt.get("interface"):
            sockopt["interface"] = phys_iface
        stream_settings["sockopt"] = sockopt
        outbound_copy["streamSettings"] = stream_settings

    direct_ob = {"tag": "direct", "protocol": "freedom"}
    direct_local_ob = {"tag": "direct-local", "protocol": "freedom"}
    if phys_iface:
        direct_ob["streamSettings"] = {"sockopt": {"interface": phys_iface}}

    routing_rules = [
        {
            "inboundTag": ["api"],
            "outboundTag": "api",
            "type": "field",
        },
        {
            "type": "field",
            "ip": [
                "127.0.0.0/8",
                "::1/128",
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "fc00::/7",
                "fe80::/10",
            ],
            "outboundTag": "direct-local",
        },
        {
            "type": "field",
            "domain": ["domain:.ir", "localhost"],
            "outboundTag": "direct",
        },
    ]
    if not is_ssh and _find_xray_asset_file("geoip.dat"):
        routing_rules.append({
            "type": "field",
            "ip": ["geoip:private"],
            "outboundTag": "direct-local",
        })

    return {
        "log": {"loglevel": "warning"},
        "api": {
            "tag": "api",
            "services": ["StatsService"],
        },
        "stats": {},
        "policy": {
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
            }
        },
        "dns": {
            "servers": [
                {
                    "address": "localhost",
                    "domains": ["domain:.ir", "localhost"],
                },
                "https://1.1.1.1/dns-query",
                "8.8.8.8",
            ]
        },
        "inbounds": [
            {
                "tag": "mixed",
                "port": proxy_port,
                "listen": listen_addr,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            },
            {
                "tag": "http-in",
                "port": proxy_port + 1,
                "listen": listen_addr,
                "protocol": "http",
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
            },
            {
                "tag": "api",
                "port": api_port,
                "listen": "127.0.0.1",
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
            },
        ],
        "outbounds": [
            outbound_copy,
            direct_ob,
            direct_local_ob,
        ],
        "routing": {
            "domainStrategy": strategy,
            "rules": routing_rules,
        },
    }


# --- Persistent Traffic & Bandwidth Tracker (SQLite) ---
class TrafficTracker:
    _lock = threading.Lock()
    _db_initialized = False

    @classmethod
    def get_db(cls):
        conn = sqlite3.connect(TRAFFIC_DB_FILE, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    @classmethod
    @contextlib.contextmanager
    def db_session(cls):
        conn = cls.get_db()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @classmethod
    def init_db(cls):
        if cls._db_initialized:
            return
        with cls._lock:
            if cls._db_initialized:
                return
            with cls.db_session() as conn:
                try:
                    conn.execute("PRAGMA journal_mode=WAL;")
                    conn.execute("PRAGMA synchronous=NORMAL;")
                except Exception:
                    pass
                conn.execute("""
                CREATE TABLE IF NOT EXISTS traffic_hourly (
                    node_key TEXT NOT NULL,
                    node_tag TEXT NOT NULL,
                    timestamp_hour TEXT NOT NULL,
                    year INTEGER NOT NULL,
                    month TEXT NOT NULL,
                    day TEXT NOT NULL,
                    hour INTEGER NOT NULL,
                    down_bytes INTEGER DEFAULT 0,
                    up_bytes INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0,
                    PRIMARY KEY (node_key, timestamp_hour)
                );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_day ON traffic_hourly(node_key, day);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_month ON traffic_hourly(node_key, month);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_traffic_year ON traffic_hourly(node_key, year);")

                conn.execute("""
                CREATE TABLE IF NOT EXISTS connection_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    node_key TEXT NOT NULL,
                    node_tag TEXT NOT NULL,
                    node_server TEXT NOT NULL,
                    node_port INTEGER NOT NULL,
                    node_type TEXT NOT NULL,
                    start_time REAL NOT NULL,
                    end_time REAL,
                    duration INTEGER DEFAULT 0,
                    down_bytes INTEGER DEFAULT 0,
                    up_bytes INTEGER DEFAULT 0,
                    total_bytes INTEGER DEFAULT 0
                );
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_node ON connection_sessions(node_key);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_sessions_start ON connection_sessions(start_time DESC);")
            cls._db_initialized = True

    @classmethod
    def get_session_traffic(cls, session_id: Optional[int]) -> Tuple[int, int]:
        if not session_id:
            return 0, 0
        cls.init_db()
        with cls.db_session() as conn:
            row = conn.execute(
                "SELECT down_bytes, up_bytes FROM connection_sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
            if row:
                return int(row["down_bytes"] or 0), int(row["up_bytes"] or 0)
        return 0, 0

    @classmethod
    def session_exists(cls, session_id: Optional[int]) -> bool:
        if not session_id:
            return False
        cls.init_db()
        with cls.db_session() as conn:
            row = conn.execute(
                "SELECT 1 FROM connection_sessions WHERE id = ?",
                (session_id,),
            ).fetchone()
            return row is not None

    @classmethod
    def start_session(cls, node: dict) -> int:
        cls.init_db()
        srv = str(node.get("server") or "")
        prt = int(node.get("port") or 0)
        ptype = str(node.get("type") or "vless").lower()
        tag = str(node.get("tag") or srv)
        node_key = f"{srv}:{prt}:{ptype}"
        now = time.time()

        with cls._lock:
            with cls.db_session() as conn:
                cur = conn.execute("""
                INSERT INTO connection_sessions (node_key, node_tag, node_server, node_port, node_type, start_time)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (node_key, tag, srv, prt, ptype, now))
                return cur.lastrowid

    @classmethod
    def record_traffic(cls, node_key: str, node_tag: str, delta_down: int, delta_up: int, session_id: Optional[int] = None):
        if delta_down <= 0 and delta_up <= 0:
            return
        cls.init_db()
        now = datetime.datetime.now()
        ts_hour = now.strftime("%Y-%m-%d %H:00")
        year = now.year
        month = now.strftime("%Y-%m")
        day = now.strftime("%Y-%m-%d")
        hour = now.hour
        delta_total = delta_down + delta_up

        with cls._lock:
            with cls.db_session() as conn:
                # 1. Update hourly bucket for specific node
                conn.execute("""
                INSERT INTO traffic_hourly (node_key, node_tag, timestamp_hour, year, month, day, hour, down_bytes, up_bytes, total_bytes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_key, timestamp_hour) DO UPDATE SET
                    down_bytes = down_bytes + excluded.down_bytes,
                    up_bytes = up_bytes + excluded.up_bytes,
                    total_bytes = total_bytes + excluded.total_bytes,
                    node_tag = excluded.node_tag;
                """, (node_key, node_tag, ts_hour, year, month, day, hour, delta_down, delta_up, delta_total))

                # 2. Update hourly bucket for global (__GLOBAL__)
                conn.execute("""
                INSERT INTO traffic_hourly (node_key, node_tag, timestamp_hour, year, month, day, hour, down_bytes, up_bytes, total_bytes)
                VALUES ('__GLOBAL__', 'All Nodes', ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_key, timestamp_hour) DO UPDATE SET
                    down_bytes = down_bytes + excluded.down_bytes,
                    up_bytes = up_bytes + excluded.up_bytes,
                    total_bytes = total_bytes + excluded.total_bytes;
                """, (ts_hour, year, month, day, hour, delta_down, delta_up, delta_total))

                # 3. Update session if active
                if session_id:
                    conn.execute("""
                    UPDATE connection_sessions SET
                        down_bytes = down_bytes + ?,
                        up_bytes = up_bytes + ?,
                        total_bytes = total_bytes + ?,
                        duration = CAST((? - start_time) AS INTEGER),
                        end_time = ?
                    WHERE id = ?;
                    """, (delta_down, delta_up, delta_total, now.timestamp(), now.timestamp(), session_id))

    @classmethod
    def end_session(cls, session_id: Optional[int], final_down: int = 0, final_up: int = 0):
        if not session_id:
            return
        cls.init_db()
        now = time.time()
        with cls._lock:
            with cls.db_session() as conn:
                row = conn.execute("SELECT start_time, down_bytes, up_bytes FROM connection_sessions WHERE id = ?", (session_id,)).fetchone()
                if row:
                    st = row["start_time"]
                    dur = max(0, int(now - st))
                    down_b = max(row["down_bytes"] or 0, final_down)
                    up_b = max(row["up_bytes"] or 0, final_up)
                    conn.execute("""
                    UPDATE connection_sessions SET
                        end_time = ?,
                        duration = ?,
                        down_bytes = ?,
                        up_bytes = ?,
                        total_bytes = ?
                    WHERE id = ?
                    """, (now, dur, down_b, up_b, down_b + up_b, session_id))

    @classmethod
    def get_summary(cls, node_key: Optional[str] = None) -> dict:
        cls.init_db()
        target_key = node_key if node_key else "__GLOBAL__"
        now = datetime.datetime.now()
        today_str = now.strftime("%Y-%m-%d")
        month_str = now.strftime("%Y-%m")
        year_val = now.year

        with cls.db_session() as conn:
            # Today
            r_today = conn.execute("""
            SELECT COALESCE(SUM(down_bytes), 0) AS down, COALESCE(SUM(up_bytes), 0) AS up, COALESCE(SUM(total_bytes), 0) AS total
            FROM traffic_hourly WHERE node_key = ? AND day = ?
            """, (target_key, today_str)).fetchone()

            # Month
            r_month = conn.execute("""
            SELECT COALESCE(SUM(down_bytes), 0) AS down, COALESCE(SUM(up_bytes), 0) AS up, COALESCE(SUM(total_bytes), 0) AS total
            FROM traffic_hourly WHERE node_key = ? AND month = ?
            """, (target_key, month_str)).fetchone()

            # Year
            r_year = conn.execute("""
            SELECT COALESCE(SUM(down_bytes), 0) AS down, COALESCE(SUM(up_bytes), 0) AS up, COALESCE(SUM(total_bytes), 0) AS total
            FROM traffic_hourly WHERE node_key = ? AND year = ?
            """, (target_key, year_val)).fetchone()

            # All time
            r_all = conn.execute("""
            SELECT COALESCE(SUM(down_bytes), 0) AS down, COALESCE(SUM(up_bytes), 0) AS up, COALESCE(SUM(total_bytes), 0) AS total
            FROM traffic_hourly WHERE node_key = ?
            """, (target_key,)).fetchone()

            # Session count & latest session
            if node_key and node_key != "__GLOBAL__":
                s_count = conn.execute("SELECT COUNT(*) AS c FROM connection_sessions WHERE node_key = ?", (node_key,)).fetchone()["c"]
                r_latest = conn.execute("SELECT * FROM connection_sessions WHERE node_key = ? ORDER BY id DESC LIMIT 1", (node_key,)).fetchone()
            else:
                s_count = conn.execute("SELECT COUNT(*) AS c FROM connection_sessions").fetchone()["c"]
                r_latest = conn.execute("SELECT * FROM connection_sessions ORDER BY id DESC LIMIT 1").fetchone()

        def pack(row):
            d = row["down"] if row else 0
            u = row["up"] if row else 0
            t = row["total"] if row else 0
            return {
                "down_bytes": d,
                "up_bytes": u,
                "total_bytes": t,
                "down_fmt": format_bytes(d),
                "up_fmt": format_bytes(u),
                "total_fmt": format_bytes(t),
            }

        latest_sess = None
        if r_latest:
            latest_sess = {
                "id": r_latest["id"],
                "node_key": r_latest["node_key"],
                "node_tag": r_latest["node_tag"],
                "start_time": r_latest["start_time"],
                "duration": r_latest["duration"],
                "down_bytes": r_latest["down_bytes"],
                "up_bytes": r_latest["up_bytes"],
                "total_bytes": r_latest["total_bytes"],
                "down_fmt": format_bytes(r_latest["down_bytes"]),
                "up_fmt": format_bytes(r_latest["up_bytes"]),
                "total_fmt": format_bytes(r_latest["total_bytes"]),
            }

        return {
            "node_key": target_key,
            "today": pack(r_today),
            "this_month": pack(r_month),
            "this_year": pack(r_year),
            "all_time": pack(r_all),
            "session_count": s_count,
            "latest_session": latest_sess,
        }

    @classmethod
    def get_hourly(cls, node_key: Optional[str] = None, date_str: Optional[str] = None) -> list:
        cls.init_db()
        target_key = node_key if node_key else "__GLOBAL__"
        target_date = date_str if date_str else datetime.datetime.now().strftime("%Y-%m-%d")

        with cls.db_session() as conn:
            rows = conn.execute("""
            SELECT hour, SUM(down_bytes) AS down, SUM(up_bytes) AS up, SUM(total_bytes) AS total
            FROM traffic_hourly
            WHERE node_key = ? AND day = ?
            GROUP BY hour
            ORDER BY hour ASC
            """, (target_key, target_date)).fetchall()

        hour_map = {r["hour"]: r for r in rows}
        result = []
        for h in range(24):
            r = hour_map.get(h)
            d = r["down"] if r else 0
            u = r["up"] if r else 0
            t = r["total"] if r else 0
            result.append({
                "hour": h,
                "label": f"{h:02d}:00",
                "down_bytes": d,
                "up_bytes": u,
                "total_bytes": t,
                "down_fmt": format_bytes(d),
                "up_fmt": format_bytes(u),
                "total_fmt": format_bytes(t),
            })
        return result

    @classmethod
    def get_daily(cls, node_key: Optional[str] = None, month_str: Optional[str] = None) -> list:
        cls.init_db()
        target_key = node_key if node_key else "__GLOBAL__"
        now = datetime.datetime.now()
        target_month = month_str if month_str else now.strftime("%Y-%m")

        try:
            parts = target_month.split("-")
            yr, mo = int(parts[0]), int(parts[1])
            if not (1 <= mo <= 12):
                raise ValueError("month out of range")
            days_in_mo = calendar.monthrange(yr, mo)[1]
            target_month = f"{yr:04d}-{mo:02d}"
        except Exception:
            yr, mo = now.year, now.month
            target_month = now.strftime("%Y-%m")
            days_in_mo = calendar.monthrange(yr, mo)[1]

        with cls.db_session() as conn:
            rows = conn.execute("""
            SELECT day, SUM(down_bytes) AS down, SUM(up_bytes) AS up, SUM(total_bytes) AS total
            FROM traffic_hourly
            WHERE node_key = ? AND month = ?
            GROUP BY day
            ORDER BY day ASC
            """, (target_key, target_month)).fetchall()

        day_map = {r["day"]: r for r in rows}
        result = []
        month_name = calendar.month_abbr[mo] if 1 <= mo <= 12 else str(mo)
        for d_num in range(1, days_in_mo + 1):
            d_str = f"{yr:04d}-{mo:02d}-{d_num:02d}"
            r = day_map.get(d_str)
            d = r["down"] if r else 0
            u = r["up"] if r else 0
            t = r["total"] if r else 0
            result.append({
                "day": d_str,
                "day_num": d_num,
                "label": f"{month_name} {d_num:02d}",
                "down_bytes": d,
                "up_bytes": u,
                "total_bytes": t,
                "down_fmt": format_bytes(d),
                "up_fmt": format_bytes(u),
                "total_fmt": format_bytes(t),
            })
        return result

    @classmethod
    def get_monthly(cls, node_key: Optional[str] = None, year_val: Optional[int] = None) -> list:
        cls.init_db()
        target_key = node_key if node_key else "__GLOBAL__"
        yr = int(year_val) if year_val else datetime.datetime.now().year

        with cls.db_session() as conn:
            rows = conn.execute("""
            SELECT month, SUM(down_bytes) AS down, SUM(up_bytes) AS up, SUM(total_bytes) AS total
            FROM traffic_hourly
            WHERE node_key = ? AND year = ?
            GROUP BY month
            ORDER BY month ASC
            """, (target_key, yr)).fetchall()

        month_map = {r["month"]: r for r in rows}
        result = []
        for mo in range(1, 13):
            mo_str = f"{yr:04d}-{mo:02d}"
            r = month_map.get(mo_str)
            d = r["down"] if r else 0
            u = r["up"] if r else 0
            t = r["total"] if r else 0
            result.append({
                "month": mo_str,
                "month_num": mo,
                "label": calendar.month_abbr[mo],
                "down_bytes": d,
                "up_bytes": u,
                "total_bytes": t,
                "down_fmt": format_bytes(d),
                "up_fmt": format_bytes(u),
                "total_fmt": format_bytes(t),
            })
        return result

    @classmethod
    def get_yearly(cls, node_key: Optional[str] = None) -> list:
        cls.init_db()
        target_key = node_key if node_key else "__GLOBAL__"

        with cls.db_session() as conn:
            rows = conn.execute("""
            SELECT year, SUM(down_bytes) AS down, SUM(up_bytes) AS up, SUM(total_bytes) AS total
            FROM traffic_hourly
            WHERE node_key = ?
            GROUP BY year
            ORDER BY year ASC
            """, (target_key,)).fetchall()

        current_year = datetime.datetime.now().year
        year_set = {r["year"] for r in rows}
        year_set.add(current_year)

        year_map = {r["year"]: r for r in rows}
        result = []
        for yr in sorted(year_set):
            r = year_map.get(yr)
            d = r["down"] if r else 0
            u = r["up"] if r else 0
            t = r["total"] if r else 0
            result.append({
                "year": yr,
                "label": str(yr),
                "down_bytes": d,
                "up_bytes": u,
                "total_bytes": t,
                "down_fmt": format_bytes(d),
                "up_fmt": format_bytes(u),
                "total_fmt": format_bytes(t),
            })
        return result

    @classmethod
    def get_nodes_traffic(cls) -> dict:
        cls.init_db()
        with cls.db_session() as conn:
            rows = conn.execute("""
            SELECT th.node_key,
                   COALESCE((
                       SELECT th2.node_tag FROM traffic_hourly th2
                       WHERE th2.node_key = th.node_key
                       ORDER BY th2.timestamp_hour DESC LIMIT 1
                   ), th.node_key) AS node_tag,
                   SUM(th.down_bytes) AS down, SUM(th.up_bytes) AS up, SUM(th.total_bytes) AS total
            FROM traffic_hourly th
            WHERE th.node_key != '__GLOBAL__'
            GROUP BY th.node_key
            ORDER BY total DESC
            """).fetchall()

            sessions_info = conn.execute("""
            SELECT node_key, COUNT(id) AS scount, MAX(end_time) AS last_ts
            FROM connection_sessions
            GROUP BY node_key
            """).fetchall()

        s_map = {r["node_key"]: r for r in sessions_info}
        nodes_list = []
        traffic_map = {}

        for r in rows:
            nk = r["node_key"]
            sinfo = s_map.get(nk)
            sc = sinfo["scount"] if sinfo else 0
            lts = sinfo["last_ts"] if sinfo and sinfo["last_ts"] else None
            last_used_fmt = datetime.datetime.fromtimestamp(lts).strftime("%Y-%m-%d %H:%M") if lts else "Never"

            d = r["down"] or 0
            u = r["up"] or 0
            t = r["total"] or 0

            entry = {
                "node_key": nk,
                "node_tag": r["node_tag"] or nk,
                "down_bytes": d,
                "up_bytes": u,
                "total_bytes": t,
                "down_fmt": format_bytes(d),
                "up_fmt": format_bytes(u),
                "total_fmt": format_bytes(t),
                "sessions_count": sc,
                "last_used": last_used_fmt,
            }
            nodes_list.append(entry)
            traffic_map[nk] = entry

        return {"nodes": nodes_list, "map": traffic_map}

    @classmethod
    def get_sessions(cls, node_key: Optional[str] = None, limit: int = 50) -> list:
        cls.init_db()
        with cls.db_session() as conn:
            if node_key and node_key != "__GLOBAL__":
                rows = conn.execute("""
                SELECT id, node_key, node_tag, node_server, node_port, node_type, start_time, end_time, duration, down_bytes, up_bytes, total_bytes
                FROM connection_sessions
                WHERE node_key = ?
                ORDER BY start_time DESC
                LIMIT ?
                """, (node_key, limit)).fetchall()
            else:
                rows = conn.execute("""
                SELECT id, node_key, node_tag, node_server, node_port, node_type, start_time, end_time, duration, down_bytes, up_bytes, total_bytes
                FROM connection_sessions
                ORDER BY start_time DESC
                LIMIT ?
                """, (limit,)).fetchall()

        result = []
        for r in rows:
            st = r["start_time"]
            et = r["end_time"]
            dur = r["duration"] or 0
            st_fmt = datetime.datetime.fromtimestamp(st).strftime("%Y-%m-%d %H:%M:%S") if st else "N/A"
            et_fmt = datetime.datetime.fromtimestamp(et).strftime("%Y-%m-%d %H:%M:%S") if et else "Active"
            d = r["down_bytes"] or 0
            u = r["up_bytes"] or 0
            t = r["total_bytes"] or 0

            result.append({
                "id": r["id"],
                "node_key": r["node_key"],
                "node_tag": r["node_tag"],
                "server": r["node_server"],
                "port": r["node_port"],
                "type": r["node_type"],
                "start_time": st,
                "start_time_fmt": st_fmt,
                "end_time_fmt": et_fmt,
                "duration": dur,
                "duration_fmt": format_duration(dur),
                "down_bytes": d,
                "up_bytes": u,
                "total_bytes": t,
                "down_fmt": format_bytes(d),
                "up_fmt": format_bytes(u),
                "total_fmt": format_bytes(t),
            })
        return result

    @classmethod
    def reset_traffic(cls, node_key: Optional[str] = None) -> bool:
        cls.init_db()
        with cls._lock:
            with cls.db_session() as conn:
                if node_key and node_key != "__GLOBAL__":
                    conn.execute("DELETE FROM traffic_hourly WHERE node_key = ?", (node_key,))
                    conn.execute("DELETE FROM connection_sessions WHERE node_key = ?", (node_key,))
                else:
                    conn.execute("DELETE FROM traffic_hourly")
                    conn.execute("DELETE FROM connection_sessions")
        return True


# --- Core Proxy Manager ---
class ProxyManager:
    def __init__(self, proxy_port: int = DEFAULT_PROXY_PORT):
        self.proxy_port = proxy_port
        self.api_port = proxy_port + 2
        self.proc = None
        self.aux_proc = None
        self.active_node = None
        self.connected = False
        self.start_time = None
        self.core_name = "None"
        self.status_msg = ""
        self.allow_lan = False

        self._lock = threading.RLock()
        self._manual_stop = False
        self._reconnecting = False
        self._reconnect_thread = None
        self._adopted_pid = None
        self._adopted_aux_pid = None

        # Live traffic & speed tracking
        self.last_down = 0
        self.last_up = 0
        self.total_down = 0
        self.total_up = 0
        self.down_speed = 0.0
        self.up_speed = 0.0
        self.last_stats_time = time.time()
        self.current_session_id = None
        self.session_down = 0
        self.session_up = 0
        self.prev_stat_down = 0
        self.prev_stat_up = 0

        self._check_existing()

    def _reset_local_state(self):
        self.proc = None
        self.aux_proc = None
        self._adopted_pid = None
        self._adopted_aux_pid = None
        self.connected = False
        self.active_node = None
        self.start_time = None
        self.down_speed = 0.0
        self.up_speed = 0.0
        self.current_session_id = None
        self.session_down = 0
        self.session_up = 0
        self.prev_stat_down = 0
        self.prev_stat_up = 0
        self.last_down = 0
        self.last_up = 0
        self.total_down = 0
        self.total_up = 0

    def reset_session_counters(self):
        """Synchronize in-memory counters after DB traffic stats are cleared."""
        with self._lock:
            cur_down, cur_up = self._read_core_counters() if self.connected else (0, 0)
            self.session_down = 0
            self.session_up = 0
            self.prev_stat_down = cur_down
            self.prev_stat_up = cur_up
            self.last_down = cur_down
            self.last_up = cur_up
            self.total_down = cur_down
            self.total_up = cur_up

    def _record_live_counters(self) -> Tuple[int, int]:
        """Read current core counters, persist deltas to TrafficTracker, and return (down, up)."""
        down, up = self._read_core_counters()
        if self.active_node:
            srv = str(self.active_node.get("server") or "")
            prt = int(self.active_node.get("port") or 0)
            ptype = str(self.active_node.get("type") or "vless").lower()
            node_key = f"{srv}:{prt}:{ptype}"
            node_tag = self.active_node.get("tag") or srv

            delta_down = max(0, down - self.prev_stat_down) if down >= self.prev_stat_down else down
            delta_up = max(0, up - self.prev_stat_up) if up >= self.prev_stat_up else up

            if delta_down > 0 or delta_up > 0:
                TrafficTracker.record_traffic(node_key, node_tag, delta_down, delta_up, session_id=self.current_session_id)
                self.session_down += delta_down
                self.session_up += delta_up
                self.prev_stat_down = down
                self.prev_stat_up = up
        return down, up

    def flush_session_traffic(self):
        """Persist any unrecorded core counters for the current session."""
        with self._lock:
            if self.connected and self.active_node:
                self._record_live_counters()

    def _hydrate_node(self, node: Optional[dict]) -> Optional[dict]:
        """Resolve full node credentials/config from saved stores when state.json only holds metadata."""
        if not node or node.get("raw"):
            return node
        try:
            node_id = node.get("id")
            srv = str(node.get("server") or "")
            prt = int(node.get("port") or 0)
            ptype = (node.get("type") or "").lower()
            tag = node.get("tag")
            candidates = load_all_nodes()
            if node_id:
                for cand in candidates:
                    if (cand.get("id") or get_node_identity(cand)) == node_id:
                        return cand
            fallback = None
            for cand in candidates:
                if (
                    str(cand.get("server") or "") == srv
                    and int(cand.get("port") or 0) == prt
                    and (cand.get("type") or "").lower() == ptype
                ):
                    if tag and cand.get("tag") == tag:
                        return cand
                    if fallback is None:
                        fallback = cand
            if fallback is not None:
                return fallback
        except Exception:
            pass
        return node

    def _read_core_counters(self) -> Tuple[int, int]:
        """Read current cumulative core counters (down, up) without side effects."""
        down = self.total_down
        up = self.total_up
        if self.core_name == "Sing-box":
            try:
                req = urllib.request.Request(f"http://127.0.0.1:{self.api_port}/connections")
                with urllib.request.urlopen(req, timeout=0.8) as resp:
                    data = json.loads(resp.read().decode())
                    down = int(data.get("downloadTotal", 0))
                    up = int(data.get("uploadTotal", 0))
            except Exception:
                pass
        elif os.path.exists(XRAY_BIN):
            try:
                res = subprocess.run(
                    [XRAY_BIN, "api", "statsquery", f"--server=127.0.0.1:{self.api_port}"],
                    capture_output=True,
                    text=True,
                    timeout=0.8,
                )
                if res.returncode == 0:
                    data = json.loads(res.stdout)
                    sum_down = 0
                    sum_up = 0
                    for item in data.get("stat", []):
                        n = item.get("name", "")
                        if not n.startswith("inbound>>>") or n.startswith("inbound>>>api>>>"):
                            continue
                        val = int(item.get("value", 0))
                        if n.endswith(">>>downlink"):
                            sum_down += val
                        elif n.endswith(">>>uplink"):
                            sum_up += val
                    down = sum_down
                    up = sum_up
            except Exception:
                pass
        return down, up

    def _check_existing(self):
        """Check if a previous instance is already running as a daemon."""
        if not os.path.exists(STATE_FILE):
            return

        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                state = json.load(f)

            pid = state.get("pid")
            aux_pid = state.get("aux_pid")
            if pid and self._is_pid_alive(pid):
                self._adopted_pid = pid
                self._adopted_aux_pid = aux_pid if aux_pid and self._is_pid_alive(aux_pid) else None
                self.connected = True
                self.active_node = self._hydrate_node(state.get("node"))
                self.start_time = state.get("start_time")
                self.proxy_port = state.get("proxy_port", DEFAULT_PROXY_PORT)
                self.api_port = self.proxy_port + 2
                self.core_name = state.get("core", "active")
                self.allow_lan = state.get("allow_lan", False)
                self.current_session_id = state.get("session_id")
                tag = self.active_node.get("tag", "proxy") if self.active_node else "proxy"
                self.status_msg = f"Connected to {tag}"

                if self.current_session_id and TrafficTracker.session_exists(self.current_session_id):
                    s_down, s_up = TrafficTracker.get_session_traffic(self.current_session_id)
                    self.session_down = s_down
                    self.session_up = s_up
                    cur_down, cur_up = self._read_core_counters()
                    self.prev_stat_down = s_down if cur_down >= s_down else 0
                    self.prev_stat_up = s_up if cur_up >= s_up else 0
                else:
                    cur_down, cur_up = self._read_core_counters()
                    self.session_down = 0
                    self.session_up = 0
                    self.prev_stat_down = cur_down
                    self.prev_stat_up = cur_up
                self.last_down = cur_down
                self.last_up = cur_up
                self.total_down = cur_down
                self.total_up = cur_up
            else:
                self._cleanup_state()
        except Exception:
            self._cleanup_state()

    def _is_pid_alive(self, pid: int) -> bool:
        """Check if PID is alive."""
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False

    def _kill_pid_or_pgid(self, pid: Optional[int]):
        """Terminate a managed process and its child process group cleanly."""
        if not pid or not self._is_pid_alive(pid):
            return
        try:
            pgid = os.getpgid(pid)
            if pgid != os.getpgid(0) and pgid > 1:
                os.killpg(pgid, signal.SIGTERM)
                for _ in range(15):
                    if not self._is_pid_alive(pid):
                        break
                    time.sleep(0.08)
                if self._is_pid_alive(pid):
                    os.killpg(pgid, signal.SIGKILL)
                return
        except Exception:
            pass
        try:
            os.kill(pid, signal.SIGTERM)
            for _ in range(15):
                if not self._is_pid_alive(pid):
                    break
                time.sleep(0.08)
            if self._is_pid_alive(pid):
                os.kill(pid, signal.SIGKILL)
        except Exception:
            pass

    def _append_log(self, message: str):
        try:
            os.makedirs(RUNTIME_DIR, exist_ok=True)
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{ts}] {message}\n")
        except Exception:
            pass

    def _open_log_fp(self, header: str):
        os.makedirs(RUNTIME_DIR, exist_ok=True)
        try:
            if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > 512 * 1024:
                with open(LOG_FILE, "w", encoding="utf-8") as f:
                    f.write(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Log rotated (>512KB)\n")
        except Exception:
            pass
        fp = open(LOG_FILE, "a", encoding="utf-8")
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fp.write(f"\n--- [{ts}] {header} ---\n")
        fp.flush()
        return fp

    def _cleanup_state(self):
        """Clean up runtime state file."""
        if os.path.exists(STATE_FILE):
            try:
                os.remove(STATE_FILE)
            except Exception:
                pass
        self._reset_local_state()

    def _kill_stale_processes(self):
        """Clean up only stale XHM daemon PIDs without touching external services."""
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    st = json.load(f)
                for pid_key in ("pid", "aux_pid"):
                    old_pid = st.get(pid_key)
                    self._kill_pid_or_pgid(old_pid)
            except Exception:
                pass

    def test_live_web_latency(self, timeout: float = 3.5) -> dict:
        """Test real round-trip HTTP connectivity through active proxy port."""
        if not self.connected:
            return {"alive": False, "error": "Proxy not connected"}
        http_p = self.proxy_port + 1
        test_urls = [
            ("Google", "https://www.google.com/generate_204"),
            ("Cloudflare", "https://cp.cloudflare.com/generate_204"),
            ("Firefox", "http://detectportal.firefox.com/success.txt"),
        ]
        proxy_handler = urllib.request.ProxyHandler({
            "http": f"http://127.0.0.1:{http_p}",
            "https": f"http://127.0.0.1:{http_p}",
        })
        opener = urllib.request.build_opener(proxy_handler)
        for label, url in test_urls:
            start = time.perf_counter()
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})
                with opener.open(req, timeout=timeout) as resp:
                    if resp.status in (200, 204):
                        elapsed_ms = round((time.perf_counter() - start) * 1000)
                        return {"alive": True, "latency_ms": elapsed_ms, "target": label}
            except Exception:
                continue
        return {"alive": False, "error": "No internet access through proxy"}

    def verify_live_connectivity(self, timeout: float = 4.5) -> bool:
        """Verify real internet connectivity through the running proxy instance."""
        http_p = self.proxy_port + 1
        test_urls = [
            "http://detectportal.firefox.com/success.txt",
            "https://www.google.com/generate_204",
            "https://connectivitycheck.gstatic.com/generate_204",
            "https://cp.cloudflare.com/generate_204",
        ]
        proxy_handler = urllib.request.ProxyHandler({
            "http": f"http://127.0.0.1:{http_p}",
            "https": f"http://127.0.0.1:{http_p}",
        })
        opener = urllib.request.build_opener(proxy_handler)
        for url in test_urls:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"})
                with opener.open(req, timeout=timeout) as resp:
                    if resp.status in (200, 204):
                        return True
            except Exception:
                continue
        return False

    def _validate_node_before_stop(self, node: dict) -> Tuple[bool, Optional[dict], str]:
        """Validate binaries and generated config BEFORE stopping an existing active tunnel.

        Returns (ok, prepared_config_or_None, error_msg).
        """
        node_type = (node.get("type") or "").lower()
        raw_node = node.get("raw") or node
        srv = str(node.get("server") or raw_node.get("server") or "").strip()
        try:
            prt = int(node.get("port") or raw_node.get("server_port") or 0)
        except (ValueError, TypeError):
            prt = 0
        if not srv or prt <= 0 or prt > 65535:
            return False, None, "❌ Invalid proxy server host or port."
        if node_type not in (
            "vless", "vmess", "trojan", "shadowsocks", "ss",
            "socks", "http", "hysteria2", "hy2", "tuic", "wireguard", "ssh",
        ):
            return False, None, f"❌ Unsupported proxy protocol: {node_type or 'unknown'}"

        use_singbox = node_type in ("hysteria2", "hy2", "tuic", "wireguard") or (
            node_type != "ssh" and not (os.path.exists(XRAY_BIN) and os.access(XRAY_BIN, os.X_OK))
        )

        if node_type == "ssh":
            ssh_host = node.get("server", "")
            ssh_pass = raw_node.get("password", "")
            cfg_type = raw_node.get("ssh_config_type") or node.get("ssh_config_type", "")
            sni = raw_node.get("sni") or node.get("sni", "")
            if not shutil.which("ssh"):
                return False, None, "❌ OpenSSH client 'ssh' not found on system."
            if ssh_pass and not shutil.which("sshpass"):
                return False, None, "❌ 'sshpass' not found for password-authenticated SSH."
            use_tls = cfg_type in ("SSH-TLS", "SSH-SSL") or (bool(sni) and sni != ssh_host)
            if use_tls and not os.path.exists(SSH_DIALER_BIN) and not shutil.which("openssl"):
                return False, None, "❌ 'openssl' command not found for SSH-TLS wrapping."
            if not (os.path.exists(XRAY_BIN) and os.access(XRAY_BIN, os.X_OK)):
                return False, None, f"❌ Xray binary not found at {XRAY_BIN}"
            internal_socks_port = self.proxy_port + 5
            xray_ob = {
                "protocol": "socks",
                "tag": "ssh-tunnel",
                "settings": {"servers": [{"address": "127.0.0.1", "port": internal_socks_port}]},
            }
            config_dict = build_xray_config(xray_ob, self.proxy_port, self.api_port, allow_lan=self.allow_lan)
            return True, config_dict, ""

        if use_singbox:
            if not (os.path.exists(SING_BOX_BIN) and os.access(SING_BOX_BIN, os.X_OK)):
                return False, None, f"❌ sing-box binary not found at {SING_BOX_BIN}"
            singbox_cfg = build_singbox_run_config(raw_node, self.proxy_port, self.api_port, allow_lan=self.allow_lan)
            os.makedirs(RUNTIME_DIR, exist_ok=True)
            fd, tmp_cfg = tempfile.mkstemp(dir=RUNTIME_DIR, prefix=".xhm_check_", suffix=".json")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(singbox_cfg, f, indent=2, ensure_ascii=False)
                chk = subprocess.run([SING_BOX_BIN, "check", "-c", tmp_cfg], capture_output=True, text=True)
                if chk.returncode != 0:
                    raw_err = (chk.stderr or chk.stdout or "").strip()
                    err_line = raw_err.splitlines()[-1] if raw_err else "Validation failed"
                    return False, None, f"Sing-box config error: {err_line[:80]}"
            finally:
                try:
                    os.remove(tmp_cfg)
                except OSError:
                    pass
            return True, singbox_cfg, ""

        if not (os.path.exists(XRAY_BIN) and os.access(XRAY_BIN, os.X_OK)):
            return False, None, f"❌ Xray binary not found at {XRAY_BIN}"
        xray_ob = singbox_to_xray_outbound(raw_node)
        config_dict = build_xray_config(xray_ob, self.proxy_port, self.api_port, allow_lan=self.allow_lan)
        os.makedirs(RUNTIME_DIR, exist_ok=True)
        fd, tmp_cfg = tempfile.mkstemp(dir=RUNTIME_DIR, prefix=".xhm_check_", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(config_dict, f, indent=2, ensure_ascii=False)
            chk = subprocess.run([XRAY_BIN, "run", "-test", "-c", tmp_cfg], capture_output=True, text=True)
            if chk.returncode != 0:
                raw_err = (chk.stderr or chk.stdout or "").strip()
                err_line = raw_err.splitlines()[-1] if raw_err else "Validation failed"
                return False, None, f"Xray config error: {err_line[:80]}"
        finally:
            try:
                os.remove(tmp_cfg)
            except OSError:
                pass
        return True, config_dict, ""

    def start(self, node: dict, _from_reconnect: bool = False, _restore_tun: Optional[bool] = None) -> bool:
        """Start proxy connection to target node using independent Xray, OpenSSH, or Sing-box Core."""
        if not _from_reconnect:
            self._manual_stop = True
            self._reconnecting = False

        with self._lock:
            if _from_reconnect and self._manual_stop:
                return False

            node = self._hydrate_node(node) or node
            ok_valid, prepared_cfg, err_msg = self._validate_node_before_stop(node)
            if not ok_valid:
                self.status_msg = err_msg
                self._append_log(err_msg)
                return False

            was_tun_active = (
                _restore_tun
                if _restore_tun is not None
                else (is_tun_active() or os.path.exists(TUN_MANAGED_FILE))
            )

            self._manual_stop = False
            self.stop(silent=True, unexpected=True)
            self._kill_stale_processes()
            os.makedirs(RUNTIME_DIR, exist_ok=True)

            node_type = (node.get("type") or "").lower()
            _, phys_iface = get_physical_interface()
            use_singbox = node_type in ("hysteria2", "hy2", "tuic", "wireguard") or (
                node_type != "ssh" and not (os.path.exists(XRAY_BIN) and os.access(XRAY_BIN, os.X_OK))
            )

            if node_type == "ssh":
                ssh_host = node.get("server", "")
                ssh_port = int(node.get("port", 22))
                raw_node = node.get("raw") or node
                ssh_user = raw_node.get("user", "")
                ssh_pass = raw_node.get("password", "")
                cfg_type = raw_node.get("ssh_config_type") or node.get("ssh_config_type", "")
                sni = raw_node.get("sni") or node.get("sni", "")
                internal_socks_port = self.proxy_port + 5  # 10855

                for _ in range(15):
                    if not is_port_in_use(internal_socks_port):
                        break
                    time.sleep(0.1)

                cmd = []
                popen_env = None
                if ssh_pass:
                    cmd.extend(["sshpass", "-e"])
                    popen_env = os.environ.copy()
                    popen_env["SSHPASS"] = str(ssh_pass)

                cmd.extend([
                    "ssh",
                    "-N",
                    "-D", f"127.0.0.1:{internal_socks_port}",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "ServerAliveInterval=20",
                    "-o", "ServerAliveCountMax=6",
                    "-o", "TCPKeepAlive=yes",
                    "-o", "ConnectTimeout=10",
                    "-o", "ExitOnForwardFailure=yes",
                ])

                use_tls = cfg_type in ("SSH-TLS", "SSH-SSL") or (bool(sni) and sni != ssh_host)
                if os.path.exists(SSH_DIALER_BIN):
                    dialer_parts = [sys.executable, SSH_DIALER_BIN, str(ssh_host), str(ssh_port)]
                    if phys_iface:
                        dialer_parts.extend(["--iface", phys_iface])
                    if use_tls:
                        dialer_parts.extend(["--sni", sni or ssh_host])
                    proxy_cmd = " ".join(shlex.quote(p) for p in dialer_parts)
                    cmd.extend(["-p", str(ssh_port), "-o", f"ProxyCommand={proxy_cmd}"])
                elif use_tls:
                    sni_target = sni or ssh_host
                    proxy_cmd = f"openssl s_client -quiet -connect {ssh_host}:{ssh_port} -servername {sni_target}"
                    cmd.extend(["-o", f"ProxyCommand={proxy_cmd}"])
                else:
                    cmd.extend(["-p", str(ssh_port)])

                cmd.append(f"{ssh_user}@{ssh_host}" if ssh_user else ssh_host)

                with self._open_log_fp(f"Starting SSH tunnel: {node.get('tag', ssh_host)} (iface={phys_iface or 'auto'})") as log_fp:
                    self.aux_proc = subprocess.Popen(
                        cmd,
                        stdout=log_fp,
                        stderr=subprocess.STDOUT,
                        stdin=subprocess.DEVNULL,
                        env=popen_env,
                        start_new_session=True,
                    )

                aux_ready = False
                for _ in range(120):
                    if self._manual_stop:
                        self.stop(silent=True)
                        return False
                    if self.aux_proc.poll() is not None:
                        break
                    if is_port_in_use(internal_socks_port):
                        aux_ready = True
                        break
                    time.sleep(0.1)

                if not aux_ready:
                    self._append_log(f"SSH tunnel failed to establish SOCKS5 on :{internal_socks_port}")
                    self.status_msg = "❌ SSH connection failed (check server address or credentials)."
                    self.stop(silent=True, unexpected=True)
                    return False

                with open(XRAY_CONFIG_FILE, "w", encoding="utf-8") as f:
                    json.dump(prepared_cfg, f, indent=2, ensure_ascii=False)

                with self._open_log_fp(f"Starting Xray wrapper for SSH: {node.get('tag', ssh_host)}") as log_fp:
                    self.proc = subprocess.Popen(
                        [XRAY_BIN, "run", "-c", XRAY_CONFIG_FILE],
                        stdout=log_fp,
                        stderr=subprocess.STDOUT,
                        stdin=subprocess.DEVNULL,
                        start_new_session=True,
                    )
                self.core_name = "SSH + Xray"

            elif use_singbox:
                try:
                    with open(SINGBOX_CONFIG_FILE, "w", encoding="utf-8") as f:
                        json.dump(prepared_cfg, f, indent=2, ensure_ascii=False)

                    with self._open_log_fp(f"Starting Sing-box: {node.get('tag', 'proxy')} (iface={phys_iface or 'auto'})") as log_fp:
                        self.proc = subprocess.Popen(
                            [SING_BOX_BIN, "run", "-c", SINGBOX_CONFIG_FILE],
                            stdout=log_fp,
                            stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL,
                            start_new_session=True,
                        )
                    self.core_name = "Sing-box"
                except Exception as e:
                    self.status_msg = f"Sing-box launch error: {e}"
                    self.stop(silent=True, unexpected=True)
                    return False
            else:
                try:
                    with open(XRAY_CONFIG_FILE, "w", encoding="utf-8") as f:
                        json.dump(prepared_cfg, f, indent=2, ensure_ascii=False)

                    with self._open_log_fp(f"Starting Xray: {node.get('tag', 'proxy')} (iface={phys_iface or 'auto'})") as log_fp:
                        self.proc = subprocess.Popen(
                            [XRAY_BIN, "run", "-c", XRAY_CONFIG_FILE],
                            stdout=log_fp,
                            stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL,
                            start_new_session=True,
                        )
                    self.core_name = "Xray"
                except Exception as e:
                    self.status_msg = f"Xray launch error: {e}"
                    self.stop(silent=True, unexpected=True)
                    return False

            success = False
            for _ in range(30):
                if self._manual_stop:
                    self.stop(silent=True)
                    return False
                if self.proc.poll() is not None:
                    break
                if is_port_in_use(self.proxy_port):
                    success = True
                    break
                time.sleep(0.1)

            if success:
                time.sleep(0.4)
                if self._manual_stop:
                    self.stop(silent=True)
                    return False
                is_live = self.verify_live_connectivity(timeout=4.5)
                self._reconnecting = False
                self._on_started(node, system_proxy=True)
                tun_suffix = ""
                if was_tun_active:
                    ok_tun, tun_msg = set_tun_mode_detailed(True, manager=self)
                    tun_suffix = " + TUN" if ok_tun else f" (TUN restore skipped: {tun_msg})"
                if is_live:
                    self.status_msg = f"🟢 Connected to {node.get('tag', 'Proxy')} (Verified Live{tun_suffix})"
                else:
                    self.status_msg = f"⚠️ Connected to {node.get('tag', 'Proxy')} ({self.core_name} Active - Unverified{tun_suffix})"
                self._append_log(f"Connected: {self.status_msg}")
                return True
            else:
                self.status_msg = f"{self.core_name} Core failed to bind proxy port."
                self._append_log(self.status_msg)

            self.stop(silent=True, unexpected=True)
            return False

    def _trigger_auto_reconnect(self, node: dict, reason: str, restore_tun: bool = False):
        """Start background reconnect loop with backoff when a tunnel drops unexpectedly."""
        if self._manual_stop or self._reconnecting or not node:
            return
        self._reconnecting = True
        tag = node.get("tag", "proxy")
        self.status_msg = f"🔄 {reason} Reconnecting to {tag}..."
        self._append_log(f"{reason} Triggering auto-reconnect for {tag}.")

        def worker():
            delays = (4, 10, 20)
            for idx, wait_s in enumerate(delays, start=1):
                for _ in range(wait_s * 4):
                    if self._manual_stop:
                        self._reconnecting = False
                        return
                    time.sleep(0.25)
                if self._manual_stop:
                    self._reconnecting = False
                    return
                self.status_msg = f"🔄 Reconnecting to {tag} (attempt {idx}/{len(delays)})..."
                self._append_log(f"Auto-reconnect attempt {idx}/{len(delays)} for {tag}")
                try:
                    if self.start(node, _from_reconnect=True, _restore_tun=restore_tun):
                        return
                except Exception as exc:
                    self._append_log(f"Auto-reconnect attempt {idx} error: {exc}")
            if not self._manual_stop:
                self._reconnecting = False
                self.status_msg = f"❌ Auto-reconnect failed after {len(delays)} attempts ({tag})."
                self._append_log(self.status_msg)

        t = threading.Thread(target=worker, daemon=True)
        self._reconnect_thread = t
        t.start()

    def _on_started(self, node: dict, system_proxy: bool = True):
        """Post-start actions."""
        self._adopted_pid = None
        self._adopted_aux_pid = None
        self.connected = True
        self.active_node = node
        self.start_time = time.time()
        self.last_stats_time = time.time()
        self.total_down = 0
        self.total_up = 0
        self.last_down = 0
        self.last_up = 0
        self.down_speed = 0.0
        self.up_speed = 0.0
        self.session_down = 0
        self.session_up = 0
        self.prev_stat_down = 0
        self.prev_stat_up = 0
        self.current_session_id = TrafficTracker.start_session(node)
        self.status_msg = f"🟢 Connected to {node['tag']}"

        # Turn ON GNOME system proxy & CLI env
        http_p = self.proxy_port + 1
        if system_proxy:
            set_gnome_proxy(True, self.proxy_port, http_port=http_p)
        else:
            set_gnome_proxy(False, self.proxy_port)

        state_data = {
            "pid": self.proc.pid if self.proc else None,
            "aux_pid": self.aux_proc.pid if hasattr(self, "aux_proc") and self.aux_proc else None,
            "core": self.core_name,
            "node": {
                "id": node.get("id") or get_node_identity(node),
                "profile": node.get("profile"),
                "tag": node.get("tag"),
                "type": node.get("type"),
                "server": node.get("server"),
                "port": node.get("port"),
            },
            "proxy_port": self.proxy_port,
            "api_port": self.api_port,
            "start_time": self.start_time,
            "session_id": self.current_session_id,
            "system_proxy": system_proxy,
            "allow_lan": self.allow_lan,
        }
        _atomic_write_json(STATE_FILE, state_data)

    def _sync_with_external_state(self):
        """Synchronize in-memory daemon state with STATE_FILE edited by external CLI invocations."""
        ext_state = None
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, "r", encoding="utf-8") as f:
                    ext_state = json.load(f)
            except Exception:
                ext_state = None

        if not self.connected:
            if ext_state and ext_state.get("pid") and self._is_pid_alive(int(ext_state["pid"])):
                self._check_existing()
            return

        my_pid = self.proc.pid if self.proc else self._adopted_pid
        if ext_state is None:
            # STATE_FILE removed (e.g. CLI `xhm off`): do not fight user with auto-reconnect
            if my_pid and not self._is_pid_alive(int(my_pid)):
                self._manual_stop = True
                self._reset_local_state()
                self.status_msg = "🔴 Proxy Disconnected (OFF)"
            return

        st_pid = ext_state.get("pid")
        if st_pid and my_pid and int(st_pid) != int(my_pid) and self._is_pid_alive(int(st_pid)):
            self._reset_local_state()
            self._check_existing()

    def query_traffic_stats(self) -> dict:
        """Query real-time transfer speeds and total consumed bandwidth."""
        acquired = self._lock.acquire(timeout=0.05)
        if not acquired:
            return {
                "down_speed_fmt": format_speed(self.down_speed),
                "up_speed_fmt": format_speed(self.up_speed),
                "down_total_fmt": format_bytes(self.session_down),
                "up_total_fmt": format_bytes(self.session_up),
                "total_fmt": format_bytes(self.session_down + self.session_up),
                "down_bytes": self.session_down,
                "up_bytes": self.session_up,
                "session_id": self.current_session_id,
                "allow_lan": self.allow_lan,
            }

        try:
            self._sync_with_external_state()
            if not self.connected:
                self.down_speed = 0.0
                self.up_speed = 0.0
                return {
                    "down_speed_fmt": format_speed(0.0),
                    "up_speed_fmt": format_speed(0.0),
                    "down_total_fmt": format_bytes(self.session_down),
                    "up_total_fmt": format_bytes(self.session_up),
                    "total_fmt": format_bytes(self.session_down + self.session_up),
                    "down_bytes": self.session_down,
                    "up_bytes": self.session_up,
                    "session_id": self.current_session_id,
                    "allow_lan": self.allow_lan,
                }

            now = time.time()
            dt = max(0.2, now - self.last_stats_time)

            proc_dead = (self.proc is not None and self.proc.poll() is not None) or (
                self.proc is None and self._adopted_pid and not self._is_pid_alive(self._adopted_pid)
            )
            aux_dead = (self.aux_proc is not None and self.aux_proc.poll() is not None) or (
                self.aux_proc is None and self._adopted_aux_pid and not self._is_pid_alive(self._adopted_aux_pid)
            )
            if proc_dead or aux_dead:
                dropped_node = self._hydrate_node(dict(self.active_node)) if self.active_node else None
                was_tun = is_tun_active() or os.path.exists(TUN_MANAGED_FILE)
                state_still_present = os.path.exists(STATE_FILE)
                should_reconnect = (
                    (not self._manual_stop)
                    and state_still_present
                    and (dropped_node is not None)
                    and (not self._reconnecting)
                )
                reason = "Auxiliary tunnel (SSH) disconnected." if aux_dead else "Core process terminated unexpectedly."
                self.stop(silent=True, unexpected=True)
                if should_reconnect:
                    self._trigger_auto_reconnect(dropped_node, reason, restore_tun=was_tun)
                else:
                    self.status_msg = f"❌ {reason}"

            if self.connected:
                down, up = self._record_live_counters()

                if self.last_stats_time > 0 and (down >= self.last_down or up >= self.last_up):
                    self.down_speed = max(0.0, (down - self.last_down) / dt)
                    self.up_speed = max(0.0, (up - self.last_up) / dt)

                self.last_down = down
                self.last_up = up
                self.total_down = down
                self.total_up = up
                self.last_stats_time = now
            else:
                self.down_speed = 0.0
                self.up_speed = 0.0
        finally:
            self._lock.release()

        return {
            "down_speed_fmt": format_speed(self.down_speed),
            "up_speed_fmt": format_speed(self.up_speed),
            "down_total_fmt": format_bytes(self.session_down),
            "up_total_fmt": format_bytes(self.session_up),
            "total_fmt": format_bytes(self.session_down + self.session_up),
            "down_bytes": self.session_down,
            "up_bytes": self.session_up,
            "session_id": self.current_session_id,
            "allow_lan": self.allow_lan,
        }

    def stop(self, silent: bool = False, unexpected: bool = False):
        """Stop active proxy connection."""
        if not unexpected:
            self._manual_stop = True
            self._reconnecting = False

        with self._lock:
            if self.connected and self.active_node:
                try:
                    self._record_live_counters()
                except Exception:
                    pass

            # 1. ALWAYS stop TUN Mode FIRST before tearing down the proxy core!
            # Sing-box TUN routes 100% of system traffic into self.proxy_port (10850).
            # If we kill the proxy core before stopping TUN, all machine traffic enters
            # a dead black-hole until TUN is stopped.
            # Crucially: TUN must be stopped regardless of 'silent', because unexpected drops
            # or background reconnects would otherwise leave system internet severed!
            tun_note = ""
            if is_tun_active() or os.path.exists(TUN_MANAGED_FILE):
                ok_tun, _ = set_tun_mode_detailed(False)
                if ok_tun:
                    tun_note = " & stopped TUN"

            if self.current_session_id:
                TrafficTracker.end_session(self.current_session_id, self.session_down, self.session_up)
                self.current_session_id = None

            target_pid = self.proc.pid if self.proc else self._adopted_pid
            aux_pid = self.aux_proc.pid if hasattr(self, "aux_proc") and self.aux_proc else self._adopted_aux_pid
            was_sys_proxy = False
            if os.path.exists(STATE_FILE):
                try:
                    with open(STATE_FILE, "r", encoding="utf-8") as f:
                        st = json.load(f)
                        if not target_pid:
                            target_pid = st.get("pid")
                        if not aux_pid:
                            aux_pid = st.get("aux_pid")
                        was_sys_proxy = bool(st.get("system_proxy", False))
                except Exception:
                    pass
            elif self.connected:
                was_sys_proxy = True

            for p in (target_pid, aux_pid):
                self._kill_pid_or_pgid(p)

            self._cleanup_state()

            curr_proxy = get_current_gnome_proxy()
            curr_ports = {str(curr_proxy.get("http_port") or ""), str(curr_proxy.get("socks_port") or "")}
            xhm_ports = {str(self.proxy_port), str(self.proxy_port + 1)}
            pointing_to_xhm = curr_proxy.get("mode") == "manual" and bool(curr_ports & xhm_ports)

            if was_sys_proxy or pointing_to_xhm:
                set_gnome_proxy(False, self.proxy_port, http_port=self.proxy_port + 1)

            # Ensure resolved DNS cache and physical interface routes are 100% healthy
            _revert_system_tun_dns()

            if not silent:
                self.status_msg = f"🔴 Proxy Disconnected (OFF{tun_note})"
                self._append_log(self.status_msg)

    def toggle(self, node: dict = None) -> bool:
        """Toggle connection state."""
        if self.connected:
            if node and self.active_node and not is_same_node(node, self.active_node):
                return self.start(node)
            else:
                self.stop()
                return False
        else:
            if not node:
                nodes = load_all_nodes()
                if nodes:
                    node = nodes[0]
            if node:
                return self.start(node)
            return False


# --- Version & Git Update Checker ---
def extract_github_owner_repo(remote_url: str) -> Optional[Tuple[str, str]]:
    """Extract (owner, repo) from a GitHub HTTPS or SSH remote URL."""
    raw = str(remote_url or "").strip()
    if not raw:
        return None
    if raw.startswith("git@github.com:"):
        path = raw[len("git@github.com:"):]
    else:
        parsed = urllib.parse.urlparse(raw)
        if parsed.netloc.lower() != "github.com":
            return None
        path = parsed.path.lstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = [p for p in path.strip("/").split("/") if p]
    if len(parts) >= 2:
        return parts[0], parts[1]
    return None


def normalize_github_https(remote_url: str) -> str:
    """Normalize a GitHub remote URL to HTTPS form for web display or API fallback."""
    pair = extract_github_owner_repo(remote_url)
    if pair:
        return f"https://github.com/{pair[0]}/{pair[1]}.git"
    return str(remote_url or DEFAULT_REPO_URL).strip() or DEFAULT_REPO_URL


def _run_git_ro(repo_dir: str, *args: str, timeout: int = 3) -> str:
    """Run a read-only git subcommand cleanly, returning stripped stdout or empty string."""
    if not repo_dir or not os.path.isdir(os.path.join(repo_dir, ".git")):
        return ""
    try:
        out = subprocess.check_output(
            ["git", "-C", repo_dir, *args],
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        )
        return out.decode("utf-8", errors="ignore").strip()
    except Exception:
        return ""


def _read_version_file(path: str) -> str:
    """Read a VERSION file and return its stripped content, or empty string."""
    if not path or not os.path.isfile(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def get_installed_meta() -> dict:
    """Return installed version, commit, branch, and repository state metadata."""
    repo_guess = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data = {}
    has_meta_file = os.path.isfile(INSTALL_META_FILE)
    if has_meta_file:
        try:
            with open(INSTALL_META_FILE, "r", encoding="utf-8") as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    data = loaded
        except Exception:
            data = {}

    repo_dir = str(data.get("repo_dir") or "").strip()
    if not has_meta_file and not repo_dir and os.path.isdir(os.path.join(repo_guess, ".git")):
        repo_dir = repo_guess

    version = (
        str(data.get("version") or "").strip()
        or _read_version_file(os.path.join(XHM_DATA_DIR, "VERSION"))
        or _read_version_file(os.path.join(repo_dir or repo_guess, "VERSION"))
        or "1.0.0"
    )
    branch = str(data.get("branch") or "").strip()
    if not branch and repo_dir:
        b = _run_git_ro(repo_dir, "rev-parse", "--abbrev-ref", "HEAD")
        if b and b != "HEAD":
            branch = b
    branch = branch or "main"

    remote_url = str(data.get("remote_url") or "").strip()
    if not remote_url and repo_dir:
        remote_url = _run_git_ro(repo_dir, "remote", "get-url", "origin")
    remote_url = remote_url or DEFAULT_REPO_URL

    commit = str(data.get("commit") or "").strip()
    short_commit = str(data.get("short_commit") or "").strip()
    local_head = _run_git_ro(repo_dir, "rev-parse", "HEAD") if repo_dir else ""
    local_short = _run_git_ro(repo_dir, "rev-parse", "--short", "HEAD") if repo_dir else ""
    local_dirty = bool(_run_git_ro(repo_dir, "status", "--porcelain")) if repo_dir else False

    if not commit and local_head:
        commit = local_head
        short_commit = short_commit or local_short
    if commit and not short_commit:
        short_commit = commit[:7]

    has_git_repo = bool(repo_dir and os.path.isdir(os.path.join(repo_dir, ".git")))
    return {
        "version": version,
        "commit": commit,
        "short_commit": short_commit,
        "branch": branch,
        "remote_url": remote_url,
        "repo_dir": repo_dir,
        "installed_at": str(data.get("installed_at") or ""),
        "bootstrap_mode": bool(data.get("bootstrap_mode", False)),
        "has_git_repo": has_git_repo,
        "local_head": local_head,
        "local_short": local_short,
        "repo_clean": has_git_repo and (not local_dirty),
        "sync_needed": bool(local_head and commit and local_head != commit),
    }


def _build_update_command(meta: dict) -> str:
    """Return a clean copyable CLI command for updating XHM."""
    if meta.get("has_git_repo") and meta.get("repo_dir"):
        q_dir = shlex.quote(meta["repo_dir"])
        return f"git -C {q_dir} pull --ff-only && {q_dir}/install.sh --no-deps --no-grant-tun-cap"
    return 'bash -c "$(curl -fsSL https://raw.githubusercontent.com/Man30ur/xhm/main/install.sh)"'


def read_update_cache() -> Optional[dict]:
    """Read cached update check data without performing any network calls."""
    if not os.path.isfile(UPDATE_CACHE_FILE):
        return None
    try:
        with open(UPDATE_CACHE_FILE, "r", encoding="utf-8") as f:
            cached = json.load(f)
        if not isinstance(cached, dict):
            return None
    except Exception:
        return None

    meta = get_installed_meta()
    cached["installed_version"] = meta["version"]
    cached["installed_commit"] = meta["commit"]
    cached["installed_short"] = meta["short_commit"]
    cached["branch"] = meta["branch"]
    cached["repo_dir"] = meta["repo_dir"]
    cached["has_git_repo"] = meta["has_git_repo"]
    cached["repo_clean"] = meta["repo_clean"]
    cached["sync_needed"] = meta["sync_needed"]
    cached["can_auto_update"] = bool(meta["has_git_repo"] and meta["repo_clean"])
    cached["update_command"] = _build_update_command(meta)

    latest_commit = str(cached.get("latest_commit") or "").strip()
    if latest_commit and meta["commit"]:
        if latest_commit == meta["commit"]:
            cached["update_available"] = False
            cached["ahead_by"] = 0
        elif cached.get("ahead_by") is not None:
            cached["update_available"] = bool(int(cached.get("ahead_by") or 0) > 0)
    elif meta["sync_needed"]:
        cached["update_available"] = True
    return cached


def _write_update_cache(payload: dict):
    """Persist update check cache atomically inside XHM_DATA_DIR."""
    try:
        os.makedirs(os.path.dirname(UPDATE_CACHE_FILE), exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix=".update_cache_", suffix=".tmp", dir=os.path.dirname(UPDATE_CACHE_FILE))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp_path, UPDATE_CACHE_FILE)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except Exception:
        pass


def _urlopen_json(url: str, timeout: float = 3.5, http_proxy_port: Optional[int] = None) -> dict:
    """Fetch JSON over HTTPS, optionally routing through the local XHM HTTP proxy."""
    headers = {
        "User-Agent": "xhm-update-checker/1.0",
        "Accept": "application/vnd.github+json",
    }
    req = urllib.request.Request(url, headers=headers)
    if http_proxy_port:
        proxy_url = f"http://127.0.0.1:{int(http_proxy_port)}"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    else:
        opener = urllib.request.build_opener()
    with opener.open(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        return data if isinstance(data, dict) else {}


def _fetch_remote_head_info(meta: dict, timeout: float = 3.5, http_proxy_port: Optional[int] = None) -> dict:
    """Query GitHub API (with git ls-remote fallback) for latest upstream commit info."""
    branch = meta.get("branch") or "main"
    installed_commit = meta.get("commit") or ""
    remote_url = meta.get("remote_url") or DEFAULT_REPO_URL
    gh_pair = extract_github_owner_repo(remote_url)
    last_err = ""

    if gh_pair:
        owner, repo = gh_pair
        repo_web_url = f"https://github.com/{owner}/{repo}"
        try:
            if installed_commit:
                cmp_url = f"https://api.github.com/repos/{owner}/{repo}/compare/{urllib.parse.quote(installed_commit)}...{urllib.parse.quote(branch)}"
                cmp_data = _urlopen_json(cmp_url, timeout=timeout, http_proxy_port=http_proxy_port)
                status = str(cmp_data.get("status") or "")
                ahead_by = int(cmp_data.get("ahead_by") or 0)
                commits = cmp_data.get("commits") or []
                latest = commits[-1] if commits else {}
                latest_sha = str(latest.get("sha") or (installed_commit if status == "identical" else "")).strip()
                commit_obj = latest.get("commit") or {}
                msg_raw = str(commit_obj.get("message") or "").strip()
                commit_msg = msg_raw.splitlines()[0] if msg_raw else ""
                commit_date = str((commit_obj.get("author") or {}).get("date") or "")
                if not latest_sha and status == "behind":
                    latest_sha = installed_commit
                return {
                    "latest_commit": latest_sha,
                    "latest_short": latest_sha[:7] if latest_sha else "",
                    "commit_message": commit_msg,
                    "commit_date": commit_date,
                    "ahead_by": ahead_by if status in ("ahead", "diverged") else 0,
                    "compare_status": status,
                    "release_url": str(cmp_data.get("html_url") or f"{repo_web_url}/commits/{branch}"),
                }
        except Exception as e:
            last_err = str(e)

        try:
            branch_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{urllib.parse.quote(branch)}"
            br_data = _urlopen_json(branch_url, timeout=timeout, http_proxy_port=http_proxy_port)
            latest_sha = str(br_data.get("sha") or "").strip()
            commit_obj = br_data.get("commit") or {}
            msg_raw = str(commit_obj.get("message") or "").strip()
            commit_msg = msg_raw.splitlines()[0] if msg_raw else ""
            commit_date = str((commit_obj.get("author") or {}).get("date") or "")
            if latest_sha:
                is_diff = bool(not installed_commit or latest_sha != installed_commit)
                return {
                    "latest_commit": latest_sha,
                    "latest_short": latest_sha[:7],
                    "commit_message": commit_msg,
                    "commit_date": commit_date,
                    "ahead_by": 1 if is_diff else 0,
                    "compare_status": "ahead" if is_diff else "identical",
                    "release_url": str(br_data.get("html_url") or f"{repo_web_url}/commits/{branch}"),
                }
        except Exception as e:
            last_err = str(e)

    # Fallback to git ls-remote over HTTPS
    https_remote = normalize_github_https(remote_url)
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if http_proxy_port:
        proxy_url = f"http://127.0.0.1:{int(http_proxy_port)}"
        env["HTTPS_PROXY"] = proxy_url
        env["HTTP_PROXY"] = proxy_url
        env["https_proxy"] = proxy_url
        env["http_proxy"] = proxy_url
    try:
        out = subprocess.check_output(
            ["git", "ls-remote", https_remote, f"refs/heads/{branch}"],
            stderr=subprocess.PIPE,
            env=env,
            timeout=max(2.0, timeout),
        ).decode("utf-8", errors="ignore").strip()
        if out:
            latest_sha = out.split()[0].strip()
            is_diff = bool(not installed_commit or latest_sha != installed_commit)
            return {
                "latest_commit": latest_sha,
                "latest_short": latest_sha[:7],
                "commit_message": "",
                "commit_date": "",
                "ahead_by": 1 if is_diff else 0,
                "compare_status": "ahead" if is_diff else "identical",
                "release_url": https_remote[:-4] if https_remote.endswith(".git") else https_remote,
            }
        raise RuntimeError("Empty response from git ls-remote")
    except Exception as e:
        raise RuntimeError(last_err or str(e))


def check_for_updates(force: bool = False, http_proxy_port: Optional[int] = None, ttl_seconds: int = 21600) -> dict:
    """Check whether a newer upstream Git commit is available (with local TTL cache)."""
    meta = get_installed_meta()
    now_ts = int(time.time())

    if not force:
        cached = read_update_cache()
        if cached and cached.get("checked_at"):
            age = now_ts - int(cached.get("checked_at") or 0)
            retry_window = 300 if cached.get("error") else ttl_seconds
            if 0 <= age < retry_window and cached.get("branch") == meta["branch"]:
                cached["cached"] = True
                return cached

    if http_proxy_port is None and is_port_in_use(DEFAULT_PROXY_PORT + 1):
        http_proxy_port = DEFAULT_PROXY_PORT + 1

    base_payload = {
        "installed_version": meta["version"],
        "installed_commit": meta["commit"],
        "installed_short": meta["short_commit"],
        "branch": meta["branch"],
        "remote_url": meta["remote_url"],
        "repo_dir": meta["repo_dir"],
        "has_git_repo": meta["has_git_repo"],
        "repo_clean": meta["repo_clean"],
        "sync_needed": meta["sync_needed"],
        "can_auto_update": bool(meta["has_git_repo"] and meta["repo_clean"]),
        "update_command": _build_update_command(meta),
        "checked_at": now_ts,
        "cached": False,
    }

    try:
        remote = _fetch_remote_head_info(meta, timeout=3.5, http_proxy_port=http_proxy_port)
        ahead_by = int(remote.get("ahead_by") or 0)
        latest_commit = str(remote.get("latest_commit") or "").strip()
        update_available = bool(
            (ahead_by > 0 and (not meta["commit"] or latest_commit != meta["commit"]))
            or meta["sync_needed"]
        )
        payload = {
            **base_payload,
            "update_available": update_available,
            "latest_commit": latest_commit,
            "latest_short": remote.get("latest_short") or (latest_commit[:7] if latest_commit else ""),
            "commit_message": remote.get("commit_message") or "",
            "commit_date": remote.get("commit_date") or "",
            "ahead_by": ahead_by,
            "compare_status": remote.get("compare_status") or "",
            "release_url": remote.get("release_url") or "",
            "error": None,
            "offline": False,
        }
    except Exception as e:
        payload = {
            **base_payload,
            "update_available": bool(meta["sync_needed"]),
            "latest_commit": meta["local_head"] if meta["sync_needed"] else "",
            "latest_short": meta["local_short"] if meta["sync_needed"] else "",
            "commit_message": "Local repository is ahead of installed files" if meta["sync_needed"] else "",
            "commit_date": "",
            "ahead_by": 1 if meta["sync_needed"] else 0,
            "compare_status": "local_ahead" if meta["sync_needed"] else "error",
            "release_url": normalize_github_https(meta["remote_url"]).removesuffix(".git"),
            "error": str(e),
            "offline": True,
        }

    _write_update_cache(payload)
    return payload


def apply_git_update(http_proxy_port: Optional[int] = None) -> dict:
    """Safely fast-forward a clean local XHM Git repo and sync updated files."""
    meta = get_installed_meta()
    repo_dir = meta.get("repo_dir") or ""
    if not meta.get("has_git_repo") or not repo_dir:
        return {
            "success": False,
            "updated": False,
            "dirty": False,
            "restart_required": False,
            "message": "No local Git repository is linked to this installation. Run the one-line installer command to upgrade.",
            "update_command": _build_update_command(meta),
        }

    if not meta.get("repo_clean"):
        return {
            "success": False,
            "updated": False,
            "dirty": True,
            "restart_required": False,
            "message": f"Local repository ({repo_dir}) has uncommitted changes. Commit/stash them or update manually.",
            "update_command": _build_update_command(meta),
        }

    if http_proxy_port is None and is_port_in_use(DEFAULT_PROXY_PORT + 1):
        http_proxy_port = DEFAULT_PROXY_PORT + 1

    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    if http_proxy_port:
        proxy_url = f"http://127.0.0.1:{int(http_proxy_port)}"
        env["HTTPS_PROXY"] = proxy_url
        env["HTTP_PROXY"] = proxy_url
        env["https_proxy"] = proxy_url
        env["http_proxy"] = proxy_url

    old_commit = meta.get("commit") or meta.get("local_head") or ""
    pull_res = subprocess.run(
        ["git", "-C", repo_dir, "pull", "--ff-only"],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    if pull_res.returncode != 0:
        err_msg = (pull_res.stderr or pull_res.stdout or "git pull failed").strip()
        return {
            "success": False,
            "updated": False,
            "dirty": False,
            "restart_required": False,
            "message": f"git pull --ff-only failed: {err_msg}",
            "update_command": _build_update_command(meta),
        }

    install_sh = os.path.join(repo_dir, "install.sh")
    if os.path.isfile(install_sh):
        inst_res = subprocess.run(
            ["bash", install_sh, "--no-deps", "--no-grant-tun-cap", "--user-only"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if inst_res.returncode != 0:
            err_msg = (inst_res.stderr or inst_res.stdout or "install.sh failed").strip()
            return {
                "success": False,
                "updated": False,
                "dirty": False,
                "restart_required": False,
                "message": f"Updated repo, but syncing installed files failed: {err_msg}",
            }

    new_meta = get_installed_meta()
    new_commit = new_meta.get("commit") or new_meta.get("local_head") or ""
    changed = bool(not old_commit or new_commit != old_commit or meta.get("sync_needed"))

    _write_update_cache({
        "installed_version": new_meta["version"],
        "installed_commit": new_commit,
        "installed_short": new_meta["short_commit"],
        "branch": new_meta["branch"],
        "remote_url": new_meta["remote_url"],
        "repo_dir": new_meta["repo_dir"],
        "has_git_repo": new_meta["has_git_repo"],
        "repo_clean": new_meta["repo_clean"],
        "sync_needed": False,
        "can_auto_update": bool(new_meta["has_git_repo"] and new_meta["repo_clean"]),
        "update_command": _build_update_command(new_meta),
        "update_available": False,
        "latest_commit": new_commit,
        "latest_short": new_meta["short_commit"],
        "commit_message": "",
        "commit_date": "",
        "ahead_by": 0,
        "compare_status": "identical",
        "release_url": normalize_github_https(new_meta["remote_url"]).removesuffix(".git"),
        "error": None,
        "offline": False,
        "checked_at": int(time.time()),
        "cached": False,
    })

    return {
        "success": True,
        "updated": changed,
        "dirty": False,
        "restart_required": changed,
        "old_commit": old_commit,
        "new_commit": new_commit,
        "new_short": new_meta.get("short_commit") or "",
        "new_version": new_meta.get("version") or "1.0.0",
        "message": (
            f"Updated to {new_meta.get('version')} ({new_meta.get('short_commit') or 'latest'}). Restart XHM GUI when convenient to load backend changes."
            if changed
            else f"Already up to date ({new_meta.get('version')} · {new_meta.get('short_commit')})."
        ),
    }
