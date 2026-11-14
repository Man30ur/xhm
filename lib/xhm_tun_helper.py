#!/usr/bin/env python3
"""Privileged helper for starting/stopping XHM's self-contained xhm-tun interface."""
import argparse
import os
import pwd
import signal
import subprocess
import sys
import time


def _is_pid_alive(pid: int) -> bool:
    if not pid or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("State:"):
                    return "Z" not in line.split()[1]
    except OSError:
        return False
    return True


def _iface_exists(iface: str) -> bool:
    res = subprocess.run(
        ["ip", "link", "show", "dev", iface],
        capture_output=True,
        text=True,
        timeout=2,
    )
    return res.returncode == 0


def _cleanup_table_2022():
    """Clean up orphan rules and routes for table 2022 if left behind."""
    try:
        res = subprocess.run(["ip", "rule", "show"], capture_output=True, text=True, timeout=2)
        if "2022" in res.stdout:
            for line in res.stdout.splitlines():
                if "2022" in line or "xhm-tun" in line:
                    parts = line.split(":")
                    if parts and parts[0].strip().isdigit():
                        pref = parts[0].strip()
                        subprocess.run(["ip", "rule", "del", "pref", pref], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", "2022"], capture_output=True, timeout=2)
    except Exception:
        pass


def _stop_pid_file(pid_file: str, iface: str = "xhm-tun") -> int:
    if os.path.exists(pid_file):
        try:
            with open(pid_file, "r", encoding="utf-8") as f:
                pid = int(f.read().strip())
        except Exception:
            pid = 0
        if pid > 1 and _is_pid_alive(pid):
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            for _ in range(50):
                if not _is_pid_alive(pid):
                    break
                time.sleep(0.1)
            if _is_pid_alive(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        try:
            os.remove(pid_file)
        except OSError:
            pass
    # Wait briefly for kernel interface teardown
    for _ in range(20):
        if not _iface_exists(iface):
            break
        time.sleep(0.1)
    # If the interface still lingers, remove it explicitly (helper has privileges)
    if _iface_exists(iface):
        subprocess.run(["ip", "link", "del", "dev", iface], capture_output=True, timeout=3)
    # Ensure no leftover kernel rules or routes point to table 2022
    _cleanup_table_2022()
    return 0


def _start_tun(
    singbox_bin: str,
    config_file: str,
    pid_file: str,
    log_file: str,
    iface: str,
    stop_legacy: bool,
) -> int:
    if not os.path.isfile(singbox_bin) or not os.access(singbox_bin, os.X_OK):
        sys.stderr.write(f"sing-box binary not found: {singbox_bin}\n")
        return 1
    if not os.path.isfile(config_file):
        sys.stderr.write(f"TUN config file not found: {config_file}\n")
        return 1

    chk = subprocess.run([singbox_bin, "check", "-c", config_file], capture_output=True, text=True)
    if chk.returncode != 0:
        sys.stderr.write((chk.stderr or chk.stdout or "Invalid sing-box TUN config").strip() + "\n")
        return 1

    if stop_legacy:
        subprocess.run(["systemctl", "stop", "xray-tun"], capture_output=True, timeout=8)

    _stop_pid_file(pid_file, iface=iface)

    os.makedirs(os.path.dirname(os.path.abspath(pid_file)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
    log_fp = open(log_file, "a", encoding="utf-8")
    proc = subprocess.Popen(
        [singbox_bin, "run", "-c", config_file],
        stdout=log_fp,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    log_fp.close()

    with open(pid_file, "w", encoding="utf-8") as f:
        f.write(str(proc.pid))

    # Hand ownership back to the invoking user (pkexec/sudo) so later
    # unprivileged TUN toggles can append logs without Permission denied.
    try:
        uid = int(os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID") or "0")
    except ValueError:
        uid = 0
    gid_raw = os.environ.get("PKEXEC_GID") or os.environ.get("SUDO_GID")
    if gid_raw:
        try:
            gid = int(gid_raw)
        except ValueError:
            gid = uid
    elif uid > 0:
        try:
            gid = pwd.getpwuid(uid).pw_gid
        except KeyError:
            gid = uid
    else:
        gid = 0
    for path in (pid_file, log_file):
        try:
            os.chmod(path, 0o644)
            if uid > 0:
                os.chown(path, uid, gid)
        except OSError:
            pass

    for _ in range(50):
        if proc.poll() is not None:
            _stop_pid_file(pid_file, iface=iface)
            sys.stderr.write("sing-box TUN exited unexpectedly; check tun.log\n")
            return 1
        if _iface_exists(iface):
            return 0
        time.sleep(0.1)

    _stop_pid_file(pid_file, iface=iface)
    sys.stderr.write(f"Timed out waiting for {iface} interface\n")
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="XHM TUN Helper")
    sub = parser.add_subparsers(dest="action", required=True)

    p_start = sub.add_parser("start")
    p_start.add_argument("singbox_bin")
    p_start.add_argument("config_file")
    p_start.add_argument("pid_file")
    p_start.add_argument("log_file")
    p_start.add_argument("--iface", default="xhm-tun")
    p_start.add_argument("--stop-legacy", action="store_true")

    p_stop = sub.add_parser("stop")
    p_stop.add_argument("pid_file")
    p_stop.add_argument("--iface", default="xhm-tun")

    args = parser.parse_args()
    if args.action == "start":
        return _start_tun(
            args.singbox_bin,
            args.config_file,
            args.pid_file,
            args.log_file,
            args.iface,
            args.stop_legacy,
        )
    return _stop_pid_file(args.pid_file, iface=args.iface)


if __name__ == "__main__":
    sys.exit(main())
