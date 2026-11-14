#!/usr/bin/env python3
"""
XHM Local Web Server & REST API.
Ties XHM Core (parsers, proxy manager, ping engine) to the modern HTML5 frontend.
"""

import os
import sys
import json
import time
import threading
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from concurrent.futures import ThreadPoolExecutor

_LOCAL_REPO_LIB = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
_USER_LIB = os.path.expanduser("~/.local/lib")
for _lib_dir in (_LOCAL_REPO_LIB, _USER_LIB):
    if os.path.isdir(_lib_dir) and _lib_dir not in sys.path:
        sys.path.append(_lib_dir)
import xhm_core

WEB_DIR = os.path.realpath(os.path.dirname(os.path.abspath(__file__)))
PORT = 18501

# Shared proxy manager & concurrency lock
manager = xhm_core.ProxyManager()
manager_lock = threading.Lock()
update_lock = threading.Lock()


def _is_local_origin(url_val: str) -> bool:
    if not url_val:
        return False
    try:
        u = urllib.parse.urlparse(url_val)
        return u.scheme in ("http", "https") and u.hostname in ("127.0.0.1", "localhost", "::1")
    except Exception:
        return False


def _ping_sni_for_node(node: dict) -> str:
    ptype = str(node.get("type") or "").lower()
    raw = node.get("raw") if isinstance(node.get("raw"), dict) else node
    if ptype == "ssh":
        cfg_type = str(raw.get("ssh_config_type") or node.get("ssh_config_type") or "")
        sni = str(raw.get("sni") or node.get("sni") or "")
        if cfg_type in ("SSH-TLS", "SSH-SSL") or (sni and sni != str(node.get("server") or "")):
            return sni or str(node.get("server") or "")
        return ""
    tls = raw.get("tls") if isinstance(raw.get("tls"), dict) else {}
    if tls.get("enabled"):
        return str(tls.get("server_name") or node.get("server") or "")
    return ""


class XhmHttpServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


class XhmApiHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silent logs for clean output
        return

    def _send_cors_headers(self):
        origin = self.headers.get("Origin", "")
        if origin and _is_local_origin(origin):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def _check_browser_csrf(self) -> bool:
        origin = self.headers.get("Origin", "")
        if origin:
            return _is_local_origin(origin)
        referer = self.headers.get("Referer", "")
        if referer:
            return _is_local_origin(referer)
        # Allow local CLI/curl clients without Origin/Referer headers
        return True

    def send_json(self, data, status: int = 200, send_body: bool = True):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    MIME_TYPES = {
        ".html": "text/html; charset=utf-8",
        ".css": "text/css; charset=utf-8",
        ".js": "application/javascript; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".svg": "image/svg+xml",
        ".ico": "image/x-icon",
        ".webp": "image/webp",
    }

    def do_OPTIONS(self):
        origin = self.headers.get("Origin", "")
        if origin and not _is_local_origin(origin):
            self.send_json({"error": "Forbidden cross-origin request"}, status=403)
            return
        self.send_response(200)
        self._send_cors_headers()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_HEAD(self):
        self._handle_get_or_head(send_body=False)

    def do_GET(self):
        self._handle_get_or_head(send_body=True)

    def _handle_get_or_head(self, send_body=True):
        parsed = urllib.parse.urlparse(self.path)
        parsed_path = parsed.path

        if parsed_path == "/api/status":
            uptime = "00:00:00"
            if manager.connected and manager.start_time:
                uptime = xhm_core.format_duration(int(time.time() - manager.start_time))

            traffic = manager.query_traffic_stats()
            raw_active = manager.active_node
            safe_active = None
            if isinstance(raw_active, dict):
                safe_active = {
                    k: raw_active.get(k)
                    for k in ("id", "profile", "profile_id", "tag", "type", "server", "port", "is_custom")
                    if k in raw_active
                }
                if not safe_active.get("id") and raw_active.get("raw"):
                    safe_active["id"] = xhm_core.get_node_identity(raw_active)
            data = {
                "connected": manager.connected,
                "reconnecting": bool(getattr(manager, "_reconnecting", False)),
                "active_node": safe_active,
                "core": manager.core_name or "Xray Core",
                "proxy_port": manager.proxy_port,
                "system_proxy": xhm_core.get_gnome_proxy_state(),
                "tun_mode": xhm_core.is_tun_active(),
                "tun_supported": xhm_core.is_tun_supported(),
                "uptime": uptime,
                "status_msg": manager.status_msg,
                "traffic": traffic,
                "allow_lan": manager.allow_lan,
            }
            self.send_json(data, send_body=send_body)
            return

        elif parsed_path == "/api/nodes":
            nodes = xhm_core.load_all_nodes()
            self.send_json(nodes, send_body=send_body)
            return

        elif parsed_path == "/api/logs":
            query = urllib.parse.parse_qs(parsed.query)
            source = (query.get("source", ["core"])[0] or "core").lower()
            if source == "tun":
                alt_tun = f"{xhm_core.TUN_LOG_FILE}.{os.getuid()}"
                log_file = alt_tun if (os.path.exists(alt_tun) and (not os.path.exists(xhm_core.TUN_LOG_FILE) or os.path.getmtime(alt_tun) >= os.path.getmtime(xhm_core.TUN_LOG_FILE))) else xhm_core.TUN_LOG_FILE
                empty_msg = "No TUN log records yet. Toggle TUN Mode to view sing-box TUN output."
            else:
                log_file = xhm_core.LOG_FILE
                empty_msg = "No log records yet. Start a proxy connection to view core output."

            lines_to_return = []
            if os.path.exists(log_file):
                try:
                    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                        lines_to_return = [line.rstrip("\r\n") for line in f.readlines()[-150:]]
                except Exception as e:
                    lines_to_return = [f"Error reading log file: {e}"]
            else:
                lines_to_return = [empty_msg]

            data = {"logs": lines_to_return, "count": len(lines_to_return), "source": source}
            self.send_json(data, send_body=send_body)
            return

        elif parsed_path == "/api/subscriptions":
            subs = xhm_core.CustomConfigStore.load_subscriptions()
            self.send_json(subs, send_body=send_body)
            return

        elif parsed_path == "/api/version":
            meta = xhm_core.get_installed_meta()
            self.send_json(meta, send_body=send_body)
            return

        elif parsed_path == "/api/check-update":
            query = urllib.parse.parse_qs(parsed.query)
            force_raw = str(query.get("force", ["0"])[0]).lower()
            force = force_raw in ("1", "true", "yes")
            with manager_lock:
                proxy_port = (manager.proxy_port + 1) if manager.connected else None
            data = xhm_core.check_for_updates(force=force, http_proxy_port=proxy_port)
            self.send_json(data, send_body=send_body)
            return

        elif parsed_path == "/api/traffic-stats":
            query = urllib.parse.parse_qs(parsed.query)
            node_key = query.get("node_key", [None])[0]
            view = query.get("view", ["summary"])[0]
            date_str = query.get("date", [None])[0]
            month_str = query.get("month", [None])[0]
            year_raw = query.get("year", [None])[0]
            try:
                year_val = int(year_raw) if year_raw else None
            except (ValueError, TypeError):
                year_val = None
            try:
                limit_val = max(1, min(int(query.get("limit", [50])[0]), 500))
            except (ValueError, TypeError):
                limit_val = 50

            if view == "hourly":
                data = xhm_core.TrafficTracker.get_hourly(node_key=node_key, date_str=date_str)
            elif view == "daily":
                data = xhm_core.TrafficTracker.get_daily(node_key=node_key, month_str=month_str)
            elif view == "monthly":
                data = xhm_core.TrafficTracker.get_monthly(node_key=node_key, year_val=year_val)
            elif view == "yearly":
                data = xhm_core.TrafficTracker.get_yearly(node_key=node_key)
            elif view == "nodes":
                data = xhm_core.TrafficTracker.get_nodes_traffic()
            elif view == "sessions":
                data = xhm_core.TrafficTracker.get_sessions(node_key=node_key, limit=limit_val)
            else:
                data = xhm_core.TrafficTracker.get_summary(node_key=node_key)

            self.send_json(data, send_body=send_body)
            return

        # Static assets (explicit MIME allowlist — never expose server.py or dotfiles)
        rel_path = "index.html" if parsed_path in ("/", "/index.html") else parsed_path.lstrip("/")
        if rel_path.startswith(".") or "/." in rel_path:
            self.send_error(404, "Endpoint Not Found")
            return
        file_path = os.path.realpath(os.path.join(WEB_DIR, rel_path))
        _, ext = os.path.splitext(file_path)
        content_type = self.MIME_TYPES.get(ext.lower())
        if content_type and os.path.commonpath([WEB_DIR, file_path]) == WEB_DIR and os.path.isfile(file_path):
            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(content)))
                self._send_cors_headers()
                if ext.lower() in (".png", ".svg", ".ico", ".webp"):
                    self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                if send_body:
                    self.wfile.write(content)
                return
            except Exception as e:
                self.send_error(500, f"Cannot read file: {e}")
                return

        self.send_error(404, "Endpoint Not Found")

    def do_POST(self):
        if not self._check_browser_csrf():
            self.send_json({"error": "Forbidden cross-origin request"}, status=403)
            return

        parsed_path = urllib.parse.urlparse(self.path).path
        try:
            content_len = int(self.headers.get("Content-Length", 0))
        except (ValueError, TypeError):
            self.send_json({"error": "Invalid Content-Length"}, status=400)
            return
        if content_len < 0 or content_len > 16 * 1024 * 1024:
            self.send_json({"error": "Payload too large"}, status=413)
            return

        body = self.rfile.read(content_len).decode("utf-8", errors="ignore") if content_len > 0 else ""
        req_data = {}
        if body.strip():
            try:
                parsed_json = json.loads(body)
            except Exception:
                self.send_json({"error": "Invalid JSON body"}, status=400)
                return
            if not isinstance(parsed_json, dict):
                self.send_json({"error": "JSON body must be an object"}, status=400)
                return
            req_data = parsed_json

        if parsed_path == "/api/connect":
            node_id = req_data.get("id")
            srv = req_data.get("server")
            prt = req_data.get("port")
            ptype = req_data.get("type", "").lower()
            try:
                prt_int = int(prt)
            except (ValueError, TypeError):
                prt_int = 0

            nodes = xhm_core.load_all_nodes()
            target = None
            if node_id:
                for n in nodes:
                    if (n.get("id") or xhm_core.get_node_identity(n)) == node_id:
                        target = n
                        break
            if not target:
                for n in nodes:
                    if n.get("server") == srv and int(n.get("port", 0)) == prt_int:
                        if not ptype or n.get("type", "").lower() == ptype:
                            target = n
                            break

            with manager_lock:
                if target:
                    success = manager.start(target)
                    self.send_json({"success": success, "status_msg": manager.status_msg})
                else:
                    self.send_json({"success": False, "status_msg": "Target node not found"}, status=400)
            return

        elif parsed_path == "/api/disconnect":
            with manager_lock:
                manager.stop()
                msg = manager.status_msg
            self.send_json({"success": True, "status_msg": msg, "tun_mode": xhm_core.is_tun_active()})
            return

        elif parsed_path == "/api/toggle":
            with manager_lock:
                manager.toggle()
            self.send_json({"success": True, "connected": manager.connected})
            return

        elif parsed_path == "/api/toggle-tun":
            enable = bool(req_data.get("enable"))
            with manager_lock:
                success, msg = xhm_core.set_tun_mode_detailed(enable, manager=manager)
            self.send_json({"success": success, "tun_mode": xhm_core.is_tun_active(), "status_msg": msg})
            return

        elif parsed_path == "/api/toggle-system-proxy":
            enable = bool(req_data.get("enable"))
            with manager_lock:
                http_p = manager.proxy_port + 1
                xhm_core.set_gnome_proxy(enable, manager.proxy_port, http_port=http_p)
                if os.path.exists(xhm_core.STATE_FILE):
                    try:
                        with open(xhm_core.STATE_FILE, "r", encoding="utf-8") as f:
                            st = json.load(f)
                        st["system_proxy"] = enable
                        xhm_core._atomic_write_json(xhm_core.STATE_FILE, st)
                    except Exception:
                        pass
            self.send_json({"success": True, "enabled": enable})
            return

        elif parsed_path == "/api/toggle-lan":
            enable = bool(req_data.get("enable"))
            with manager_lock:
                manager.allow_lan = enable
                if manager.connected and manager.active_node:
                    manager.start(manager.active_node)
            self.send_json({"success": True, "allow_lan": manager.allow_lan})
            return

        elif parsed_path == "/api/terminal-proxy-command":
            port = manager.proxy_port
            http_p = port + 1
            cmd = f'export http_proxy="http://127.0.0.1:{http_p}" https_proxy="http://127.0.0.1:{http_p}" all_proxy="socks5://127.0.0.1:{port}"'
            self.send_json({"command": cmd, "script_path": xhm_core.ENV_SCRIPT_FILE})
            return

        elif parsed_path == "/api/ping":
            srv = req_data.get("server")
            prt = req_data.get("port")
            sni = req_data.get("sni")
            try:
                prt_int = int(prt)
            except (ValueError, TypeError):
                prt_int = 0
            ms = xhm_core.test_tcp_ping(srv, prt_int, sni=sni) if srv and prt_int else None
            self.send_json({"server": srv, "port": prt_int, "ping": ms})
            return

        elif parsed_path == "/api/ping-all":
            nodes = xhm_core.load_all_nodes()
            with ThreadPoolExecutor(max_workers=16) as executor:
                futures = {
                    executor.submit(
                        xhm_core.test_tcp_ping,
                        n["server"],
                        int(n["port"]),
                        2.2,
                        _ping_sni_for_node(n) or None,
                    ): n
                    for n in nodes
                }
                for f in futures:
                    n = futures[f]
                    try:
                        n["ping"] = f.result()
                    except Exception:
                        n["ping"] = None
            self.send_json(nodes)
            return

        elif parsed_path == "/api/add-config":
            text = str(req_data.get("text") or "").strip()
            name = str(req_data.get("name") or "").strip()
            replace_id = str(req_data.get("replace_id") or "").strip()
            if not text:
                self.send_json({"count": 0, "message": "Input text is empty"}, status=400)
                return

            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            added_count = 0
            err_msg = ""
            last_msg = ""
            for line in lines:
                if line.startswith("http://") or line.startswith("https://"):
                    try:
                        c, msg = xhm_core.CustomConfigStore.add_subscription(line, name=name)
                        added_count += c
                        last_msg = msg
                    except Exception as e:
                        err_msg = str(e)
                else:
                    rid = replace_id if len(lines) == 1 else ""
                    node = xhm_core.CustomConfigStore.add_node_from_link(line, custom_name=name, replace_id=rid)
                    if node:
                        added_count += 1

            if added_count > 0:
                self.send_json({
                    "count": added_count,
                    "message": last_msg or f"Successfully imported {added_count} proxy nodes",
                })
            else:
                self.send_json({"count": 0, "message": err_msg or "No valid proxy URLs recognized"}, status=400)
            return

        elif parsed_path == "/api/delete-config":
            node_id = req_data.get("id") or ""
            srv = req_data.get("server")
            prt = req_data.get("port")
            ptype = req_data.get("type", "").lower()
            try:
                prt_int = int(prt)
            except (ValueError, TypeError):
                prt_int = 0
            if node_id or (srv and prt_int):
                res = xhm_core.CustomConfigStore.delete_node(srv or "", prt_int, ptype, node_id=node_id)
                self.send_json({"success": res})
            else:
                self.send_json({"success": False}, status=400)
            return

        elif parsed_path == "/api/clear-logs":
            source = str(req_data.get("source") or "core").lower()
            if source == "tun":
                targets = [xhm_core.TUN_LOG_FILE, f"{xhm_core.TUN_LOG_FILE}.{os.getuid()}"]
            else:
                targets = [xhm_core.LOG_FILE]
            try:
                cleared_any = False
                for log_file in targets:
                    if os.path.exists(log_file):
                        try:
                            with open(log_file, "w", encoding="utf-8") as f:
                                f.write("")
                            cleared_any = True
                        except PermissionError:
                            if not cleared_any:
                                raise
                self.send_json({"success": True, "message": "Logs cleared", "source": source})
            except Exception as e:
                self.send_json({"success": False, "error": str(e)}, status=500)
            return

        elif parsed_path == "/api/test-connectivity":
            res = manager.test_live_web_latency()
            self.send_json(res)
            return

        elif parsed_path == "/api/clear-all-custom":
            with manager_lock:
                success = xhm_core.CustomConfigStore.clear_all_nodes()
            self.send_json({"success": success})
            return

        elif parsed_path == "/api/update-subscriptions":
            with manager_lock:
                count, msg = xhm_core.CustomConfigStore.update_all_subscriptions()
            self.send_json({"count": count, "message": msg})
            return

        elif parsed_path == "/api/delete-subscription":
            url = req_data.get("url", "")
            with manager_lock:
                success = xhm_core.CustomConfigStore.delete_subscription(url)
            self.send_json({"success": success})
            return

        elif parsed_path == "/api/traffic-reset":
            node_key = req_data.get("node_key")
            with manager_lock:
                success = xhm_core.TrafficTracker.reset_traffic(node_key=node_key)
                if success:
                    if not node_key or node_key == "__GLOBAL__":
                        manager.reset_session_counters()
                    elif manager.active_node:
                        an = manager.active_node
                        active_key = f"{an.get('server') or ''}:{int(an.get('port') or 0)}:{str(an.get('type') or 'vless').lower()}"
                        if active_key == node_key:
                            manager.reset_session_counters()
            self.send_json({"success": success})
            return

        elif parsed_path == "/api/apply-update":
            if not update_lock.acquire(blocking=False):
                self.send_json({"success": False, "updated": False, "message": "An update is already in progress."}, status=409)
                return
            try:
                with manager_lock:
                    proxy_port = (manager.proxy_port + 1) if manager.connected else None
                result = xhm_core.apply_git_update(http_proxy_port=proxy_port)
                self.send_json(result)
            except Exception as e:
                self.send_json({"success": False, "updated": False, "message": f"Update error: {e}"}, status=500)
            finally:
                update_lock.release()
            return

        self.send_error(404, "Endpoint Not Found")


def run_server(port: int = PORT):
    server = XhmHttpServer(("127.0.0.1", port), XhmApiHandler)
    print(f"XHM Web Server running at http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
