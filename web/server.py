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

sys.path.insert(0, os.path.expanduser("~/.local/lib"))
import xhm_core

WEB_DIR = os.path.dirname(os.path.abspath(__file__))
PORT = 18501

# Shared proxy manager & concurrency lock
manager = xhm_core.ProxyManager()
manager_lock = threading.Lock()


class XhmApiHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silent logs for clean output
        return

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
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
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_HEAD(self):
        self._handle_get_or_head(send_body=False)

    def do_GET(self):
        self._handle_get_or_head(send_body=True)

    def _handle_get_or_head(self, send_body=True):
        parsed_path = self.path.split("?")[0]

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
            if send_body:
                self.send_json(data)
            else:
                body = json.dumps(data, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
            return

        elif parsed_path == "/api/nodes":
            nodes = xhm_core.load_all_nodes()
            if send_body:
                self.send_json(nodes)
            else:
                body = json.dumps(nodes, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
            return

        elif parsed_path == "/api/logs":
            log_file = xhm_core.LOG_FILE
            lines_to_return = []
            if os.path.exists(log_file):
                try:
                    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                        lines_to_return = [line.rstrip("\r\n") for line in f.readlines()[-150:]]
                except Exception as e:
                    lines_to_return = [f"Error reading log file: {e}"]
            else:
                lines_to_return = ["No log records yet. Start a proxy connection to view core output."]

            data = {"logs": lines_to_return, "count": len(lines_to_return)}
            if send_body:
                self.send_json(data)
            else:
                body = json.dumps(data, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
            return

        elif parsed_path == "/api/subscriptions":
            subs = xhm_core.CustomConfigStore.load_subscriptions()
            if send_body:
                self.send_json(subs)
            else:
                body = json.dumps(subs, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
            return

        elif parsed_path == "/api/traffic-stats":
            query = urllib.parse.parse_qs(self.path.split("?")[1]) if "?" in self.path else {}
            node_key = query.get("node_key", [None])[0]
            view = query.get("view", ["summary"])[0]
            date_str = query.get("date", [None])[0]
            month_str = query.get("month", [None])[0]
            year_val = query.get("year", [None])[0]
            try:
                limit_val = int(query.get("limit", [50])[0])
            except (ValueError, TypeError):
                limit_val = 50

            if view == "hourly":
                data = xhm_core.TrafficTracker.get_hourly(node_key=node_key, date_str=date_str)
            elif view == "daily":
                data = xhm_core.TrafficTracker.get_daily(node_key=node_key, month_str=month_str)
            elif view == "monthly":
                data = xhm_core.TrafficTracker.get_monthly(node_key=node_key, year_val=int(year_val) if year_val else None)
            elif view == "yearly":
                data = xhm_core.TrafficTracker.get_yearly(node_key=node_key)
            elif view == "nodes":
                data = xhm_core.TrafficTracker.get_nodes_traffic()
            elif view == "sessions":
                data = xhm_core.TrafficTracker.get_sessions(node_key=node_key, limit=limit_val)
            else:
                data = xhm_core.TrafficTracker.get_summary(node_key=node_key)

            if send_body:
                self.send_json(data)
            else:
                body = json.dumps(data, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
            return

        # Static assets
        rel_path = "index.html" if parsed_path in ("/", "/index.html") else parsed_path.lstrip("/")
        file_path = os.path.normpath(os.path.join(WEB_DIR, rel_path))
        if os.path.commonpath([WEB_DIR, file_path]) == WEB_DIR and os.path.isfile(file_path):
            _, ext = os.path.splitext(file_path)
            content_type = self.MIME_TYPES.get(ext.lower(), "application/octet-stream")
            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Access-Control-Allow-Origin", "*")
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
        parsed_path = self.path.split("?")[0]
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8", errors="ignore") if content_len > 0 else ""
        req_data = {}
        if body:
            try:
                req_data = json.loads(body)
            except Exception:
                pass

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
                        with open(xhm_core.STATE_FILE, "w", encoding="utf-8") as f:
                            json.dump(st, f, indent=2)
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
                        (n.get("raw") or {}).get("sni") or n.get("sni")
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
            text = req_data.get("text", "").strip()
            name = req_data.get("name", "").strip()
            if not text:
                self.send_json({"count": 0, "message": "Input text is empty"}, status=400)
                return

            added_count = 0
            err_msg = ""
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                if line.startswith("http://") or line.startswith("https://"):
                    try:
                        c, msg = xhm_core.CustomConfigStore.add_subscription(line, name=name)
                        added_count += c
                    except Exception as e:
                        err_msg = str(e)
                else:
                    node = xhm_core.CustomConfigStore.add_node_from_link(line, custom_name=name)
                    if node:
                        added_count += 1

            if added_count > 0:
                self.send_json({"count": added_count, "message": f"Successfully imported {added_count} proxy nodes"})
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
            log_file = xhm_core.LOG_FILE
            try:
                if os.path.exists(log_file):
                    with open(log_file, "w", encoding="utf-8") as f:
                        f.write("")
                self.send_json({"success": True, "message": "Logs cleared"})
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
            self.send_json({"success": success})
            return

        self.send_error(404, "Endpoint Not Found")


def run_server(port: int = PORT):
    server = ThreadingHTTPServer(("127.0.0.1", port), XhmApiHandler)
    print(f"XHM Web Server running at http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    run_server()
