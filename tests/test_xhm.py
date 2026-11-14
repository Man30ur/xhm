#!/usr/bin/env python3
"""
Isolated test suite for XHM.
All state, config, runtime, DB, GNOME proxy, subprocess, and HTTP server checks
run exclusively against temporary directories, mocked subprocesses/sockets, and
ephemeral ports so active system proxy/TUN/GUI sessions remain untouched.
"""

import argparse
import atexit
import base64
import contextlib
import curses
import importlib.machinery
import importlib.util
import io
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import types
import unittest
import urllib.error
import urllib.request
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
LIB_DIR = os.path.join(REPO_ROOT, "lib")
WEB_DIR = os.path.join(REPO_ROOT, "web")
BIN_XHM = os.path.join(REPO_ROOT, "bin", "xhm")

if LIB_DIR not in sys.path:
    sys.path.insert(0, LIB_DIR)

import xhm_core  # noqa: E402

_ORIG_PATHS = {
    "XHM_DATA_DIR": xhm_core.XHM_DATA_DIR,
    "CUSTOM_CONFIGS_FILE": xhm_core.CUSTOM_CONFIGS_FILE,
    "SUBSCRIPTIONS_FILE": xhm_core.SUBSCRIPTIONS_FILE,
    "TRAFFIC_DB_FILE": xhm_core.TRAFFIC_DB_FILE,
    "ENV_SCRIPT_FILE": xhm_core.ENV_SCRIPT_FILE,
    "SAVED_SYSTEM_PROXY_FILE": xhm_core.SAVED_SYSTEM_PROXY_FILE,
    "INSTALL_META_FILE": xhm_core.INSTALL_META_FILE,
    "UPDATE_CACHE_FILE": xhm_core.UPDATE_CACHE_FILE,
    "RUNTIME_DIR": xhm_core.RUNTIME_DIR,
    "STATE_FILE": xhm_core.STATE_FILE,
    "RUN_CONFIG_FILE": xhm_core.RUN_CONFIG_FILE,
    "XRAY_CONFIG_FILE": xhm_core.XRAY_CONFIG_FILE,
    "SINGBOX_CONFIG_FILE": xhm_core.SINGBOX_CONFIG_FILE,
    "LOG_FILE": xhm_core.LOG_FILE,
    "TUN_MANAGED_FILE": xhm_core.TUN_MANAGED_FILE,
    "TUN_PID_FILE": xhm_core.TUN_PID_FILE,
    "TUN_CONFIG_FILE": xhm_core.TUN_CONFIG_FILE,
    "TUN_LOG_FILE": xhm_core.TUN_LOG_FILE,
}


def _apply_temp_paths(base_dir: str):
    data_dir = os.path.join(base_dir, "data")
    runtime_dir = os.path.join(base_dir, "runtime")
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(runtime_dir, exist_ok=True)

    xhm_core.XHM_DATA_DIR = data_dir
    xhm_core.CUSTOM_CONFIGS_FILE = os.path.join(data_dir, "custom_configs.json")
    xhm_core.SUBSCRIPTIONS_FILE = os.path.join(data_dir, "subscriptions.json")
    xhm_core.TRAFFIC_DB_FILE = os.path.join(data_dir, "traffic.db")
    xhm_core.ENV_SCRIPT_FILE = os.path.join(data_dir, "proxy_env.sh")
    xhm_core.SAVED_SYSTEM_PROXY_FILE = os.path.join(data_dir, "saved_system_proxy.json")
    xhm_core.INSTALL_META_FILE = os.path.join(data_dir, "install_meta.json")
    xhm_core.UPDATE_CACHE_FILE = os.path.join(data_dir, "update_cache.json")

    xhm_core.RUNTIME_DIR = runtime_dir
    xhm_core.STATE_FILE = os.path.join(runtime_dir, "state.json")
    xhm_core.RUN_CONFIG_FILE = os.path.join(runtime_dir, "run.json")
    xhm_core.XRAY_CONFIG_FILE = os.path.join(runtime_dir, "xray.json")
    xhm_core.SINGBOX_CONFIG_FILE = os.path.join(runtime_dir, "singbox.json")
    xhm_core.LOG_FILE = os.path.join(runtime_dir, "core.log")
    xhm_core.TUN_MANAGED_FILE = os.path.join(runtime_dir, "tun_managed")
    xhm_core.TUN_PID_FILE = os.path.join(runtime_dir, "tun.pid")
    xhm_core.TUN_CONFIG_FILE = os.path.join(runtime_dir, "singbox-tun.json")
    xhm_core.TUN_LOG_FILE = os.path.join(runtime_dir, "tun.log")
    xhm_core.TrafficTracker._db_initialized = False


def _restore_orig_paths():
    for k, v in _ORIG_PATHS.items():
        setattr(xhm_core, k, v)
    xhm_core.TrafficTracker._db_initialized = False


def _wrap_node(link: str) -> dict:
    ob = xhm_core.parse_proxy_link(link)
    assert ob is not None, f"Failed to parse link: {link}"
    node = {
        "profile_id": "custom",
        "profile": "Custom",
        "is_custom": True,
        "tag": ob["tag"],
        "type": ob["type"],
        "server": ob["server"],
        "port": ob["server_port"],
        "raw": ob,
        "link": link,
        "ping": None,
    }
    node["id"] = xhm_core.get_node_identity(node)
    return node


# Redirect globals into a staging temp dir BEFORE importing web.server, whose
# module-level initialization constructs ProxyManager().
_BOOT_TMP = tempfile.TemporaryDirectory(prefix="xhm_test_boot_")
atexit.register(_BOOT_TMP.cleanup)
_apply_temp_paths(_BOOT_TMP.name)

_web_spec = importlib.util.spec_from_file_location("xhm_web_server", os.path.join(WEB_DIR, "server.py"))
web_server = importlib.util.module_from_spec(_web_spec)
_web_spec.loader.exec_module(web_server)

_cli_loader = importlib.machinery.SourceFileLoader("xhm_cli_mod", BIN_XHM)
_cli_spec = importlib.util.spec_from_loader("xhm_cli_mod", _cli_loader)
cli_mod = importlib.util.module_from_spec(_cli_spec)
_cli_spec.loader.exec_module(cli_mod)

_restore_orig_paths()


class _IsolatedXhmTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self._tmpdir = tempfile.TemporaryDirectory(prefix="xhm_test_")
        _apply_temp_paths(self._tmpdir.name)
        self.assertNotEqual(xhm_core.RUNTIME_DIR, "/tmp/xhm")
        self.assertTrue(xhm_core.TRAFFIC_DB_FILE.startswith(self._tmpdir.name))

    def tearDown(self):
        _restore_orig_paths()
        self._tmpdir.cleanup()
        super().tearDown()


class _FakePopenProc:
    _next_pid = 900001

    def __init__(self, alive=True):
        _FakePopenProc._next_pid += 1
        self.pid = _FakePopenProc._next_pid
        self._alive = alive

    def poll(self):
        return None if self._alive else 0

    def wait(self, timeout=None):
        self._alive = False
        return 0


class _DummyHTTPResponse:
    def __init__(self, body_bytes: bytes):
        self._body = body_bytes

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TestUriParsersAndRoundTrips(_IsolatedXhmTestCase):
    def test_vless_non_tls_port_443_and_decoded_params(self):
        link = (
            "vless://11111111-1111-1111-1111-111111111111@vless.example.com:443"
            "?encryption=aes-128-gcm&security=none&type=xhttp&path=%2Fmy%20path"
            "&host=cdn.example.com&mode=packet-up#My%20VLESS%20Node"
        )
        ob = xhm_core.parse_proxy_link(link)
        self.assertIsNotNone(ob)
        self.assertEqual(ob["type"], "vless")
        self.assertEqual(ob["tag"], "My VLESS Node")
        self.assertEqual(ob["encryption"], "aes-128-gcm")
        self.assertFalse(ob["tls"]["enabled"])
        self.assertNotIn("server_name", ob["tls"])
        self.assertEqual(ob["transport"]["type"], "xhttp")
        self.assertEqual(ob["transport"]["path"], "/my path")
        self.assertEqual(ob["transport"]["mode"], "packet-up")

        rt_link = xhm_core.outbound_to_link(ob)
        rt_ob = xhm_core.parse_proxy_link(rt_link)
        self.assertEqual(rt_ob["transport"]["path"], "/my path")
        self.assertEqual(rt_ob["transport"]["mode"], "packet-up")
        self.assertFalse(rt_ob["tls"]["enabled"])
        self.assertEqual(rt_ob["encryption"], "aes-128-gcm")

    def test_vless_reality_grpc_roundtrip(self):
        link = (
            "vless://22222222-2222-2222-2222-222222222222@reality.example.com:8443"
            "?security=reality&sni=www.google.com&fp=chrome&pbk=PUBKEY123&sid=ab12"
            "&spx=%2Fspider&flow=xtls-rprx-vision&type=grpc&serviceName=my.GrpcSvc"
            "&mode=multi#RealityGRPC"
        )
        ob = xhm_core.parse_proxy_link(link)
        self.assertIsNotNone(ob)
        self.assertTrue(ob["tls"]["enabled"])
        self.assertTrue(ob["tls"]["reality"]["enabled"])
        self.assertEqual(ob["tls"]["reality"]["public_key"], "PUBKEY123")
        self.assertEqual(ob["tls"]["reality"]["short_id"], "ab12")
        self.assertEqual(ob["tls"]["reality"]["spider_x"], "/spider")
        self.assertEqual(ob["transport"]["type"], "grpc")
        self.assertEqual(ob["transport"]["service_name"], "my.GrpcSvc")
        self.assertEqual(ob["transport"]["mode"], "multi")

        rt = xhm_core.parse_proxy_link(xhm_core.outbound_to_link(ob))
        self.assertEqual(rt["tls"]["reality"]["public_key"], "PUBKEY123")
        self.assertEqual(rt["tls"]["reality"]["short_id"], "ab12")
        self.assertEqual(rt["transport"]["service_name"], "my.GrpcSvc")
        self.assertEqual(rt["flow"], "xtls-rprx-vision")

    def test_vless_splithttp_and_httpupgrade(self):
        for tp in ("splithttp", "httpupgrade"):
            ob = xhm_core.parse_proxy_link(
                f"vless://33333333-3333-3333-3333-333333333333@tp.example.com:443"
                f"?security=tls&sni=tp.example.com&type={tp}&path=%2Fws&host=h.example.com#TP"
            )
            self.assertEqual(ob["transport"]["type"], tp)
            self.assertEqual(ob["transport"]["path"], "/ws")
            rt = xhm_core.parse_proxy_link(xhm_core.outbound_to_link(ob))
            self.assertEqual(rt["transport"]["type"], tp)

    def test_vmess_empty_aid_scy_fp_alpn_and_roundtrip(self):
        payload = {
            "v": "2",
            "ps": "VMess Node",
            "add": "vm.example.com",
            "port": "443",
            "id": "44444444-4444-4444-4444-444444444444",
            "aid": "",
            "scy": "chacha20-poly1305",
            "net": "ws",
            "type": "none",
            "host": "cdn.vm.example.com",
            "path": "/vm",
            "tls": "tls",
            "sni": "vm.example.com",
            "fp": "firefox",
            "alpn": "h2,http/1.1",
        }
        link = "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()
        ob = xhm_core.parse_proxy_link(link)
        self.assertIsNotNone(ob)
        self.assertEqual(ob["alter_id"], 0)
        self.assertEqual(ob["security"], "chacha20-poly1305")
        self.assertEqual(ob["tls"]["utls"]["fingerprint"], "firefox")
        self.assertEqual(ob["tls"]["alpn"], ["h2", "http/1.1"])
        self.assertEqual(ob["transport"]["type"], "ws")

        rt = xhm_core.parse_proxy_link(xhm_core.outbound_to_link(ob))
        self.assertEqual(rt["security"], "chacha20-poly1305")
        self.assertEqual(rt["tls"]["alpn"], ["h2", "http/1.1"])
        self.assertEqual(rt["tls"]["utls"]["fingerprint"], "firefox")

    def test_trojan_colon_password_and_security_none(self):
        link = "trojan://user:p%40ss:secret@troj.example.com:443?security=none&type=tcp#MyTrojan"
        ob = xhm_core.parse_proxy_link(link)
        self.assertIsNotNone(ob)
        self.assertEqual(ob["password"], "user:p@ss:secret")
        self.assertFalse(ob["tls"]["enabled"])
        rt = xhm_core.parse_proxy_link(xhm_core.outbound_to_link(ob))
        self.assertEqual(rt["password"], "user:p@ss:secret")
        self.assertFalse(rt["tls"]["enabled"])

    def test_ss_ipv6_sip002_and_b64_and_plugin(self):
        creds_b64 = base64.b64encode(b"aes-256-gcm:p@ss:word").decode()
        link = (
            f"ss://{creds_b64}@[2001:db8::1]:8388"
            "?plugin=v2ray-plugin%3Bmode%3Dwebsocket#SS%20IPv6"
        )
        ob = xhm_core.parse_proxy_link(link)
        self.assertIsNotNone(ob)
        self.assertEqual(ob["server"], "2001:db8::1")
        self.assertEqual(ob["server_port"], 8388)
        self.assertEqual(ob["method"], "aes-256-gcm")
        self.assertEqual(ob["password"], "p@ss:word")
        self.assertEqual(ob["plugin"], "v2ray-plugin")
        self.assertIn("mode=websocket", ob["plugin_opts"])

        link_plain = "ss://chacha20-ietf-poly1305:secret%401@[2001:db8::2]:8388#SSPlain"
        ob_plain = xhm_core.parse_proxy_link(link_plain)
        self.assertEqual(ob_plain["password"], "secret@1")
        self.assertIn("[2001:db8::2]:8388", xhm_core.outbound_to_link(ob_plain))

    def test_hysteria2_and_tuic_roundtrip(self):
        hy2_link = (
            "hy2://my%40pass@hy.example.com:443"
            "?sni=hy.example.com&obfs=salamander&obfs-password=ob%3Apw&insecure=1&upmbps=20&downmbps=100#Hy2"
        )
        hy2 = xhm_core.parse_proxy_link(hy2_link)
        self.assertEqual(hy2["type"], "hysteria2")
        self.assertEqual(hy2["password"], "my@pass")
        self.assertEqual(hy2["obfs"]["type"], "salamander")
        self.assertTrue(hy2["tls"]["insecure"])
        hy2_rt = xhm_core.parse_proxy_link(xhm_core.outbound_to_link(hy2))
        self.assertEqual(hy2_rt["password"], "my@pass")
        self.assertEqual(hy2_rt["obfs"]["password"], "ob:pw")

        tuic_link = (
            "tuic://55555555-5555-5555-5555-555555555555:tu%3Apw@tuic.example.com:8443"
            "?congestion_control=bbr&udp_relay_mode=quic&alpn=h3&sni=tuic.example.com#TUIC"
        )
        tuic = xhm_core.parse_proxy_link(tuic_link)
        self.assertEqual(tuic["type"], "tuic")
        self.assertEqual(tuic["password"], "tu:pw")
        self.assertEqual(tuic["congestion_control"], "bbr")
        tuic_rt = xhm_core.parse_proxy_link(xhm_core.outbound_to_link(tuic))
        self.assertEqual(tuic_rt["uuid"], "55555555-5555-5555-5555-555555555555")
        self.assertEqual(tuic_rt["password"], "tu:pw")

    def test_socks5_and_ssh_quoted_auth_roundtrip(self):
        s_link = "socks5://alice%40home:pa%3Ass@socks.example.com:1080#MySocks"
        s_ob = xhm_core.parse_proxy_link(s_link)
        self.assertEqual(s_ob["type"], "socks")
        self.assertEqual(s_ob["username"], "alice@home")
        self.assertEqual(s_ob["password"], "pa:ss")
        s_rt = xhm_core.parse_proxy_link(xhm_core.outbound_to_link(s_ob))
        self.assertEqual(s_rt["username"], "alice@home")
        self.assertEqual(s_rt["password"], "pa:ss")

        ssh_link = "ssh://user%40host:p%40ss%3A1@1.2.3.4:22?sshConfigType=SSH-TLS&sni=cdn.ssh.example#MySSH"
        ssh_ob = xhm_core.parse_proxy_link(ssh_link)
        self.assertEqual(ssh_ob["type"], "ssh")
        self.assertEqual(ssh_ob["user"], "user@host")
        self.assertEqual(ssh_ob["password"], "p@ss:1")
        self.assertEqual(ssh_ob["ssh_config_type"], "SSH-TLS")
        self.assertEqual(ssh_ob["sni"], "cdn.ssh.example")
        ssh_rt = xhm_core.parse_proxy_link(xhm_core.outbound_to_link(ssh_ob))
        self.assertEqual(ssh_rt["user"], "user@host")
        self.assertEqual(ssh_rt["password"], "p@ss:1")
        self.assertEqual(ssh_rt["ssh_config_type"], "SSH-TLS")

    def test_npvt_ssh_parse_and_roundtrip(self):
        payload = {
            "sshHost": "ssh2.example.com",
            "sshPort": 443,
            "sshUsername": "u1",
            "sshPassword": "p1",
            "sshConfigType": "SSH-TLS",
            "sni": "sni.example.com",
            "remarks": "NpvtSSH",
        }
        link = "npvt-ssh://" + base64.b64encode(json.dumps(payload).encode()).decode()
        ob = xhm_core.parse_proxy_link(link)
        self.assertIsNotNone(ob)
        self.assertEqual(ob["type"], "ssh")
        self.assertEqual(ob["tag"], "NpvtSSH")
        self.assertEqual(ob["sni"], "sni.example.com")
        rt = xhm_core.parse_proxy_link(xhm_core.outbound_to_link(ob))
        self.assertEqual(rt["server"], "ssh2.example.com")
        self.assertEqual(rt["password"], "p1")


class TestSubscriptionsAndStore(_IsolatedXhmTestCase):
    def test_fetch_subscription_singbox_json_parsing_and_fields(self):
        sb_doc = {
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
                {
                    "type": "vless",
                    "tag": "SB-VLESS",
                    "server": "sb1.example.com",
                    "server_port": 443,
                    "uuid": "66666666-6666-6666-6666-666666666666",
                    "tls": {"enabled": True, "server_name": "sb1.example.com"},
                },
                {
                    "type": "hysteria2",
                    "tag": "SB-HY2",
                    "server": "sb2.example.com",
                    "server_port": 443,
                    "password": "secret",
                    "tls": {"enabled": True, "server_name": "sb2.example.com"},
                },
            ]
        }
        url = "https://sub.example.com/sb"
        with mock.patch("xhm_core.urllib.request.urlopen", return_value=_DummyHTTPResponse(json.dumps(sb_doc).encode())):
            nodes = xhm_core.fetch_subscription(url, default_name="MySB")

        self.assertEqual(len(nodes), 2)
        for n in nodes:
            self.assertFalse(n["is_custom"])
            self.assertEqual(n["subscription_url"], url)
            self.assertTrue(n["id"])
            self.assertTrue(n["link"])
            self.assertEqual(n["profile"], "MySB")

    def test_fetch_subscription_ssl_verify_retry_only_on_cert_error(self):
        body = b"vless://77777777-7777-7777-7777-777777777777@s.example.com:443?security=none#S1"
        calls = []

        def fake_cert_then_ok(req, timeout=20, context=None):
            calls.append((req.headers.get("User-agent"), context))
            if len(calls) == 1:
                raise urllib.error.URLError(ssl.SSLCertVerificationError(1, "self signed certificate"))
            return _DummyHTTPResponse(body)

        with mock.patch("xhm_core.urllib.request.urlopen", side_effect=fake_cert_then_ok):
            nodes = xhm_core.fetch_subscription("https://selfsigned.example.com/sub")
        self.assertEqual(len(nodes), 1)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][0], "XHM/1.0 (Linux; Xray)")
        self.assertEqual(calls[1][1].verify_mode, ssl.CERT_NONE)

        calls.clear()

        def fake_conn_refused(req, timeout=20, context=None):
            calls.append(context)
            raise urllib.error.URLError(ConnectionRefusedError("refused"))

        with mock.patch("xhm_core.urllib.request.urlopen", side_effect=fake_conn_refused):
            with self.assertRaises(RuntimeError):
                xhm_core.fetch_subscription("https://down.example.com/sub")
        self.assertEqual(len(calls), 1)

    def test_custom_store_replace_id_and_invalid_edit_preserves_existing(self):
        n1 = xhm_core.CustomConfigStore.add_node_from_link(
            "vless://11111111-1111-1111-1111-111111111111@a.example.com:443?security=none#First"
        )
        n2 = xhm_core.CustomConfigStore.add_node_from_link(
            "vless://22222222-2222-2222-2222-222222222222@b.example.com:443?security=none#Second"
        )
        self.assertIsNotNone(n1)
        self.assertIsNotNone(n2)

        # Invalid replacement link leaves existing list intact
        bad = xhm_core.CustomConfigStore.add_node_from_link("not-a-valid-link", replace_id=n1["id"])
        self.assertIsNone(bad)
        self.assertEqual([x["tag"] for x in xhm_core.CustomConfigStore.load_nodes()], ["Second", "First"])

        # Valid edit replaces target cleanly in its exact slot (index 1 here)
        updated = xhm_core.CustomConfigStore.add_node_from_link(
            "vless://99999999-9999-9999-9999-999999999999@a2.example.com:8443?security=none#Updated",
            replace_id=n1["id"],
        )
        self.assertIsNotNone(updated)
        loaded = xhm_core.CustomConfigStore.load_nodes()
        self.assertEqual([x["tag"] for x in loaded], ["Second", "Updated"])
        self.assertEqual(loaded[1]["server"], "a2.example.com")
        self.assertNotIn(n1["id"], [x["id"] for x in loaded])

    def test_custom_store_clear_all_preserves_subscriptions(self):
        xhm_core.CustomConfigStore.add_node_from_link(
            "vless://11111111-1111-1111-1111-111111111111@c.example.com:443?security=none#Custom1"
        )
        sub_body = b"vless://22222222-2222-2222-2222-222222222222@sub.example.com:443?security=none#SubNode1"
        with mock.patch("xhm_core.urllib.request.urlopen", return_value=_DummyHTTPResponse(sub_body)):
            cnt, _ = xhm_core.CustomConfigStore.add_subscription("https://s.example.com/1", name="SubOne")
        self.assertEqual(cnt, 1)

        xhm_core.CustomConfigStore.clear_all_nodes()
        remaining = xhm_core.load_all_nodes()
        self.assertEqual([n["tag"] for n in remaining], ["SubNode1"])
        self.assertFalse(remaining[0]["is_custom"])

    def test_subscription_add_update_preserve_ping_partial_failure_and_delete(self):
        sub1_url = "https://sub1.example.com/feed"
        sub2_url = "https://sub2.example.com/feed"
        n1_a = "vless://11111111-1111-1111-1111-111111111111@s1a.example.com:443?security=none#S1A"
        n1_b = "vless://22222222-2222-2222-2222-222222222222@s1b.example.com:443?security=none#S1B"
        n2_a = "vless://33333333-3333-3333-3333-333333333333@s2a.example.com:443?security=none#S2A"

        def mock_fetch(req, timeout=20, context=None):
            if req.full_url == sub1_url:
                return _DummyHTTPResponse((n1_a + "\n" + n1_b).encode())
            return _DummyHTTPResponse(n2_a.encode())

        with mock.patch("xhm_core.urllib.request.urlopen", side_effect=mock_fetch):
            xhm_core.CustomConfigStore.add_subscription(sub1_url)
            xhm_core.CustomConfigStore.add_subscription(sub2_url)

        subs = xhm_core.CustomConfigStore.load_subscriptions()
        self.assertEqual(len({s["name"] for s in subs}), 2)

        nodes = xhm_core.CustomConfigStore.load_nodes()
        for n in nodes:
            if n["tag"] == "S1A":
                n["ping"] = 42
        xhm_core.CustomConfigStore.save_nodes(nodes)

        def mock_update(req, timeout=20, context=None):
            if req.full_url == sub1_url:
                return _DummyHTTPResponse(n1_a.encode())
            raise urllib.error.URLError(ConnectionRefusedError("down"))

        with mock.patch("xhm_core.urllib.request.urlopen", side_effect=mock_update):
            cnt, msg = xhm_core.CustomConfigStore.update_all_subscriptions()

        self.assertEqual(cnt, 1)
        self.assertIn("failed", msg.lower())
        after = xhm_core.load_all_nodes()
        tags = {n["tag"]: n for n in after}
        self.assertIn("S1A", tags)
        self.assertNotIn("S1B", tags)
        self.assertIn("S2A", tags)
        self.assertEqual(tags["S1A"]["ping"], 42)

        self.assertTrue(xhm_core.CustomConfigStore.delete_subscription(sub1_url))
        final_tags = [n["tag"] for n in xhm_core.load_all_nodes()]
        self.assertEqual(final_tags, ["S2A"])


class TestConfigBuildersAndCoreSchemas(_IsolatedXhmTestCase):
    def test_singbox_to_xray_non_tls_port_443_and_transports(self):
        vless_plain = xhm_core.parse_proxy_link(
            "vless://11111111-1111-1111-1111-111111111111@plain443.example.com:443"
            "?security=none&encryption=none&type=httpupgrade&path=%2Fhu&host=h.example.com#Plain443"
        )
        ob = xhm_core.singbox_to_xray_outbound(vless_plain)
        self.assertEqual(ob["streamSettings"]["security"], "none")
        self.assertEqual(ob["streamSettings"]["network"], "httpupgrade")
        self.assertEqual(ob["streamSettings"]["httpupgradeSettings"]["host"], "h.example.com")
        self.assertEqual(ob["settings"]["vnext"][0]["users"][0]["encryption"], "none")

        socks = xhm_core.parse_proxy_link("socks5://bob:sec@socks.example.com:1080#Socks")
        sob = xhm_core.singbox_to_xray_outbound(socks)
        self.assertEqual(sob["protocol"], "socks")
        self.assertEqual(sob["settings"]["servers"][0]["users"][0]["user"], "bob")

    def test_build_xray_config_no_dns_leak_and_validates_with_xray_binary(self):
        sample_links = [
            "vless://11111111-1111-1111-1111-111111111111@v1.example.com:443?security=reality&sni=google.com&pbk=7p5vM2m2S6c4B3R1L8T9w2N5q0F3k6V1j4X7y8Z2cDA&sid=ab12&fp=chrome&type=tcp#R1",
            "vless://22222222-2222-2222-2222-222222222222@v2.example.com:443?security=tls&sni=v2.example.com&type=xhttp&path=%2Fx&host=x.example.com&mode=auto#X1",
            "vless://33333333-3333-3333-3333-333333333333@10.0.0.5:443?security=none&type=xhttp&path=%2Fx&host=x.local&mode=auto#XPlainLocal",
            "trojan://pass@t1.example.com:443?security=tls&sni=t1.example.com&type=ws&path=%2Ftws#T1",
            "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@198.51.100.10:8388#SS1",
            "socks5://alice:pass@198.51.100.11:1080#Socks1",
        ]
        with mock.patch("xhm_core.get_physical_interface", return_value=("192.0.2.10", None)):
            for idx, link in enumerate(sample_links):
                raw_ob = xhm_core.parse_proxy_link(link)
                ob = xhm_core.singbox_to_xray_outbound(raw_ob)
                cfg = xhm_core.build_xray_config(ob, proxy_port=39850, api_port=39852)

                for rule in cfg["routing"]["rules"]:
                    self.assertNotEqual(str(rule.get("port", "")), "53")
                self.assertEqual(cfg["dns"]["servers"][0]["domains"], ["domain:.ir", "localhost"])
                for ib in cfg["inbounds"]:
                    if ib["tag"] in ("mixed", "http-in"):
                        self.assertTrue(ib["sniffing"]["enabled"])

                if os.path.exists(xhm_core.XRAY_BIN):
                    cfg_path = os.path.join(self._tmpdir.name, f"xray_{idx}.json")
                    with open(cfg_path, "w", encoding="utf-8") as f:
                        json.dump(cfg, f)
                    res = subprocess.run(
                        [xhm_core.XRAY_BIN, "run", "-test", "-c", cfg_path],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(res.returncode, 0, f"xray -test failed for {link}: {res.stdout}\n{res.stderr}")

    def test_build_singbox_run_and_tun_configs_valid_schema(self):
        with mock.patch("xhm_core.get_physical_interface", return_value=("192.0.2.10", None)), \
             mock.patch("xhm_core._resolve_server_cidrs", return_value=["198.51.100.20/32"]):
            for link in (
                "hy2://pw@hy.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=ob#Hy2",
                "tuic://11111111-1111-1111-1111-111111111111:pw@tuic.example.com:443?sni=tuic.example.com&congestion_control=bbr#TUIC",
            ):
                raw_ob = xhm_core.parse_proxy_link(link)
                raw_ob["is_custom"] = True
                raw_ob["ping"] = 50
                raw_ob["link"] = link
                cfg = xhm_core.build_singbox_run_config(raw_ob, proxy_port=39850, api_port=39852)
                proxy_ob = cfg["outbounds"][0]
                for meta in ("is_custom", "ping", "link", "ssh_config_type"):
                    self.assertNotIn(meta, proxy_ob)
                self.assertEqual(cfg["dns"]["servers"][0]["type"], "https")

                if os.path.exists(xhm_core.SING_BOX_BIN):
                    cfg_path = os.path.join(self._tmpdir.name, f"sb_{raw_ob['type']}.json")
                    with open(cfg_path, "w", encoding="utf-8") as f:
                        json.dump(cfg, f)
                    res = subprocess.run(
                        [xhm_core.SING_BOX_BIN, "check", "-c", cfg_path],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(res.returncode, 0, f"sing-box check failed: {res.stdout}\n{res.stderr}")

            with mock.patch("xhm_core._has_ipv6_enabled", return_value=True):
                tun_v6 = xhm_core.build_singbox_tun_config(39850, active_node={"server": "hy.example.com"})
                ib = tun_v6["inbounds"][0]
                self.assertIn("fdfe:dcba:9876::1/126", ib["address"])
                self.assertIn("::1/128", ib["route_exclude_address"])
                self.assertIn("fe80::/10", ib["route_exclude_address"])
                self.assertEqual(tun_v6["dns"]["servers"][0]["type"], "https")
                if os.path.exists(xhm_core.SING_BOX_BIN):
                    p = os.path.join(self._tmpdir.name, "tun_v6.json")
                    with open(p, "w", encoding="utf-8") as f:
                        json.dump(tun_v6, f)
                    res = subprocess.run([xhm_core.SING_BOX_BIN, "check", "-c", p], capture_output=True, text=True, timeout=10)
                    self.assertEqual(res.returncode, 0, f"sing-box check tun_v6 failed: {res.stdout}\n{res.stderr}")

            with mock.patch("xhm_core._has_ipv6_enabled", return_value=False):
                tun_v4 = xhm_core.build_singbox_tun_config(39850)
                self.assertEqual(tun_v4["inbounds"][0]["address"], ["172.19.0.1/30"])


class TestEnvGnomeAndTrafficTracker(_IsolatedXhmTestCase):
    def test_proxy_env_script_dynamic_ports_and_shell_syntax(self):
        xhm_core._write_proxy_env_script(True, 31234, 31235)
        with open(xhm_core.ENV_SCRIPT_FILE, "r", encoding="utf-8") as f:
            enabled_sh = f.read()
        self.assertIn("31234", enabled_sh)
        self.assertIn("31235", enabled_sh)
        self.assertNotIn("10808", enabled_sh)
        self.assertNotIn("10809", enabled_sh)
        self.assertIn('eval "_val=\\"\\${${_var}:-}\\""', enabled_sh)
        for shell_bin in ("bash", "sh"):
            if shutil.which(shell_bin):
                res = subprocess.run([shell_bin, "-n", xhm_core.ENV_SCRIPT_FILE], capture_output=True, text=True)
                self.assertEqual(res.returncode, 0, f"{shell_bin} -n failed: {res.stderr}")

        xhm_core._write_proxy_env_script(False, 31234, 31235)
        with open(xhm_core.ENV_SCRIPT_FILE, "r", encoding="utf-8") as f:
            disabled_sh = f.read()
        self.assertIn("_xhm_clear_xhm_proxy", disabled_sh)
        for shell_bin in ("bash", "sh"):
            if shutil.which(shell_bin):
                res = subprocess.run([shell_bin, "-n", xhm_core.ENV_SCRIPT_FILE], capture_output=True, text=True)
                self.assertEqual(res.returncode, 0, f"{shell_bin} -n failed on disable: {res.stderr}")
                # Execute inside a clean shell verifying XHM proxy var clears while foreign proxy survives
                cmd = (
                    f'export HTTP_PROXY="http://127.0.0.1:31235"; '
                    f'export ALL_PROXY="socks5://127.0.0.1:31234"; '
                    f'export https_proxy="http://10.0.0.1:8080"; '
                    f'. "{xhm_core.ENV_SCRIPT_FILE}"; '
                    f'[ -z "${{HTTP_PROXY:-}}" ] && [ -z "${{ALL_PROXY:-}}" ] && [ "${{https_proxy:-}}" = "http://10.0.0.1:8080" ]'
                )
                run_sh = subprocess.run([shell_bin, "-c", cmd], capture_output=True, text=True)
                self.assertEqual(run_sh.returncode, 0, f"{shell_bin} runtime clear failed: {run_sh.stderr}")

    def test_set_gnome_proxy_restores_socks_only_and_handles_port_zero(self):
        prev_socks_only = {
            "mode": "manual",
            "http_host": "",
            "http_port": "0",
            "https_host": "",
            "https_port": "0",
            "socks_host": "10.10.0.5",
            "socks_port": "1080",
            "ignore_hosts": "['localhost', '127.0.0.0/8']",
        }
        calls = []

        def fake_subproc_run(cmd, *args, **kwargs):
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with mock.patch("xhm_core.get_current_gnome_proxy", return_value=prev_socks_only), \
             mock.patch("xhm_core.is_port_in_use", side_effect=lambda p: int(p) == 1080), \
             mock.patch("xhm_core.subprocess.run", side_effect=fake_subproc_run):
            xhm_core.set_gnome_proxy(True, port=39850, http_port=39851)
            self.assertTrue(os.path.exists(xhm_core.SAVED_SYSTEM_PROXY_FILE))

            calls.clear()
            xhm_core.set_gnome_proxy(False, port=39850, http_port=39851)

        self.assertTrue(any(c[-2:] == ["host", "10.10.0.5"] for c in calls))
        self.assertTrue(any(c[-2:] == ["port", "1080"] for c in calls))
        self.assertFalse(os.path.exists(xhm_core.SAVED_SYSTEM_PROXY_FILE))

    def test_traffic_tracker_end_session_invalid_month_latest_tag_and_reset(self):
        xhm_core.TrafficTracker.end_session(999, 100, 200)

        node = {"server": "tr.example.com", "port": 443, "type": "vless", "tag": "TagOld"}
        sid = xhm_core.TrafficTracker.start_session(node)
        xhm_core.TrafficTracker.record_traffic("tr.example.com:443:vless", "TagOld", 500, 300, session_id=sid)

        with xhm_core.TrafficTracker.db_session() as conn:
            conn.execute(
                "INSERT INTO traffic_hourly "
                "(timestamp_hour, year, month, day, hour, node_key, node_tag, down_bytes, up_bytes, total_bytes) "
                "VALUES ('9999-12-31 23', 9999, 12, 31, 23, 'tr.example.com:443:vless', 'TagNew', 10, 5, 15)"
            )

        nodes_info = xhm_core.TrafficTracker.get_nodes_traffic()
        self.assertEqual(nodes_info["map"]["tr.example.com:443:vless"]["node_tag"], "TagNew")

        daily = xhm_core.TrafficTracker.get_daily(month_str="not-a-month")
        self.assertIsInstance(daily, list)
        self.assertGreaterEqual(len(daily), 28)

        xhm_core.TrafficTracker.end_session(sid, 610, 355)
        self.assertTrue(xhm_core.TrafficTracker.reset_traffic())
        self.assertEqual(xhm_core.TrafficTracker.get_summary()["all_time"]["total_bytes"], 0)


class TestProxyManagerLifecycle(_IsolatedXhmTestCase):
    def _make_manager(self):
        with mock.patch("xhm_core.get_current_gnome_proxy", return_value={"mode": "none"}), \
             mock.patch("xhm_core.subprocess.run"):
            return xhm_core.ProxyManager(proxy_port=39850)

    def test_validate_node_before_stop_keeps_existing_connection_on_error(self):
        mgr = self._make_manager()
        old_proc = _FakePopenProc(alive=True)
        mgr.proc = old_proc
        mgr.connected = True
        mgr.active_node = _wrap_node(
            "vless://11111111-1111-1111-1111-111111111111@ok.example.com:443?security=none#OK"
        )
        mgr.status_msg = "Connected to OK"

        bad_node = {"server": "", "port": 0, "type": "unsupported_proto", "raw": {}}
        with mock.patch.object(mgr, "stop") as mock_stop, \
             mock.patch("xhm_core.subprocess.Popen") as mock_popen:
            ok = mgr.start(bad_node)

        self.assertFalse(ok)
        mock_stop.assert_not_called()
        mock_popen.assert_not_called()
        self.assertTrue(mgr.connected)
        self.assertEqual(mgr.active_node["tag"], "OK")

    def test_start_preserves_tun_across_switch_and_cleans_up_on_stop(self):
        mgr = self._make_manager()
        n1 = _wrap_node("vless://11111111-1111-1111-1111-111111111111@n1.example.com:443?security=none#N1")
        n2 = _wrap_node("vless://22222222-2222-2222-2222-222222222222@n2.example.com:443?security=none#N2")
        procs = []

        def fake_popen(*args, **kwargs):
            p = _FakePopenProc(alive=True)
            procs.append(p)
            return p

        tun_state = {"active": True}

        def fake_tun_detailed(enable, manager=None):
            tun_state["active"] = bool(enable)
            return True, f"TUN {enable}"

        fake_xray = os.path.join(self._tmpdir.name, "xray")
        with open(fake_xray, "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(fake_xray, 0o755)

        with mock.patch("xhm_core.XRAY_BIN", fake_xray), \
             mock.patch("xhm_core.is_port_in_use", side_effect=lambda port: bool(procs)), \
             mock.patch("xhm_core.get_physical_interface", return_value=("192.0.2.10", None)), \
             mock.patch("xhm_core.subprocess.run", return_value=subprocess.CompletedProcess(["xray"], 0, "", "")), \
             mock.patch("xhm_core.subprocess.Popen", side_effect=fake_popen), \
             mock.patch("xhm_core.is_tun_active", side_effect=lambda: tun_state["active"]), \
             mock.patch("xhm_core.set_tun_mode_detailed", side_effect=fake_tun_detailed) as mock_tun, \
             mock.patch("xhm_core.set_gnome_proxy"), \
             mock.patch("xhm_core.get_current_gnome_proxy", return_value={"mode": "none"}), \
             mock.patch("xhm_core._revert_system_tun_dns"), \
             mock.patch.object(mgr, "verify_live_connectivity", return_value=True), \
             mock.patch.object(mgr, "_kill_pid_or_pgid"), \
             mock.patch.object(mgr, "_is_pid_alive", return_value=True):
            mgr.connected = True
            mgr.active_node = n1
            mgr.proc = _FakePopenProc(alive=True)
            ok = mgr.start(n2)

        self.assertTrue(ok)
        self.assertTrue(mgr.connected)
        self.assertEqual(mgr.active_node["tag"], "N2")
        self.assertIn(mock.call(True, manager=mgr), mock_tun.mock_calls)

        with mock.patch("xhm_core.is_tun_active", return_value=True), \
             mock.patch("xhm_core.set_tun_mode_detailed", return_value=(True, "stopped")) as mock_tun_off, \
             mock.patch("xhm_core.set_gnome_proxy"), \
             mock.patch("xhm_core.get_current_gnome_proxy", return_value={"mode": "manual", "http_port": "39851"}), \
             mock.patch("xhm_core._revert_system_tun_dns"), \
             mock.patch.object(mgr, "_read_core_counters", return_value=(400, 120)), \
             mock.patch.object(mgr, "_kill_pid_or_pgid"):
            mgr.stop()

        mock_tun_off.assert_called_once_with(False)
        self.assertFalse(mgr.connected)
        self.assertFalse(os.path.exists(xhm_core.STATE_FILE))
        self.assertEqual(xhm_core.TrafficTracker.get_summary()["all_time"]["down_bytes"], 400)

    def test_check_existing_recovers_unpolled_session_traffic(self):
        n1 = _wrap_node("vless://11111111-1111-1111-1111-111111111111@rec.example.com:443?security=none#Rec")
        sid = xhm_core.TrafficTracker.start_session(n1)
        xhm_core.TrafficTracker.record_traffic("rec.example.com:443:vless", "Rec", 1000, 500, session_id=sid)
        xhm_core._atomic_write_json(
            xhm_core.STATE_FILE,
            {
                "pid": 888888,
                "node": n1,
                "start_time": 1700000000,
                "proxy_port": 39850,
                "core": "Xray Core",
                "allow_lan": False,
                "system_proxy": True,
                "session_id": sid,
            },
        )
        with mock.patch.object(xhm_core.ProxyManager, "_is_pid_alive", return_value=True), \
             mock.patch.object(xhm_core.ProxyManager, "_read_core_counters", return_value=(1600, 750)):
            mgr = xhm_core.ProxyManager(proxy_port=39850)
            stats = mgr.query_traffic_stats()

        self.assertTrue(mgr.connected)
        self.assertEqual(mgr.session_down, 1600)
        self.assertEqual(mgr.session_up, 750)
        self.assertEqual(stats["down_bytes"], 1600)
        self.assertEqual(stats["up_bytes"], 750)

    def test_sync_with_external_state_adopts_and_handles_external_stop_without_reconnect(self):
        mgr = self._make_manager()
        n_cli = _wrap_node("vless://11111111-1111-1111-1111-111111111111@cli.example.com:443?security=none#CLI")
        xhm_core._atomic_write_json(
            xhm_core.STATE_FILE,
            {"pid": 777777, "node": n_cli, "start_time": 1700000000, "proxy_port": 39850, "core": "Xray Core"},
        )
        with mock.patch.object(mgr, "_is_pid_alive", return_value=True):
            mgr._sync_with_external_state()
        self.assertTrue(mgr.connected)
        self.assertEqual(mgr.active_node["tag"], "CLI")

        os.remove(xhm_core.STATE_FILE)
        with mock.patch.object(mgr, "_is_pid_alive", return_value=False), \
             mock.patch.object(mgr, "_trigger_auto_reconnect") as mock_reconn, \
             mock.patch.object(mgr, "stop") as mock_stop:
            stats = mgr.query_traffic_stats()

        mock_reconn.assert_not_called()
        mock_stop.assert_not_called()
        self.assertFalse(mgr.connected)
        self.assertTrue(mgr._manual_stop)
        self.assertEqual(stats["down_bytes"], 0)


class TestWebServerApi(_IsolatedXhmTestCase):
    def setUp(self):
        super().setUp()
        self.orig_mgr = web_server.manager
        with mock.patch("xhm_core.get_current_gnome_proxy", return_value={"mode": "none"}), \
             mock.patch("xhm_core.subprocess.run"):
            self.test_mgr = xhm_core.ProxyManager(proxy_port=39850)
        web_server.manager = self.test_mgr
        self.server = web_server.XhmHttpServer(("127.0.0.1", 0), web_server.XhmApiHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        web_server.manager = self.orig_mgr
        super().tearDown()

    def _request(self, method, path, body=None, headers=None):
        req_headers = dict(headers or {})
        data = None
        if body is not None:
            if isinstance(body, (dict, list)):
                data = json.dumps(body).encode("utf-8")
                req_headers.setdefault("Content-Type", "application/json")
            else:
                data = body
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data,
            headers=req_headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            try:
                return e.code, dict(e.headers), e.read()
            finally:
                e.close()

    def test_static_security_and_cors_headers(self):
        code, _, _ = self._request("GET", "/server.py")
        self.assertEqual(code, 404)

        code2, _, _ = self._request("GET", "/../lib/xhm_core.py")
        self.assertEqual(code2, 404)

        code3, hdrs3, body3 = self._request("GET", "/index.html")
        self.assertEqual(code3, 200)
        self.assertNotIn("Access-Control-Allow-Origin", hdrs3)
        self.assertIn(b"XHM", body3)

        code4, hdrs4, _ = self._request(
            "GET", "/api/nodes", headers={"Origin": f"http://127.0.0.1:{self.port}"}
        )
        self.assertEqual(code4, 200)
        self.assertEqual(hdrs4.get("Access-Control-Allow-Origin"), f"http://127.0.0.1:{self.port}")

    def test_csrf_origin_check_allows_local_and_curl_blocks_foreign(self):
        link = "vless://11111111-1111-1111-1111-111111111111@api.example.com:443?security=none#APINode"
        code_evil, _, _ = self._request(
            "POST",
            "/api/add-config",
            body={"text": link},
            headers={"Origin": "https://evil.example"},
        )
        self.assertEqual(code_evil, 403)

        code_ref_evil, _, _ = self._request(
            "POST",
            "/api/add-config",
            body={"text": link},
            headers={"Referer": "https://evil.example/attack.html"},
        )
        self.assertEqual(code_ref_evil, 403)

        code_curl, _, _ = self._request("POST", "/api/add-config", body={"text": link})
        self.assertEqual(code_curl, 200)

        code_local, hdrs_local, _ = self._request(
            "POST",
            "/api/add-config",
            body={"text": link},
            headers={"Origin": "http://127.0.0.1:18501"},
        )
        self.assertEqual(code_local, 200)
        self.assertEqual(hdrs_local.get("Access-Control-Allow-Origin"), "http://127.0.0.1:18501")

    def test_api_add_config_replace_id_and_bad_payloads(self):
        link1 = "vless://11111111-1111-1111-1111-111111111111@old.example.com:443?security=none#OldName"
        code, _, _ = self._request("POST", "/api/add-config", body={"text": link1})
        self.assertEqual(code, 200)
        nodes = xhm_core.CustomConfigStore.load_nodes()
        self.assertEqual(len(nodes), 1)
        nid = nodes[0]["id"]

        link2 = "vless://22222222-2222-2222-2222-222222222222@new.example.com:443?security=none#NewName"
        code2, _, _ = self._request("POST", "/api/add-config", body={"text": link2, "replace_id": nid})
        self.assertEqual(code2, 200)
        nodes2 = xhm_core.CustomConfigStore.load_nodes()
        self.assertEqual(len(nodes2), 1)
        self.assertEqual(nodes2[0]["tag"], "NewName")
        self.assertEqual(nodes2[0]["server"], "new.example.com")
        self.assertNotIn(nid, [n["id"] for n in nodes2])

        code_arr, _, _ = self._request("POST", "/api/add-config", body=["not", "an", "object"])
        self.assertEqual(code_arr, 400)

        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as s:
            s.sendall(b"POST /api/add-config HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: notanint\r\n\r\n")
            resp_line = s.recv(1024).decode("ascii", errors="replace").splitlines()[0]
        self.assertIn("400", resp_line)

    def test_api_logs_and_clear_logs_tun_source_and_bad_traffic_query(self):
        with open(xhm_core.LOG_FILE, "w", encoding="utf-8") as f:
            f.write("core line\n")
        with open(xhm_core.TUN_LOG_FILE, "w", encoding="utf-8") as f:
            f.write("tun line 1\ntun line 2\n")

        c1, _, b1 = self._request("GET", "/api/logs?source=tun")
        self.assertEqual(c1, 200)
        self.assertEqual(json.loads(b1)["logs"], ["tun line 1", "tun line 2"])

        c2, _, _ = self._request("POST", "/api/clear-logs", body={"source": "tun"})
        self.assertEqual(c2, 200)
        with open(xhm_core.LOG_FILE, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "core line\n")
        with open(xhm_core.TUN_LOG_FILE, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "")

        c3, _, b3 = self._request("GET", "/api/traffic-stats?view=monthly&year=badyear&limit=notint")
        self.assertEqual(c3, 200)
        self.assertIsInstance(json.loads(b3), list)


class TestCliAndTuiHelpers(_IsolatedXhmTestCase):
    def test_ping_sni_for_node(self):
        vless_tls = _wrap_node(
            "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=tls&sni=tls.example.com#TLS"
        )
        self.assertEqual(cli_mod._ping_sni_for_node(vless_tls), "tls.example.com")

        ssh_plain = _wrap_node("ssh://u:p@1.2.3.4:22#PlainSSH")
        self.assertEqual(cli_mod._ping_sni_for_node(ssh_plain), "")

        ssh_tls = _wrap_node("ssh://u:p@1.2.3.4:443?sshConfigType=SSH-TLS&sni=cdn.ssh#SSHTLS")
        self.assertEqual(cli_mod._ping_sni_for_node(ssh_tls), "cdn.ssh")

    def test_cli_on_unmatched_target_exits_1_without_starting(self):
        xhm_core.CustomConfigStore.add_node_from_link(
            "vless://11111111-1111-1111-1111-111111111111@srv.example.com:443?security=none#Germany1"
        )
        fake_mgr = mock.MagicMock()
        args = types.SimpleNamespace(command="on", target="nonexistent-server")
        with self.assertRaises(SystemExit) as cm:
            cli_mod.handle_cli_args(args, fake_mgr)
        self.assertEqual(cm.exception.code, 1)
        fake_mgr.start.assert_not_called()

    def test_terminal_width_and_sanitize_helpers(self):
        self.assertEqual(cli_mod._char_cols("\ufe0f"), 0)
        self.assertEqual(cli_mod._char_cols("\u200d"), 0)
        self.assertEqual(cli_mod._char_cols("\u0301"), 0)
        self.assertEqual(cli_mod._char_cols("中"), 2)
        self.assertEqual(cli_mod._display_width("e\u0301\ufe0fA"), 2)
        self.assertEqual(cli_mod.safe_clip("تست-سریع", 4), "تست-")
        self.assertEqual(cli_mod._sanitize_term_msg("🟢 Connected\ufe0f  to  Iran "), "Connected to Iran")

    def test_key_matching_supports_unicode_and_ints(self):
        self.assertTrue(cli_mod._key_is("q", ord("q"), "Q"))
        self.assertTrue(cli_mod._key_is(ord("q"), "q"))
        self.assertTrue(cli_mod._key_is(curses.KEY_UP, curses.KEY_UP, "k"))
        self.assertTrue(cli_mod._key_is("\x1b", 27))
        self.assertFalse(cli_mod._key_is("س", "q", 27))

    def test_cli_status_prints_traffic_without_tofu_emojis(self):
        fake_mgr = mock.MagicMock()
        fake_mgr.connected = True
        fake_mgr.active_node = {"tag": "TehranNode", "type": "vless", "server": "1.2.3.4", "port": 443}
        fake_mgr.proxy_port = 10850
        fake_mgr.core_name = "Xray Core"
        fake_mgr.start_time = 100
        fake_mgr.query_traffic_stats.return_value = {
            "down_total_fmt": "12 MB",
            "down_speed_fmt": "400 KB/s",
            "up_total_fmt": "2 MB",
            "up_speed_fmt": "50 KB/s",
        }
        buf = io.StringIO()
        args = types.SimpleNamespace(command="status", target=None)
        with (
            mock.patch.object(cli_mod, "get_gnome_proxy_state", return_value=False),
            mock.patch.object(xhm_core, "is_tun_active", return_value=False),
            mock.patch.object(cli_mod.time, "time", return_value=165),
            contextlib.redirect_stdout(buf),
            self.assertRaises(SystemExit) as cm,
        ):
            cli_mod.handle_cli_args(args, fake_mgr)
        self.assertEqual(cm.exception.code, 0)
        out = buf.getvalue()
        self.assertIn("[ON] Connected", out)
        self.assertIn("127.0.0.1:10850 (SOCKS5) / :10851 (HTTP)", out)
        self.assertIn("Down 12 MB (400 KB/s)", out)
        for bad_glyph in ("🟢", "🔴", "⚡", "❌"):
            self.assertNotIn(bad_glyph, out)

    def test_tui_unicode_filter_and_escape_clears_before_exit(self):
        xhm_core.CustomConfigStore.add_node_from_link(
            "vless://11111111-1111-1111-1111-111111111111@srv.example.com:443?security=none#Germany1"
        )
        fake_mgr = mock.MagicMock()
        fake_mgr.connected = False
        fake_mgr.active_node = None
        fake_mgr._reconnecting = False
        fake_mgr.status_msg = ""
        fake_mgr.proxy_port = 10850
        fake_mgr.core_name = "Xray Core"
        fake_mgr.query_traffic_stats.return_value = {}

        class _FakeStdscr:
            def __init__(self, keys):
                self._keys = list(keys)
                self.drawn = []

            def nodelay(self, _v): pass
            def timeout(self, _v): pass
            def getmaxyx(self): return (24, 90)
            def erase(self): self.drawn.clear()
            def attron(self, _a): pass
            def attroff(self, _a): pass
            def refresh(self): pass
            def addstr(self, y, x, text, *_args): self.drawn.append((y, x, text))
            def get_wch(self):
                if not self._keys:
                    raise AssertionError("Should have exited cleanly on second Escape")
                return self._keys.pop(0)

        # '/', 'س' (unmatched), Enter, 1st Esc clears filter, 2nd Esc quits
        scr = _FakeStdscr(["/", "س", "\n", "\x1b", "\x1b"])
        with (
            mock.patch.multiple(
                cli_mod.curses,
                curs_set=lambda _v: None,
                use_default_colors=lambda: None,
                init_pair=lambda *_a: None,
                color_pair=lambda n: n,
            ),
            mock.patch.object(cli_mod, "get_gnome_proxy_state", return_value=False),
            mock.patch.object(xhm_core, "is_tun_active", return_value=False),
        ):
            cli_mod.draw_ui(scr, fake_mgr)

        self.assertEqual(scr._keys, [])
        self.assertGreaterEqual(fake_mgr.query_traffic_stats.call_count, 5)


class TestWebUiAssets(unittest.TestCase):
    def test_ui_accessibility_contrast_and_js_syntax(self):
        with open(os.path.join(WEB_DIR, "manifest.json"), "r", encoding="utf-8") as f:
            manifest = json.load(f)
        self.assertEqual(manifest.get("theme_color"), "#10121a")

        with open(os.path.join(WEB_DIR, "index.html"), "r", encoding="utf-8") as f:
            html = f.read()

        self.assertIn("color-scheme: dark;", html)
        self.assertIn(".btn-action.active", html)
        self.assertRegex(html, r"#addModal\s*\{[^}]*z-index:\s*1050")
        self.assertIn('id="toastContainer" role="status" aria-live="polite"', html)

        for modal_id in ("addModal", "inspectorModal", "subsModal", "trafficModal", "confirmModal", "updateModal"):
            self.assertRegex(html, rf'id="{modal_id}"[^>]*role="dialog"[^>]*aria-modal="true"')
        self.assertIn('id="updatePill"', html)

        style_m = re.search(r"<style>(.*?)</style>", html, re.S)
        self.assertIsNotNone(style_m)
        declared = set(re.findall(r"(--[a-zA-Z0-9_-]+)\s*:", style_m.group(1)))
        used = set(re.findall(r"var\((--[a-zA-Z0-9_-]+)\)", html))
        self.assertEqual(used - declared, set())

        node_bin = shutil.which("node")
        if node_bin:
            scripts = re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>", html, re.S)
            self.assertGreaterEqual(len(scripts), 1)
            with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as tf:
                tf.write(scripts[-1])
                js_path = tf.name
            try:
                res = subprocess.run([node_bin, "--check", js_path], capture_output=True, text=True)
                self.assertEqual(res.returncode, 0, msg=res.stderr)
            finally:
                os.unlink(js_path)


class TestGitUpdateAndInstaller(_IsolatedXhmTestCase):
    def test_github_url_parsing_and_update_cache(self):
        self.assertEqual(
            xhm_core.extract_github_owner_repo("git@github.com:Man30ur/xhm.git"),
            ("Man30ur", "xhm"),
        )
        self.assertEqual(
            xhm_core.extract_github_owner_repo("https://github.com/Man30ur/xhm"),
            ("Man30ur", "xhm"),
        )
        self.assertEqual(
            xhm_core.normalize_github_https("git@github.com:Man30ur/xhm.git"),
            "https://github.com/Man30ur/xhm.git",
        )

        meta = {
            "version": "1.0.0",
            "commit": "1111111111111111111111111111111111111111",
            "short_commit": "1111111",
            "branch": "main",
            "remote_url": "https://github.com/Man30ur/xhm.git",
            "repo_dir": "",
        }
        with open(xhm_core.INSTALL_META_FILE, "w", encoding="utf-8") as f:
            json.dump(meta, f)

        fake_cmp = {
            "status": "ahead",
            "ahead_by": 2,
            "html_url": "https://github.com/Man30ur/xhm/compare/1111111...main",
            "commits": [
                {
                    "sha": "2222222222222222222222222222222222222222",
                    "commit": {
                        "message": "feat: add update notifier\n\nmore details",
                        "author": {"date": "2026-11-14T00:00:00Z"},
                    },
                }
            ],
        }
        with (
            mock.patch.object(xhm_core, "_urlopen_json", return_value=fake_cmp) as m_url,
            mock.patch.object(xhm_core, "is_port_in_use", return_value=False),
        ):
            res1 = xhm_core.check_for_updates(force=True)
            self.assertTrue(res1["update_available"])
            self.assertEqual(res1["ahead_by"], 2)
            self.assertEqual(res1["latest_short"], "2222222")
            self.assertEqual(res1["commit_message"], "feat: add update notifier")
            self.assertFalse(res1["cached"])
            self.assertEqual(m_url.call_count, 1)

            res2 = xhm_core.check_for_updates(force=False)
            self.assertTrue(res2["cached"])
            self.assertTrue(res2["update_available"])
            self.assertEqual(m_url.call_count, 1)

        with (
            mock.patch.object(xhm_core, "_fetch_remote_head_info", side_effect=OSError("offline")),
            mock.patch.object(xhm_core, "is_port_in_use", return_value=False),
        ):
            res_off = xhm_core.check_for_updates(force=True)
            self.assertFalse(res_off["update_available"])
            self.assertTrue(res_off["offline"])
            self.assertIn("offline", res_off["error"])

    def test_apply_git_update_guards_dirty_repo_and_updates_clean_repo(self):
        fake_repo = os.path.join(self._tmpdir.name, "repo")
        os.makedirs(os.path.join(fake_repo, ".git"), exist_ok=True)
        with open(xhm_core.INSTALL_META_FILE, "w", encoding="utf-8") as f:
            json.dump({
                "version": "1.0.0",
                "commit": "aaaaaaa000000000000000000000000000000000",
                "short_commit": "aaaaaaa",
                "branch": "main",
                "remote_url": "https://github.com/Man30ur/xhm.git",
                "repo_dir": fake_repo,
            }, f)

        # 1. Dirty repo must refuse auto-pull cleanly
        dirty_meta = {
            "version": "1.0.0",
            "commit": "aaaaaaa000000000000000000000000000000000",
            "short_commit": "aaaaaaa",
            "branch": "main",
            "remote_url": "https://github.com/Man30ur/xhm.git",
            "repo_dir": fake_repo,
            "has_git_repo": True,
            "local_head": "aaaaaaa000000000000000000000000000000000",
            "local_short": "aaaaaaa",
            "repo_clean": False,
            "sync_needed": False,
        }
        with mock.patch.object(xhm_core, "get_installed_meta", return_value=dirty_meta):
            res_dirty = xhm_core.apply_git_update()
            self.assertFalse(res_dirty["success"])
            self.assertTrue(res_dirty["dirty"])

        # 2. Clean repo runs git pull --ff-only cleanly
        clean_before = dict(dirty_meta, repo_clean=True)
        clean_after = dict(
            dirty_meta,
            repo_clean=True,
            commit="bbbbbbb000000000000000000000000000000000",
            short_commit="bbbbbbb",
            local_head="bbbbbbb000000000000000000000000000000000",
            local_short="bbbbbbb",
        )
        ok_proc = mock.Mock(returncode=0, stdout="Updating aaaaaaa..bbbbbbb\n", stderr="")
        with (
            mock.patch.object(xhm_core, "get_installed_meta", side_effect=[clean_before, clean_after]),
            mock.patch.object(xhm_core.subprocess, "run", return_value=ok_proc) as m_run,
            mock.patch.object(xhm_core, "is_port_in_use", return_value=False),
        ):
            res_ok = xhm_core.apply_git_update()
            self.assertTrue(res_ok["success"])
            self.assertTrue(res_ok["updated"])
            self.assertTrue(res_ok["restart_required"])
            self.assertEqual(res_ok["new_short"], "bbbbbbb")
            self.assertEqual(m_run.call_args_list[0][0][0], ["git", "-C", fake_repo, "pull", "--ff-only"])

    def test_server_update_endpoints_isolated(self):
        orig_mgr = web_server.manager
        with mock.patch("xhm_core.get_current_gnome_proxy", return_value={"mode": "none"}), \
             mock.patch("xhm_core.subprocess.run"):
            web_server.manager = xhm_core.ProxyManager(proxy_port=39850)

        server = web_server.XhmHttpServer(("127.0.0.1", 0), web_server.XhmApiHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with mock.patch.object(
                xhm_core,
                "check_for_updates",
                return_value={"update_available": True, "installed_version": "1.0.0", "latest_short": "deadbee"},
            ):
                with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/check-update?force=1", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    data = json.loads(resp.read().decode("utf-8"))
                    self.assertTrue(data["update_available"])
                    self.assertEqual(data["latest_short"], "deadbee")

            with mock.patch.object(
                xhm_core,
                "apply_git_update",
                return_value={"success": True, "updated": True, "restart_required": True, "message": "Updated cleanly"},
            ):
                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/api/apply-update",
                    data=b"{}",
                    method="POST",
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    post_data = json.loads(resp.read().decode("utf-8"))
                    self.assertTrue(post_data["success"])
                    self.assertTrue(post_data["restart_required"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            web_server.manager = orig_mgr

    def test_cli_update_check(self):
        fake_mgr = mock.Mock()
        fake_mgr.connected = False
        fake_mgr.proxy_port = 10850
        args = argparse.Namespace(command="update", target=None, check=True)
        out_buf = io.StringIO()
        with (
            mock.patch.object(
                xhm_core,
                "check_for_updates",
                return_value={
                    "installed_version": "1.0.0",
                    "installed_short": "1111111",
                    "latest_short": "2222222",
                    "branch": "main",
                    "commit_message": "fix: stability",
                    "update_available": True,
                },
            ),
            contextlib.redirect_stdout(out_buf),
        ):
            with self.assertRaises(SystemExit) as cm:
                cli_mod.handle_cli_args(args, fake_mgr)
        self.assertEqual(cm.exception.code, 0)
        output = out_buf.getvalue()
        self.assertIn("[UPDATE]", output)
        self.assertIn("2222222", output)

    def test_install_script_syntax_and_isolated_home_install_and_bootstrap(self):
        install_sh = os.path.join(REPO_ROOT, "install.sh")
        syn = subprocess.run(["bash", "-n", install_sh], capture_output=True, text=True)
        self.assertEqual(syn.returncode, 0, msg=syn.stderr)

        fake_home = os.path.join(self._tmpdir.name, "home_direct")
        os.makedirs(fake_home, exist_ok=True)
        env = os.environ.copy()
        env["HOME"] = fake_home
        res = subprocess.run(
            ["bash", install_sh, "--no-deps", "--no-grant-tun-cap", "--user-only"],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
        self.assertEqual(res.returncode, 0, msg=res.stdout + "\n" + res.stderr)
        self.assertTrue(os.path.isfile(os.path.join(fake_home, ".local", "bin", "xhm-gui")))
        self.assertTrue(os.path.islink(os.path.join(fake_home, ".local", "bin", "xhm")))
        self.assertTrue(os.path.isfile(os.path.join(fake_home, ".local", "share", "xhm", "VERSION")))
        meta_path = os.path.join(fake_home, ".local", "share", "xhm", "install_meta.json")
        self.assertTrue(os.path.isfile(meta_path))
        with open(meta_path, "r", encoding="utf-8") as f:
            meta = json.load(f)
        self.assertEqual(meta["repo_dir"], os.path.realpath(REPO_ROOT))
        self.assertTrue(meta["version"])
        self.assertFalse(meta["bootstrap_mode"])

        # Self-bootstrap mode from standalone install.sh using a local temporary repo clone
        boot_dir = os.path.join(self._tmpdir.name, "standalone")
        os.makedirs(boot_dir, exist_ok=True)
        boot_script = os.path.join(boot_dir, "install.sh")
        shutil.copy2(install_sh, boot_script)
        seed_repo = os.path.join(self._tmpdir.name, "seed_repo")
        shutil.copytree(REPO_ROOT, seed_repo, ignore=shutil.ignore_patterns(".venv", "__pycache__"))
        subprocess.run(["git", "-C", seed_repo, "add", "-A"], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", seed_repo, "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-q", "-m", "snapshot"],
            check=True,
            capture_output=True,
        )
        fake_home2 = os.path.join(self._tmpdir.name, "home_boot")
        boot_repo_dest = os.path.join(fake_home2, ".local", "share", "xhm", "repo")
        env2 = os.environ.copy()
        env2["HOME"] = fake_home2
        env2["XHM_REPO_URL"] = f"file://{seed_repo}"
        env2["XHM_REPO_DIR"] = boot_repo_dest
        res_boot = subprocess.run(
            ["bash", boot_script, "--no-deps", "--no-grant-tun-cap", "--user-only"],
            capture_output=True,
            text=True,
            env=env2,
            timeout=30,
        )
        self.assertEqual(res_boot.returncode, 0, msg=res_boot.stdout + "\n" + res_boot.stderr)
        with open(os.path.join(fake_home2, ".local", "share", "xhm", "install_meta.json"), "r", encoding="utf-8") as f:
            meta2 = json.load(f)
        self.assertTrue(meta2["bootstrap_mode"])
        self.assertEqual(meta2["repo_dir"], os.path.realpath(boot_repo_dest))


if __name__ == "__main__":
    unittest.main()
