#!/usr/bin/env python3
"""
Standalone interface-bound TCP/TLS dialer for OpenSSH ProxyCommand.
Supports SO_BINDTODEVICE to bypass TUN/VPN default routes (e.g. xray-tun)
so SSH tunnels stay bound to the physical uplink interface.
"""
import argparse
import errno
import os
import socket
import ssl
import sys
import threading

SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EPIPE, "short write to stdout")
        view = view[written:]


def _resolve_targets(host: str, port: int):
    last_err = None
    for family in (socket.AF_INET, socket.AF_UNSPEC):
        try:
            res = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
            if res:
                return res
        except OSError as exc:
            last_err = exc
    if last_err:
        raise last_err
    raise OSError(f"Unable to resolve {host}:{port}")


def _connect_socket(host: str, port: int, iface: str, timeout: float) -> socket.socket:
    targets = _resolve_targets(host, port)
    last_err = None
    for family, socktype, proto, _, sockaddr in targets:
        sock = None
        try:
            sock = socket.socket(family, socktype, proto)
            sock.settimeout(timeout)
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except OSError:
                pass
            if iface and iface != "auto":
                try:
                    ifbytes = iface.encode("utf-8") + b"\0"
                    sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, ifbytes)
                except OSError as exc:
                    print(f"[xhm_ssh_dialer] SO_BINDTODEVICE({iface}) warning: {exc}", file=sys.stderr)
            sock.connect(sockaddr)
            sock.settimeout(None)
            return sock
        except OSError as exc:
            last_err = exc
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
    if last_err:
        raise last_err
    raise OSError(f"Failed to connect to {host}:{port}")


def _wrap_tls(sock: socket.socket, sni: str, timeout: float) -> ssl.SSLSocket:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock.settimeout(timeout)
    tls_sock = ctx.wrap_socket(sock, server_hostname=sni)
    tls_sock.settimeout(None)
    return tls_sock


def _relay(sock: socket.socket, is_tls: bool) -> int:
    sock_done = threading.Event()

    def stdin_to_sock():
        try:
            while True:
                data = os.read(0, 32768)
                if not data:
                    break
                sock.sendall(data)
        except OSError:
            pass
        finally:
            if not is_tls:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
            if not sock_done.wait(2.0):
                try:
                    sock.close()
                except OSError:
                    pass

    def sock_to_stdout():
        try:
            while True:
                data = sock.recv(32768)
                if not data:
                    break
                _write_all(1, data)
        except OSError:
            pass
        finally:
            sock_done.set()
            try:
                os.close(1)
            except OSError:
                pass

    t_in = threading.Thread(target=stdin_to_sock, daemon=True)
    t_out = threading.Thread(target=sock_to_stdout, daemon=True)
    t_in.start()
    t_out.start()

    t_out.join()
    t_in.join(timeout=0.35)
    try:
        sock.close()
    except OSError:
        pass
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="XHM interface-bound SSH ProxyCommand dialer")
    parser.add_argument("host", help="Target hostname or IP")
    parser.add_argument("port", type=int, help="Target TCP port")
    parser.add_argument("--iface", default="", help="Network interface to bind (SO_BINDTODEVICE)")
    parser.add_argument("--sni", default="", help="Optional TLS SNI for SSH-over-TLS")
    parser.add_argument("--timeout", type=float, default=10.0, help="Connect timeout in seconds")
    args = parser.parse_args()

    try:
        sock = _connect_socket(args.host, args.port, args.iface, args.timeout)
        is_tls = False
        if args.sni:
            sock = _wrap_tls(sock, args.sni, args.timeout)
            is_tls = True
        return _relay(sock, is_tls)
    except Exception as exc:
        print(f"[xhm_ssh_dialer] {args.host}:{args.port} error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
