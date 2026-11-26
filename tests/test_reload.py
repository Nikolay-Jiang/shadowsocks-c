#!/usr/bin/env python3
"""Users-only reload: add, remove, PSK rotation, immediate drop, identity policy."""

import base64
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import unittest


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(16384)
            if not data:
                return
            self.request.sendall(data)


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError
        data.extend(chunk)
    return bytes(data)


def socks_connect(proxy_port, target_port, timeout=3):
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    sock.sendall(b"\x05\x01\x00")
    if recv_exact(sock, 2) != b"\x05\x00":
        raise AssertionError("SOCKS greeting failed")
    host = b"127.0.0.1"
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", target_port))
    head = recv_exact(sock, 4)
    if head[1] != 0:
        raise AssertionError(f"SOCKS request failed: {head.hex()}")
    if head[3] == 1:
        recv_exact(sock, 4)
    elif head[3] == 4:
        recv_exact(sock, 16)
    elif head[3] == 3:
        recv_exact(sock, recv_exact(sock, 1)[0])
    recv_exact(sock, 2)
    return sock


def random_psk():
    return base64.b64encode(os.urandom(32)).decode()


def wait_until(predicate, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


class ReloadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bin = Path(os.environ.get("SS_BIN_DIR", "build/bin")).resolve()
        for name in ("ss-server", "ss-local"):
            if not (cls.bin / name).is_file():
                raise RuntimeError(f"missing {name} in {cls.bin}")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.origin = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoHandler)
        self.origin.daemon_threads = True
        self.origin_port = self.origin.server_address[1]
        threading.Thread(target=self.origin.serve_forever, daemon=True).start()
        self.processes = []
        self.method = "2022-blake3-aes-256-gcm"

    def tearDown(self):
        for proc in reversed(self.processes):
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
        self.origin.shutdown()
        self.origin.server_close()
        self.tmp.cleanup()

    def start_server(self, users, port, require_identity=True):
        server_psk = random_psk()
        self.server_psk = server_psk
        self.config = {
            "server": "127.0.0.1",
            "server_port": port,
            "method": self.method,
            "password": server_psk,
            "users": users,
            "control_socket": str(self.dir / "control.sock"),
            "access_log": False,
            "require_identity": require_identity,
        }
        self.config_path = self.dir / "config.json"
        self.write_config()
        proc = subprocess.Popen(
            [str(self.bin / "ss-server"), "-c", str(self.config_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.processes.append(proc)
        if not wait_until(lambda: (self.dir / "control.sock").exists(), 5):
            output = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
            raise AssertionError(f"ss-server did not start:\n{output}")
        return proc

    def write_config(self):
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")

    def reload(self):
        client_path = self.dir / "client.sock"
        if client_path.exists():
            client_path.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.bind(str(client_path))
            sock.settimeout(3)
            sock.sendto(b"reload", str(self.dir / "control.sock"))
            return sock.recv(4096).decode(errors="replace").strip()

    def start_local(self, password, port):
        proc = subprocess.Popen(
            [str(self.bin / "ss-local"), "-s", "127.0.0.1", "-p", str(self.server_port),
             "-l", str(port), "-k", password, "-m", self.method],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.processes.append(proc)
        if not wait_until(lambda: self._port_open(port), 5):
            output = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
            raise AssertionError(f"ss-local did not start:\n{output}")
        return proc

    @staticmethod
    def _port_open(port):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            return False

    def echo_through(self, local_port):
        sock = socks_connect(local_port, self.origin_port)
        sock.sendall(b"reload-test")
        self.assertEqual(recv_exact(sock, 11), b"reload-test")
        return sock

    def test_remove_user_drops_existing_connection(self):
        user1 = random_psk()
        user2 = random_psk()
        self.server_port = 18701
        self.start_server({"u00001": user1, "u00002": user2}, self.server_port)
        self.start_local(f"{self.server_psk}:{user1}", 19701)
        sock = self.echo_through(19701)

        del self.config["users"]["u00001"]
        self.write_config()
        self.assertIn("ok", self.reload())

        sock.settimeout(2)
        self.assertEqual(sock.recv(1), b"")
        sock.close()

        # The remaining user still works, while the removed identity fails.
        self.start_local(f"{self.server_psk}:{user2}", 19702)
        self.echo_through(19702).close()
        self.start_local(f"{self.server_psk}:{user1}", 19703)
        with self.assertRaises((EOFError, ConnectionError, TimeoutError, OSError)):
            self.echo_through(19703)

    def test_psk_rotation_drops_old_identity(self):
        old_psk = random_psk()
        other_psk = random_psk()
        self.server_port = 18702
        self.start_server({"u00001": old_psk, "u00002": other_psk}, self.server_port)
        self.start_local(f"{self.server_psk}:{old_psk}", 19704)
        sock = self.echo_through(19704)

        new_psk = random_psk()
        self.config["users"]["u00001"] = new_psk
        self.write_config()
        self.assertIn("ok", self.reload())

        sock.settimeout(2)
        self.assertEqual(sock.recv(1), b"")
        sock.close()
        self.start_local(f"{self.server_psk}:{new_psk}", 19705)
        self.echo_through(19705).close()

    def test_require_identity_rejects_server_psk_only(self):
        user_psk = random_psk()
        self.server_port = 18703
        self.start_server({"u00001": user_psk}, self.server_port)
        self.start_local(self.server_psk, 19706)
        with self.assertRaises((EOFError, ConnectionError, TimeoutError, OSError)):
            self.echo_through(19706)

    def test_non_user_change_requires_restart(self):
        user_psk = random_psk()
        self.server_port = 18704
        self.start_server({"u00001": user_psk}, self.server_port)
        original_port = self.config["server_port"]

        self.config["server_port"] = original_port + 1
        self.write_config()
        self.assertIn("restart_required", self.reload())

        self.config["server_port"] = original_port
        self.config["require_identity"] = False
        self.write_config()
        self.assertIn("restart_required", self.reload())

        # The running server still has the old policy and user.
        self.config["require_identity"] = True
        self.write_config()
        self.start_local(f"{self.server_psk}:{user_psk}", 19707)
        self.echo_through(19707).close()


if __name__ == "__main__":
    unittest.main()
