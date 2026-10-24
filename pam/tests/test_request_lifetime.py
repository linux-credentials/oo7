#!/usr/bin/env python3
"""Exercise the built PAM module with real, short-lived Linux-PAM callers."""

import argparse
import os
import select
import shlex
import socket
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path


class RequestLifetimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Keep the Unix socket path short, regardless of the checkout location.
        cls.temporary = tempfile.TemporaryDirectory(prefix="oo7-pam-", dir="/tmp")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        source = Path(__file__).resolve().parent
        compiler = shlex.split(os.environ.get("CC", "cc"))
        for name, options in [
            ("pam_caller", []),
            ("pam_test_tokens", ["-shared", "-fPIC"]),
        ]:
            output = cls.directory / (name + (".so" if options else ""))
            subprocess.run(
                compiler
                + ["-Wall", "-Wextra", "-Werror"]
                + options
                + [str(source / f"{name}.c"), "-o", str(output), "-lpam"],
                check=True,
            )
        # PAM module paths cannot contain spaces; the checkout path may do so.
        (cls.directory / "pam_oo7.so").symlink_to(MODULE)
        (cls.directory / "oo7-test").write_text(
            f"auth required {cls.directory}/pam_test_tokens.so\n"
            f"auth required {cls.directory}/pam_oo7.so\n"
            f"session required {cls.directory}/pam_oo7.so\n"
            f"password required {cls.directory}/pam_test_tokens.so\n"
            f"password required {cls.directory}/pam_oo7.so\n"
        )

    def start_caller(self, operation, socket_path):
        # No auto_start option, live daemon, user keyrings, or system PAM config.
        environment = {
            "PATH": os.defpath,
            "HOME": str(self.directory),
            "XDG_RUNTIME_DIR": str(self.directory),
            "OO7_PAM_SOCKET": str(socket_path),
        }
        process = subprocess.Popen(
            [str(self.directory / "pam_caller"), str(self.directory), operation],
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )

        def cleanup():
            if process.poll() is None:
                process.kill()
            process.communicate()

        self.addCleanup(cleanup)
        self.assertTrue(
            select.select([process.stdout], [], [], 5)[0], "caller did not start"
        )
        self.assertEqual(process.stdout.readline(), b"calling\n")
        return process

    def assert_pending(self, process, peer, timeout=5):
        ready, _, _ = select.select([peer, process.stdout], [], [], timeout)
        self.assertNotIn(
            process.stdout, ready, "PAM returned before the daemon response"
        )
        self.assertIn(peer, ready, "PAM did not send a request")

    def read_exact(self, process, connection, size):
        data = b""
        while len(data) < size:
            self.assert_pending(process, connection)
            chunk = connection.recv(size - len(data))
            self.assertTrue(chunk, "caller disconnected before completing the request")
            data += chunk
        return data

    def check_delivery(self, operation, respond=True):
        socket_path = self.directory / f"{operation}.sock"
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(socket_path))
            self.addCleanup(socket_path.unlink)
            os.chmod(socket_path, 0o600)
            listener.listen(1)
            process = self.start_caller(operation, socket_path)
            self.assert_pending(process, listener)
            with listener.accept()[0] as connection:
                size = struct.unpack("<I", self.read_exact(process, connection, 4))[0]
                self.assertLess(size, 4096)
                request = self.read_exact(process, connection, size)
                self.assertEqual(request[0], 0 if operation == "session" else 1)
                self.assertIn(b"oo7-test-old-password", request)
                if operation == "password":
                    self.assertIn(b"oo7-test-new-password", request)

                # Deliberately withhold the response: even a detached sender that
                # raced far enough to write its request must not let PAM return.
                self.assertFalse(
                    select.select([process.stdout], [], [], 0.1)[0],
                    "PAM returned while its request was still awaiting a response",
                )
                if respond:
                    # GVariant (bool true, empty string), with the PAM frame prefix.
                    response = b"\x01\x00"
                    connection.sendall(struct.pack("<I", len(response)) + response)
                # Keep the peer connected while checking the response timeout.
                output, errors = process.communicate(timeout=5 if respond else 10)
            self.assertEqual(process.returncode, 0, errors.decode(errors="replace"))
            self.assertEqual(output, b"returned 0\n")

    def test_open_session_waits_for_delivery(self):
        self.check_delivery("session")

    def test_password_change_waits_for_delivery(self):
        self.check_delivery("password")

    def test_unresponsive_daemon_still_returns_success(self):
        self.check_delivery("session", respond=False)

    def test_unavailable_daemon_still_returns_success(self):
        for operation in ("session", "password"):
            with self.subTest(operation=operation):
                process = self.start_caller(operation, self.directory / "absent.sock")
                output, errors = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, errors.decode(errors="replace"))
                self.assertEqual(output, b"returned 0\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path, help="path to the built libpam_oo7.so")
    arguments = parser.parse_args()
    MODULE = arguments.module.resolve(strict=True)
    unittest.main(argv=[__file__], verbosity=2)
