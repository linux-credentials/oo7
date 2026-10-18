#!/usr/bin/env python3
"""Check PAM credential switching with a synthetic user in private namespaces."""

import argparse
import array
import json
import os
import shlex
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

OBSERVED = {}


class SupplementaryGroupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="oo7-pam-", dir="/tmp")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.directory.chmod(0o755)
        compiler = shlex.split(os.environ.get("CC", "cc"))
        for name, options in [
            ("pam_group_caller", []),
            ("pam_test_tokens", ["-shared", "-fPIC"]),
        ]:
            output = cls.directory / (name + (".so" if options else ""))
            subprocess.run(
                compiler
                + ["-Wall", "-Wextra", "-Werror"]
                + options
                + [f"/tmp/oo7-tests/{name}.c", "-o", str(output), "-lpam"],
                check=True,
            )
        (cls.directory / "oo7-test").write_text(
            f"auth required {cls.directory}/pam_test_tokens.so\n"
            "auth required /tmp/module.so\n"
            "session required /tmp/module.so\n"
        )

    def check_peer(self, username, uid, expected_groups):
        socket_path = self.directory / f"{username}.sock"
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(socket_path))
            self.addCleanup(socket_path.unlink)
            socket_path.chmod(0o600)
            os.chown(socket_path, uid, uid)
            listener.listen(1)
            listener.settimeout(10)
            process = subprocess.Popen(
                [
                    str(self.directory / "pam_group_caller"),
                    str(self.directory),
                    username,
                ],
                env={
                    "PATH": os.defpath,
                    "HOME": str(self.directory),
                    "XDG_RUNTIME_DIR": str(self.directory),
                    "OO7_PAM_SOCKET": str(socket_path),
                },
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            def cleanup():
                if process.poll() is None:
                    process.kill()
                process.communicate()

            self.addCleanup(cleanup)
            with listener.accept()[0] as peer:
                peer.settimeout(10)
                _, peer_uid, peer_gid = struct.unpack(
                    "3i", peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
                )
                # Linux SO_PEERGROUPS (since 4.9), absent from some Python builds.
                groups = array.array("I")
                groups.frombytes(peer.getsockopt(socket.SOL_SOCKET, 59, 256))
                OBSERVED[username] = {
                    "uid": peer_uid,
                    "gid": peer_gid,
                    "groups": list(groups),
                }
                length = struct.unpack("<I", self.read_exact(peer, 4))[0]
                self.assertLess(length, 4096)
                self.assertIn(b"oo7-test-old-password", self.read_exact(peer, length))
                response = b"\x01\x00"  # GVariant (true, empty string).
                peer.sendall(struct.pack("<I", len(response)) + response)
                self.assertEqual(peer.recv(1), b"")
            output, errors = process.communicate(input=b"\n", timeout=10)
            self.assertEqual(process.returncode, 0, errors.decode(errors="replace"))
            self.assertEqual(output, b"")
            self.assertEqual((peer_uid, peer_gid), (uid, uid))
            self.assertEqual(list(groups), expected_groups)

    @staticmethod
    def read_exact(peer, size):
        data = b""
        while len(data) < size:
            chunk = peer.recv(size - len(data))
            if not chunk:
                raise AssertionError("incomplete PAM request")
            data += chunk
        return data

    def test_root_to_user_discards_inherited_groups(self):
        self.check_peer("oo7-test", 65534, [])

    def test_same_user_preserves_groups(self):
        self.check_peer("root", 0, [0])


def private_namespace(module):
    if os.geteuid() != 0:
        raise SystemExit(
            "Run through sudo; only private namespaces and synthetic data are used."
        )
    descriptors = []

    def fixture(text):
        fd = os.memfd_create("oo7-group-test")
        os.write(fd, text.encode())
        os.lseek(fd, 0, os.SEEK_SET)
        os.fchmod(fd, 0o444)
        descriptors.append(fd)
        return str(fd)

    command = [
        "bwrap",
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--ro-bind",
        "/",
        "/",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
        "--tmpfs",
        "/home",
        "--tmpfs",
        "/root",
        "--ro-bind",
        str(Path(__file__).resolve().parent),
        "/tmp/oo7-tests",
        "--ro-bind",
        str(module),
        "/tmp/module.so",
        "--clearenv",
        "--setenv",
        "PATH",
        os.defpath,
        "--chdir",
        "/tmp",
        "--cap-add",
        "CAP_SETUID",
        "--cap-add",
        "CAP_SETGID",
        "--cap-add",
        "CAP_CHOWN",
        "--perms",
        "0444",
        "--ro-bind-data",
        fixture(
            "root:x:0:0:root:/root:/bin/false\n"
            "oo7-test:x:65534:65534:fixture:/tmp:/bin/false\n"
        ),
        "/etc/passwd",
        "--perms",
        "0444",
        "--ro-bind-data",
        fixture("root:x:0:\noo7-test:x:65534:\n"),
        "/etc/group",
        "--perms",
        "0444",
        "--ro-bind-data",
        fixture("passwd: files\ngroup: files\n"),
        "/etc/nsswitch.conf",
        "/usr/bin/python3",
        "/tmp/oo7-tests/test_supplementary_groups.py",
        "--inside",
    ]
    try:
        try:
            return subprocess.run(command, pass_fds=descriptors, timeout=120).returncode
        except subprocess.TimeoutExpired:
            print(
                "PAM group test exceeded 120 seconds; private namespace terminated.",
                file=sys.stderr,
            )
            return 1
    finally:
        for fd in descriptors:
            os.close(fd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("module", type=Path, nargs="?")
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    arguments = parser.parse_args()
    if arguments.inside:
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(
            SupplementaryGroupTests
        )
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        print(json.dumps({"passed": result.wasSuccessful(), "peers": OBSERVED}))
        sys.exit(0 if result.wasSuccessful() else 1)
    if arguments.module is None:
        parser.error("the built libpam_oo7.so path is required")
    sys.exit(private_namespace(arguments.module.resolve(strict=True)))
