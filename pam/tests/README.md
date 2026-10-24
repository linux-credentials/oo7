# PAM request lifetime tests

On Linux, with Python 3, a C compiler, and the Linux-PAM development headers,
run from the repository root:

```sh
cargo build --manifest-path pam/Cargo.toml
python3 pam/tests/test_request_lifetime.py target/debug/libpam_oo7.so
```

The tests run short-lived C applications through Linux-PAM with dummy passwords,
a temporary `pam_start_confdir` configuration, and a private socket that delays
its response. Both session opening and password changes must finish sending
before PAM returns. An unavailable daemon must still allow PAM to succeed.
A connected daemon that reads the request but never replies must allow PAM to
succeed after the existing response timeout. This tests that response wait, not
an overall deadline for every transport or helper path.

No root privileges, installed daemon, real keyrings, or changes to `/etc/pam.d`
are needed. Run as a user with its normal primary group. The module may write
diagnostic messages about these synthetic requests to the local journal.
These tests cover the same-UID socket path, not display-manager integration or
the root-to-user credential-switching path.
