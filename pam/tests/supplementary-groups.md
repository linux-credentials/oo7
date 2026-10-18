# PAM supplementary-group regression

On Linux, with Python 3, bubblewrap, a C compiler, and the Linux-PAM development
headers, run from the repository root:

```sh
cargo build --manifest-path pam/Cargo.toml
sudo python3 pam/tests/test_supplementary_groups.py target/debug/libpam_oo7.so
```

The launcher uses private mount, PID, network, IPC and UTS namespaces. The host
filesystem is read-only; home directories, runtime sockets and temporary files
are hidden. It supplies a synthetic passwd/group database and private temporary
PAM configuration. No daemon, login helper, real password or keyring is used.
Root is needed to exercise the actual root-to-user credential switch. The test
does not create accounts, change host PAM configuration or access a live bus.

A C caller starts with supplementary group 0 and sends a dummy password through
the built module to a private socket. Linux socket credentials must report the
synthetic user's UID/GID and no supplementary groups. A second case checks that
the same-user path preserves its groups. Both cases verify that PAM leaves the
caller's original credentials unchanged. The caller stays alive until delivery
finishes, so this test does not depend on request-lifetime fixes.

The unpatched module fails the root-to-user assertion because group 0 survives.
The JSON result contains only peer UIDs/GIDs/groups and pass/fail status.
