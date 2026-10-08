# oo7 PAM Module

A PAM (Pluggable Authentication Modules) module that integrates with the oo7 Secret Service daemon to automatically unlock keyrings during user authentication.

## How It Works

The PAM module communicates with the oo7 daemon via a Unix domain socket to securely transmit the user's login password for keyring unlocking:

1. **Socket Creation**: The daemon (running as the user) creates the Unix domain socket at `$XDG_RUNTIME_DIR/oo7/pam.sock` (typically `/run/user/$UID/oo7/pam.sock`, or path specified by `OO7_PAM_SOCKET`)
   - Owner: The user running the daemon
   - Permissions: `0600` (read/write by owner only)
   - Process: The user's Secret Service daemon

2. **Authentication Flow**:
   - User enters their password during login e.g., GDM
   - PAM calls `pam_oo7.so` during the authentication phase
   - The PAM module writes the username and password to the socket
   - The daemon reads the credentials from the socket
   - The daemon uses the password to attempt unlocking the default keyring

## Building

Build the PAM module as a shared library:

```bash
cargo build --release -p pam_oo7
```

The resulting library will be at: `target/release/libpam_oo7.so`

## Installation

### 1. Copy the PAM module

```bash
sudo cp target/release/libpam_oo7.so /usr/lib64/security/pam_oo7.so
# or on some systems:
sudo cp target/release/libpam_oo7.so /lib/x86_64-linux-gnu/security/pam_oo7.so
```

### 2. Configure PAM

Add the module to your PAM configuration. For example, in `/etc/pam.d/system-auth` or `/etc/pam.d/common-auth`:

```
auth       optional     pam_oo7.so
```

**Important**: Use `optional` so that authentication doesn't fail if the oo7 daemon is not running.

### Example PAM configuration for GDM

In `/etc/pam.d/gdm-password`:

```
#%PAM-1.0
auth       required     pam_env.so
auth       required     pam_unix.so
auth       optional     pam_oo7.so
account    required     pam_unix.so
password   required     pam_unix.so
password   optional     pam_oo7.so
session    required     pam_unix.so
session    optional     pam_oo7.so auto_start
session    optional     pam_systemd.so
```

**Important**: The module should be added to three PAM stacks:
- `auth` stack: Captures and stashes the password during authentication
- `session` stack: Retrieves the stashed password and sends it to the daemon for keyring unlocking
- `password` stack: Intercepts password changes and updates the keyring password to match

#### Password Change Support

When added to the `password` stack, the module will automatically update your keyring passwords when you change your user password (e.g., using `passwd` command). This ensures your keyrings remain accessible after password changes.

The module intercepts the password change operation:
1. Captures both the old and new passwords
2. Sends them to the daemon
3. The daemon validates the old password and re-encrypts all matching keyrings with the new password

## Configuration

### Lockscreen credential refresh

Screen lockers that refresh PAM credentials after successful authentication can
unlock an already running oo7 daemon. Keep `pam_oo7.so` optional and place its
auth rule after the password-providing module. Credential refresh does not start
the daemon; use the session rule with `auto_start` for a new login.

### Environment Variables

- `OO7_PAM_SOCKET`: Path to the Unix domain socket for daemon communication
  - Default: `$XDG_RUNTIME_DIR/oo7/pam.sock` (typically `/run/user/$UID/oo7/pam.sock`)

## License

The project is released under the MIT license.
