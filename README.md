# OO7

[![docs](https://docs.rs/oo7/badge.svg)](https://docs.rs/oo7/) [![crates.io](https://img.shields.io/crates/v/oo7)](https://crates.io/crates/oo7) ![CI](https://github.com/linux-credentials/oo7/workflows/CI/badge.svg) [![Coverage](https://linux-credentials.github.io/oo7/coverage/badges/flat.svg)](https://linux-credentials.github.io/oo7/coverage/)

James Bond went on a new mission and this time as a [Secret Service provider](https://specifications.freedesktop.org/secret-service-spec/latest/).

The repository consists of the following projects:

- [cargo-credential](./cargo-credential/): a [cargo credential](https://doc.rust-lang.org/stable/cargo/reference/registry-authentication.html#registry-authentication) provider
- [cli](./cli/): a secret-tool replacement
- [client](./client/): the client side library
- [pam](./pam/): PAM integration for the server implementation
- [portal](./portal/): [org.freedesktop.impl.portal.Secret](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.Secret.html) implementation
- [server](./server/): [org.freedesktop.secrets](https://specifications.freedesktop.org/secret-service-spec/latest/) server implementation

## Hacking on oo7 services

### Testing oo7-daemon

The daemon can be testing by simply compiling and running the binary with

```sh
cargo run --bin oo7-daemon -- --verbose --replace --login
```

Note however that if `gnome-keyring-daemon` is running, it will need to be
killed directly before running `oo7-daemon`, as it is not running as a systemd
service.

### Testing oo7-portal

The oo7-portal service can be tested using [systemd-sysext][systemd-sysext].
Directly running the binary is possible, but without a `oo7-portal.portal` file,
`xdg-desktop-portal` will ignore it.

First build the services on its subdirectory:

```sh
cd oo7-portal
meson setup --prefix=/usr _build
meson compile -C _build
DESTDIR=oo7-extension meson install -C _build
```

This will create a `oo7-extension` directory under `oo7-portal/_build`, which
can be moved to `/run/extensions`, afterwards extensions can be reloaded via

```sh
systemd-sysext refresh --force
```

> [!WARNING]
> In Fedora Silverblue one needs to disable SELinux via `setenforce 0` before
> loading any system extensions.

The portal can be then started with:
```sh
/usr/libexec/oo7-portal --replace --verbose
```

In order for `xdg-desktop-portal` to use `oo7-portal` as a server for
`org.freedesktop.impl.portal.Secret` it needs to be configured via a
[portals.conf][portals.conf] file at `/etc/xdg-desktop-portal/portals.conf`, see
the `portals.conf(5)` man page.

This can be achieved by creating a file at
`~/.config/xdg-desktop-portal/gnome-portals.conf` with contents:

``` toml
[preferred]
default=gnome;gtk;
org.freedesktop.impl.portal.Secret=oo7-portal;gnome-keyring;
```

and then, restarting `xdg-desktop-portal` via

```sh
systemctl restart --user xdg-desktop-portal
```

If more output is required, the later can be replaced with:

```sh
/usr/libexec/xdg-desktop-portal --replace --verbose
```

## License

The project is released under the MIT license.

[portals.conf]: https://flatpak.github.io/xdg-desktop-portal/docs/portals.conf.html
[systemd-sysext]: https://www.freedesktop.org/software/systemd/man/latest/systemd-sysext.html
