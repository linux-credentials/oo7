# PAM tests

Requires Linux and Linux-PAM development files (`libpam0g-dev` on Debian/Ubuntu).

```sh
cargo test -p oo7-pam
```

Run with your normal primary group; no root access or system PAM changes are needed.
For a single test, put its name after `--`. Cargo target selectors (`--test`,
`--all-targets`), filters before `--`, and a separate `build.build-dir` are unsupported.
