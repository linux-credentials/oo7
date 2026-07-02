
# git-credential-oo7

[![crates.io](https://img.shields.io/crates/v/git-credential-oo7)](https://crates.io/crates/git-credential-oo7)

A [git credential helper](https://git-scm.com/docs/gitcredentials) built using oo7 instead of [libsecret](https://gitlab.gnome.org/GNOME/libsecret).

## Installation

1 - `cargo install git-credential-oo7`

2 - Set as the default credential helper

```
git config --global credential.helper oo7
```

## License

The project is released under the MIT license.
