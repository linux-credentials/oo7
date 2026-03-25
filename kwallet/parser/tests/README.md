# Test Files

## Test Wallet Files

### Legacy Format (version 0.0, Blowfish-ECB + SHA1)

- `blowfish_ecb_sha1_empty_password.kwl` - Password: `""` (empty string)
- `blowfish_ecb_sha1_long_password.kwl` - Password: `"pythonpythonpythonpythonpython"`

**Source**: [gaganpreet/kwallet-dump](https://github.com/gaganpreet/kwallet-dump/tree/master/tests/wallets)
Originally named `blank_pass.kwl` and `python5.kwl`. Credit to @gaganpreet for creating these test files.

### Modern Format (version 0.1, Blowfish-CBC + PBKDF2-SHA512)

- `blowfish_cbc_pbkdf2_sha512_manual.kwl` + `.salt` - Password: `"password"`

**Source**: Created manually for testing modern KWallet format.

## Test Code

- `blowfish_ecb_sha1.rs` - Integration tests for legacy format (version 0.0)
- `blowfish_cbc_pbkdf2_sha512.rs` - Integration tests for modern format (version 0.1)
