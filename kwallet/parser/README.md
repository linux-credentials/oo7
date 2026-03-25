# kwallet-parser

Read-only parser for KWallet file format supporting legacy (Blowfish-ECB + SHA1) and modern (Blowfish-CBC + PBKDF2-SHA512) formats.

## Usage

```rust
use kwallet_parser::KWalletFile;

let wallet = KWalletFile::open("path/to/wallet.kwl", b"password")?;

for (folder_name, folder) in wallet.wallet() {
    for (key, entry) in folder {
        match entry.entry_type() {
            kwallet_parser::EntryType::Password => {
                println!("{}: {}", key, entry.as_password()?);
            }
            kwallet_parser::EntryType::Map => {
                println!("{}: {:?}", key, entry.as_map()?);
            }
            kwallet_parser::EntryType::Stream => {
                println!("{}: {} bytes", key, entry.as_stream().len());
            }
            _ => {}
        }
    }
}
```

See library documentation for full API.
