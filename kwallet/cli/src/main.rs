use std::{collections::HashMap, io::Write, path::PathBuf, process::ExitCode};

use clap::Parser;
use kwallet_parser::{EntryType, KWalletFile};
use serde::Serialize;

#[derive(Parser)]
#[command(about = "Read KWallet files")]
struct Cli {
    /// Path to wallet file (.kwl)
    wallet: PathBuf,

    /// Wallet password
    #[arg(short, long)]
    password: Option<String>,

    /// Output as JSON
    #[arg(long)]
    json: bool,

    /// Migrate entries to Secret Service
    #[arg(long)]
    migrate: bool,
}

#[derive(Serialize)]
#[serde(untagged)]
enum EntryValue {
    Password(String),
    Map(HashMap<String, String>),
    Stream(Vec<u8>),
}

#[derive(Serialize)]
struct EntryJson {
    #[serde(rename = "type")]
    entry_type: EntryType,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<EntryValue>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();

    let password = match cli.password {
        Some(p) => p,
        None => {
            eprint!("Password: ");
            std::io::stderr().flush().unwrap();
            match rpassword::read_password() {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("Can't read password: {}", e);
                    return ExitCode::FAILURE;
                }
            }
        }
    };

    let wallet = match KWalletFile::open(&cli.wallet, password.as_bytes()) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("Error: {}", e);
            return ExitCode::FAILURE;
        }
    };

    if cli.migrate {
        match migrate_to_secret_service(&wallet).await {
            Ok(count) => {
                println!(
                    "✓ Successfully migrated {} entries to Secret Service",
                    count
                );
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("✗ Migration failed: {}", e);
                ExitCode::FAILURE
            }
        }
    } else if cli.json {
        let mut output: HashMap<String, HashMap<String, EntryJson>> = HashMap::new();

        for (folder_name, folder) in wallet.wallet() {
            let mut entries = HashMap::new();

            for (key, entry) in folder {
                let entry_json = match entry.entry_type() {
                    EntryType::Password => EntryJson {
                        entry_type: entry.entry_type(),
                        value: entry.as_password().ok().map(EntryValue::Password),
                    },
                    EntryType::Map => EntryJson {
                        entry_type: entry.entry_type(),
                        value: entry.as_map().ok().map(EntryValue::Map),
                    },
                    EntryType::Stream => EntryJson {
                        entry_type: entry.entry_type(),
                        value: Some(EntryValue::Stream(entry.as_stream().to_vec())),
                    },
                    EntryType::Unknown => EntryJson {
                        entry_type: entry.entry_type(),
                        value: None,
                    },
                };

                entries.insert(key.clone(), entry_json);
            }

            output.insert(folder_name.clone(), entries);
        }

        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        ExitCode::SUCCESS
    } else {
        let mut first = true;
        for (folder_name, folder) in wallet.wallet() {
            if !first {
                println!();
            }
            first = false;

            println!("📁 {}:", folder_name);

            let entries: Vec<_> = folder.iter().collect();
            if entries.is_empty() {
                println!("   (empty)");
            } else {
                for (key, entry) in entries {
                    match entry.entry_type() {
                        EntryType::Password => {
                            if let Ok(password) = entry.as_password() {
                                println!("   🔑 {} (password): {}", key, password);
                            }
                        }
                        EntryType::Map => {
                            if let Ok(map) = entry.as_map() {
                                println!("   📋 {} (map):", key);
                                for (k, v) in map {
                                    println!("      {} = {}", k, v);
                                }
                            }
                        }
                        EntryType::Stream => {
                            println!("   📄 {} (stream): {} bytes", key, entry.as_stream().len());
                        }
                        EntryType::Unknown => {
                            println!("   ❓ {} (unknown)", key);
                        }
                    }
                }
            }
        }
        ExitCode::SUCCESS
    }
}

async fn migrate_to_secret_service(
    wallet: &KWalletFile,
) -> Result<usize, Box<dyn std::error::Error>> {
    let keyring = oo7::Keyring::new().await?;
    let mut count = 0;

    for (folder_name, folder) in wallet.wallet() {
        for (key, entry) in folder {
            match kwallet_parser::convert_entry(folder_name, key, entry) {
                Ok(ss_entry) => {
                    keyring
                        .create_item(
                            ss_entry.label(),
                            ss_entry.attributes(),
                            oo7::Secret::blob(ss_entry.secret()),
                            true,
                        )
                        .await?;
                    count += 1;
                    let entry_type = ss_entry
                        .attributes()
                        .get("type")
                        .map(|s| s.as_str())
                        .unwrap_or("unknown");
                    println!("  ✓ Migrated {} ({})", ss_entry.label(), entry_type);
                }
                Err(e) => {
                    eprintln!("  ✗ Skipped {}/{}: {}", folder_name, key, e);
                }
            }
        }
    }

    Ok(count)
}
