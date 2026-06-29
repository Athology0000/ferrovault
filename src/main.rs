//! Thin binary: parse args, prompt for secrets, dispatch, render, map errors.

use clap::Parser;
use ferrovault::cli::{Cli, Command};
use ferrovault::commands::{self, default_vault_path, exit_code};
use ferrovault::model::Entry;
use ferrovault::vault::VaultStore;
use ferrovault::{Error, Result};
use zeroize::Zeroizing;

fn prompt_master() -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        rpassword::prompt_password("Master password: ").map_err(Error::Io)?,
    ))
}

fn prompt_new_master() -> Result<Zeroizing<String>> {
    let a = Zeroizing::new(rpassword::prompt_password("New master password: ").map_err(Error::Io)?);
    let b = Zeroizing::new(rpassword::prompt_password("Confirm master password: ").map_err(Error::Io)?);
    if a.as_str() != b.as_str() {
        eprintln!("Passwords do not match.");
        std::process::exit(2);
    }
    Ok(a)
}

fn read_line(prompt: &str) -> String {
    use std::io::Write;
    eprint!("{prompt}");
    let _ = std::io::stderr().flush();
    let mut s = String::new();
    let _ = std::io::stdin().read_line(&mut s);
    s.trim().to_string()
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let path = cli.vault.clone().unwrap_or_else(default_vault_path);
    let store = VaultStore::new(path);

    match cli.command {
        Command::Init => {
            let master = prompt_new_master()?;
            commands::cmd_init(&store, master.as_bytes())?;
            eprintln!("Vault created at {}", store.path().display());
        }
        Command::Add { name, generate, totp } => {
            let master = prompt_master()?;
            let username = read_line(&format!("Username for {name}: "));
            let password: Zeroizing<String> = if generate {
                ferrovault::generator::generate(&ferrovault::generator::GenOptions {
                    length: 20,
                    symbols: true,
                })?
            } else {
                Zeroizing::new(
                    rpassword::prompt_password(format!("Password for {name} (hidden): "))
                        .map_err(Error::Io)?,
                )
            };
            let url = read_line("URL (optional): ");
            let notes = read_line("Notes (optional): ");
            let now = commands::now_rfc3339();
            let entry = Entry {
                username,
                password: password.to_string(),
                url: if url.is_empty() { None } else { Some(url) },
                notes: if notes.is_empty() { None } else { Some(notes) },
                totp,
                created: now.clone(),
                updated: now,
            };
            commands::cmd_add(&store, master.as_bytes(), &name, entry)?;
            eprintln!("Added entry: {name}");
        }
        Command::Get { name, copy, timeout: _timeout } => {
            let master = prompt_master()?;
            let entry = commands::cmd_get(&store, master.as_bytes(), &name)?;
            if copy {
                unimplemented!("copy — implemented in Task 8")
            } else {
                println!("username  {}", entry.username);
                println!("password  {}", entry.password);
                if let Some(u) = &entry.url {
                    println!("url       {u}");
                }
                if let Some(n) = &entry.notes {
                    println!("notes     {n}");
                }
            }
        }
        Command::List => {
            let master = prompt_master()?;
            for name in commands::cmd_list(&store, master.as_bytes())? {
                println!("{name}");
            }
        }
        Command::Delete { name } => {
            let master = prompt_master()?;
            commands::cmd_delete(&store, master.as_bytes(), &name)?;
            eprintln!("Deleted entry: {name}");
        }
        Command::Gen { length, no_symbols } => {
            let pw = ferrovault::generator::generate(&ferrovault::generator::GenOptions {
                length,
                symbols: !no_symbols,
            })?;
            println!("{}", pw.as_str());
        }
        Command::ChangePassword => {
            let old = prompt_master()?;
            let new = prompt_new_master()?;
            commands::cmd_change_password(&store, old.as_bytes(), new.as_bytes())?;
            eprintln!("Master password changed.");
        }
        Command::Totp { .. } => unimplemented!("totp — Task 9"),
        Command::Check { .. } => unimplemented!("check — Task 11"),
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(exit_code(&e));
    }
}
