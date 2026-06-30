//! Thin binary: parse args, prompt for secrets, dispatch, render, map errors.

use clap::Parser;
use ferrovault::cli::{Cli, Command, ConfigAction};
use ferrovault::commands::{self, default_vault_path, exit_code};
use ferrovault::config::{Config, UiMode};
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
    let b =
        Zeroizing::new(rpassword::prompt_password("Confirm master password: ").map_err(Error::Io)?);
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
        Command::Add {
            name,
            generate,
            totp,
        } => {
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
        Command::Get {
            name,
            copy,
            timeout,
        } => {
            let master = prompt_master()?;
            let entry = commands::cmd_get(&store, master.as_bytes(), &name)?;
            if copy {
                ferrovault::clipboard::copy_with_clear(&entry.password, timeout)?;
                if timeout > 0 {
                    eprintln!("Password copied; clipboard clears in {timeout}s.");
                } else {
                    eprintln!("Password copied to clipboard (no auto-clear).");
                }
            } else {
                println!("username  {}", entry.username);
                println!("password  {}", entry.password);
                if let Some(u) = &entry.url {
                    println!("url       {u}");
                }
                if let Some(n) = &entry.notes {
                    println!("notes     {n}");
                }
                println!(
                    "fingerprint  {}",
                    ferrovault::script_codec::fingerprint(&entry.password)
                );
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
        Command::Totp { name } => {
            let master = prompt_master()?;
            let (code, remaining) = commands::cmd_totp(&store, master.as_bytes(), &name)?;
            println!("{code}");
            eprintln!("Valid for {remaining}s");
        }
        Command::Check { name } => {
            let password: Zeroizing<String> = if let Some(entry_name) = name {
                let master = prompt_master()?;
                let entry = commands::cmd_get(&store, master.as_bytes(), &entry_name)?;
                Zeroizing::new(entry.password)
            } else {
                Zeroizing::new(
                    rpassword::prompt_password("Password to check: ").map_err(Error::Io)?,
                )
            };
            match commands::cmd_check(password.as_str()) {
                Ok(count) if count > 0 => {
                    eprintln!(
                        "WARNING: this password has appeared {count} time(s) in known data breaches. Change it now."
                    );
                }
                Ok(_) => {
                    println!("not found in known breaches.");
                }
                Err(Error::Network(msg)) => {
                    eprintln!("warning: HIBP check failed (network): {msg}");
                }
                Err(e) => return Err(e),
            }
        }
        Command::Stats => {
            let master = prompt_master()?;
            let s = commands::cmd_stats(&store, master.as_bytes())?;
            let pct = |n: usize| {
                if s.total > 0 {
                    n as f64 * 100.0 / s.total as f64
                } else {
                    0.0
                }
            };
            println!("entries          {}", s.total);
            println!(
                "with 2FA (TOTP)  {} ({:.0}%)",
                s.with_totp,
                pct(s.with_totp)
            );
            println!("with URL         {} ({:.0}%)", s.with_url, pct(s.with_url));
            println!("avg length       {:.1}", s.avg_len);
            println!("weak passwords   {}", s.weak);
            println!(
                "reused passwords {} ({} entries share a password)",
                s.reused_passwords, s.reused_entries
            );
            eprintln!("(computed locally — nothing was sent anywhere)");
        }
        Command::Ui { gui, tui } => {
            let mode = if gui {
                UiMode::Gui
            } else if tui {
                UiMode::Tui
            } else {
                Config::load(&Config::default_path()).unwrap_or_default().ui
            };
            match mode {
                UiMode::Gui => {
                    let path = cli
                        .vault
                        .clone()
                        .unwrap_or_else(ferrovault::commands::default_vault_path);
                    ferrovault::gui::run(path)?;
                }
                UiMode::Tui => {
                    let master = prompt_master()?;
                    let tui_store = VaultStore::new(default_vault_path());
                    ferrovault::tui::run(&tui_store, master.as_bytes())?;
                }
            }
        }
        Command::Config { action } => match action {
            ConfigAction::Show => {
                let cfg = Config::load(&Config::default_path()).unwrap_or_default();
                println!("{}", cfg.ui.as_str());
            }
            ConfigAction::Ui { mode } => {
                let ui_mode = UiMode::parse(&mode)?;
                let mut cfg = Config::load(&Config::default_path()).unwrap_or_default();
                cfg.ui = ui_mode;
                cfg.save(&Config::default_path())?;
                eprintln!("UI mode set to {}", cfg.ui.as_str());
            }
        },
        Command::Encode { text } => {
            let input = match text {
                Some(t) => Zeroizing::new(t),
                None => Zeroizing::new(
                    rpassword::prompt_password("Text to encode (hidden): ").map_err(Error::Io)?,
                ),
            };
            eprintln!("(this is a reversible encoding, not encryption — anyone can decode it)");
            println!("{}", ferrovault::script_codec::encode(&input));
        }
        Command::Decode { text } => {
            println!("{}", ferrovault::script_codec::decode(&text)?);
        }
        Command::Fingerprint { text } => {
            let input = match text {
                Some(t) => Zeroizing::new(t),
                None => Zeroizing::new(
                    rpassword::prompt_password("Text to fingerprint (hidden): ")
                        .map_err(Error::Io)?,
                ),
            };
            println!("{}", ferrovault::script_codec::fingerprint(&input));
        }
    }
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(exit_code(&e));
    }
}
