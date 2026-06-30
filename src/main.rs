//! Thin binary: parse args, prompt for secrets, dispatch, render, map errors.

use clap::Parser;
use ferrovault::cli::{Cli, Command, ConfigAction};
use ferrovault::commands::{self, default_vault_path, exit_code};
use ferrovault::config::{Config, UiMode};
use ferrovault::model::Entry;
use ferrovault::sync::HttpRemote;
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
    let cfg = Config::load(&Config::default_path()).unwrap_or_default();
    let path = cli.vault.clone().unwrap_or_else(default_vault_path);

    // Load keyfile bytes once; all stores for this invocation share the same bytes.
    let keyfile_bytes: Option<Vec<u8>> = if let Some(ref kf_path) = cfg.keyfile {
        match std::fs::read(kf_path) {
            Ok(b) => Some(b),
            Err(e) => {
                eprintln!("error: cannot read keyfile '{kf_path}': {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let store = VaultStore::new(path)
        .with_scramble(cfg.scramble)
        .with_keyfile(keyfile_bytes.clone());

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
                    let tui_store = VaultStore::new(default_vault_path())
                        .with_scramble(cfg.scramble)
                        .with_keyfile(keyfile_bytes.clone());
                    ferrovault::tui::run(&tui_store, master.as_bytes())?;
                }
            }
        }
        Command::Sync => {
            let remote_url = match cfg.remote.as_deref() {
                Some(u) => u.to_string(),
                None => {
                    eprintln!("error: no remote configured — run `ferrovault config remote <url>`");
                    std::process::exit(1);
                }
            };
            if cfg.keyfile.is_none() {
                eprintln!(
                    "WARNING: syncing to a remote with no keyfile — the remote file's security \
                     rests entirely on your master password. Set one with \
                     `ferrovault config keyfile <path>` (see README)."
                );
            }
            let remote = HttpRemote {
                url: remote_url,
                token: cfg.remote_token.clone(),
            };
            let master = prompt_master()?;
            let report = commands::cmd_sync(&store, master.as_bytes(), &remote)?;
            eprintln!(
                "synced: {} entries ({} added, {} updated); pushed to remote",
                report.total, report.added, report.updated
            );
        }
        Command::Keygen { length } => {
            let key = ferrovault::generator::generate(&ferrovault::generator::GenOptions {
                length,
                symbols: false,
            })?;
            println!("{}", key.as_str());
            eprintln!(
                "Save this as a keyfile and set it on each device with `ferrovault config keyfile <path>`. Back it up — losing it means losing the vault."
            );
        }
        Command::Config { action } => match action {
            ConfigAction::Show => {
                println!("ui           {}", cfg.ui.as_str());
                println!("scramble     {}", if cfg.scramble { "on" } else { "off" });
                println!(
                    "keyfile      {}",
                    cfg.keyfile.as_deref().unwrap_or("(none)")
                );
                println!("remote       {}", cfg.remote.as_deref().unwrap_or("(none)"));
                println!(
                    "remote_token {}",
                    if cfg.remote_token.is_some() {
                        "(set)"
                    } else {
                        "(none)"
                    }
                );
            }
            ConfigAction::Ui { mode } => {
                let ui_mode = UiMode::parse(&mode)?;
                let mut c = Config::load(&Config::default_path()).unwrap_or_default();
                c.ui = ui_mode;
                c.save(&Config::default_path())?;
                eprintln!("UI mode set to {}", c.ui.as_str());
            }
            ConfigAction::Scramble { state } => {
                let on = matches!(
                    state.trim().to_lowercase().as_str(),
                    "on" | "true" | "yes" | "1"
                );
                let mut c = Config::load(&Config::default_path()).unwrap_or_default();
                c.scramble = on;
                c.save(&Config::default_path())?;
                eprintln!(
                    "Vault scrambling {} (obfuscation only). Re-save the vault to apply (any edit or change-password).",
                    if on { "ENABLED" } else { "disabled" }
                );
            }
            ConfigAction::Keyfile { path } => {
                let mut c = Config::load(&Config::default_path()).unwrap_or_default();
                c.keyfile = if path.trim().to_lowercase() == "none" {
                    None
                } else {
                    Some(path.clone())
                };
                c.save(&Config::default_path())?;
                match &c.keyfile {
                    Some(p) => eprintln!("Keyfile set to '{p}'."),
                    None => eprintln!("Keyfile cleared."),
                }
            }
            ConfigAction::Remote { url } => {
                let mut c = Config::load(&Config::default_path()).unwrap_or_default();
                c.remote = if url.trim().to_lowercase() == "none" {
                    None
                } else {
                    Some(url.clone())
                };
                c.save(&Config::default_path())?;
                match &c.remote {
                    Some(u) => eprintln!("Remote set to '{u}'."),
                    None => eprintln!("Remote cleared."),
                }
            }
            ConfigAction::RemoteToken { token } => {
                let mut c = Config::load(&Config::default_path()).unwrap_or_default();
                c.remote_token = if token.trim().to_lowercase() == "none" {
                    None
                } else {
                    Some(token.clone())
                };
                c.save(&Config::default_path())?;
                match &c.remote_token {
                    Some(_) => eprintln!("Remote token set."),
                    None => eprintln!("Remote token cleared."),
                }
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
