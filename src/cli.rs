//! Command-line interface definition (clap derive).

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "ferrovault", about = "Encrypted command-line password manager")]
pub struct Cli {
    /// Path to the vault file (overrides $PV_VAULT and the default).
    #[arg(long, global = true, env = "PV_VAULT")]
    pub vault: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Create a new empty vault.
    Init,
    /// Add a new entry.
    Add {
        name: String,
        /// Generate a random password instead of prompting.
        #[arg(short, long)]
        generate: bool,
        /// Attach a base32 TOTP secret.
        #[arg(long)]
        totp: Option<String>,
    },
    /// Show one entry. `--copy` copies the password to the clipboard.
    Get {
        name: String,
        #[arg(long)]
        copy: bool,
        #[arg(long, default_value_t = 15)]
        timeout: u64,
    },
    /// List entry names.
    List,
    /// Delete an entry.
    Delete { name: String },
    /// Generate a strong password (no vault needed).
    Gen {
        #[arg(default_value_t = 20)]
        length: usize,
        #[arg(long)]
        no_symbols: bool,
    },
    /// Rotate the master password.
    ChangePassword,
    /// Print the current TOTP code for an entry.
    Totp { name: String },
    /// Check a password against Have I Been Pwned (k-anonymity).
    Check { name: Option<String> },
    /// Local-only vault health report: entry count, 2FA coverage, weak/reused
    /// passwords. Computed entirely on your machine — never sent anywhere.
    Stats,
    /// Launch the interactive UI (TUI by default).
    Ui {
        /// Force the graphical desktop UI.
        #[arg(long)]
        gui: bool,
        /// Force the terminal UI.
        #[arg(long)]
        tui: bool,
    },
    /// Manage persistent configuration.
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Encode text into a mixture of CJK/Cyrillic/Arabic glyphs.
    ///
    /// A reversible LOCAL encoding (like base64 with an exotic alphabet) — NOT
    /// encryption and not secret. Prompts hidden if no text is given.
    Encode { text: Option<String> },
    /// Decode ferrovault-encoded glyphs back to the original text.
    Decode { text: String },
    /// One-way visual fingerprint of text in exotic glyphs (reveals nothing).
    Fingerprint { text: Option<String> },
}

#[derive(clap::Subcommand)]
pub enum ConfigAction {
    /// Show current configuration.
    Show,
    /// Set the default UI mode (tui or gui).
    Ui { mode: String },
}
