//! ferrovault — encrypted command-line password manager (library core).

pub mod cli;
pub mod clipboard;
pub mod commands;
pub mod crypto;
pub mod format;
pub mod generator;
pub mod model;
pub mod totp;
pub mod vault;

use std::path::PathBuf;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("no vault found at {0}")]
    VaultNotFound(PathBuf),
    #[error("a vault already exists at {0}")]
    VaultExists(PathBuf),
    #[error("wrong master password or corrupt vault")]
    WrongPasswordOrCorrupt,
    #[error("malformed vault file: {0}")]
    BadFormat(&'static str),
    #[error("no entry named '{0}'")]
    EntryNotFound(String),
    #[error("an entry named '{0}' already exists")]
    EntryExists(String),
    #[error("vault is locked by another process")]
    Locked,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("clipboard error: {0}")]
    Clipboard(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("invalid TOTP secret")]
    Totp,
    #[error("password too short (minimum {0})")]
    TooShort(usize),
    #[error("cryptography error")]
    Crypto,
}

pub type Result<T> = std::result::Result<T, Error>;
