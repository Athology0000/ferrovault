//! Persistent user settings (which UI launches by default).

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UiMode {
    #[default]
    Tui,
    Gui,
}

impl UiMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            UiMode::Tui => "tui",
            UiMode::Gui => "gui",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_lowercase().as_str() {
            "tui" | "terminal" => Ok(UiMode::Tui),
            "gui" | "app" | "desktop" => Ok(UiMode::Gui),
            _ => Err(Error::BadFormat("ui mode must be 'tui' or 'gui'")),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub ui: UiMode,
    /// Obfuscate the vault file's bytes at rest (reversible; not encryption).
    #[serde(default)]
    pub scramble: bool,
}

impl Config {
    pub fn default_path() -> PathBuf {
        let base = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        base.join(".ferrovault").join("config.toml")
    }
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str(&s).map_err(|_| Error::BadFormat("invalid config.toml")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e.into()),
        }
    }
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let s = toml::to_string_pretty(self).map_err(|_| Error::Serialize("config toml"))?;
        std::fs::write(path, s)?;
        Ok(())
    }
}
