//! Copy a secret to the clipboard, then wipe it after a timeout.

use crate::{Error, Result};
use std::time::Duration;

pub fn copy_with_clear(secret: &str, timeout_secs: u64) -> Result<()> {
    let mut cb = arboard::Clipboard::new().map_err(|e| Error::Clipboard(e.to_string()))?;
    cb.set_text(secret.to_string())
        .map_err(|e| Error::Clipboard(e.to_string()))?;
    if timeout_secs > 0 {
        std::thread::sleep(Duration::from_secs(timeout_secs));
        // Best-effort wipe; ignore failure (clipboard may have changed).
        let _ = cb.set_text(String::new());
    }
    Ok(())
}
