//! Headless TUI demo — renders 4 snapshots to stdout.

use ferrovault::tui::{snapshot, EntryView, UiState};

fn base_entries() -> Vec<EntryView> {
    vec![
        EntryView {
            name: "github".into(),
            username: "alice@example.com".into(),
            password: "gh_pat_ABCDEF123456".into(),
            url: Some("https://github.com".into()),
            notes: None,
            totp_secret: None,
        },
        EntryView {
            name: "gitlab".into(),
            username: "alice@example.com".into(),
            password: "glpat-XYZ987654321".into(),
            url: Some("https://gitlab.com".into()),
            notes: Some("Work account".into()),
            totp_secret: None,
        },
        EntryView {
            name: "aws".into(),
            username: "alice".into(),
            password: "Aws$ecure!2024".into(),
            url: Some("https://console.aws.amazon.com".into()),
            notes: Some("prod account — use MFA".into()),
            totp_secret: None,
        },
        EntryView {
            name: "email".into(),
            username: "alice@example.com".into(),
            password: "M@ilP@ss#99".into(),
            url: Some("https://mail.example.com".into()),
            notes: None,
            totp_secret: None,
        },
        EntryView {
            name: "server".into(),
            username: "root".into(),
            password: "srv-s3cret-key-2024".into(),
            url: Some("ssh://prod.example.com:22".into()),
            notes: Some("SSH keypair in ~/.ssh/id_ed25519".into()),
            totp_secret: None,
        },
    ]
}

fn main() {
    // ── Screen 1: Empty vault ──────────────────────────────────────────────
    let st1 = UiState {
        vault_path: "~/.ferrovault/vault.pvlt".into(),
        entries: Vec::new(),
        query: String::new(),
        selected: 0,
        revealed: false,
        now: 1700000000,
        status: "Ready".into(),
    };
    println!("=== Screen 1: Empty vault ===");
    print!("{}", snapshot(&st1, 96, 30));
    println!();

    // ── Screen 2: 5 entries, masked ───────────────────────────────────────
    let st2 = UiState {
        vault_path: "~/.ferrovault/vault.pvlt".into(),
        entries: base_entries(),
        query: String::new(),
        selected: 1, // gitlab selected
        revealed: false,
        now: 1700000000,
        status: "Ready".into(),
    };
    println!("=== Screen 2: 5 entries, masked ===");
    print!("{}", snapshot(&st2, 96, 30));
    println!();

    // ── Screen 3: revealed + TOTP ─────────────────────────────────────────
    let mut entries3 = base_entries();
    entries3[1].totp_secret = Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into());

    let st3 = UiState {
        vault_path: "~/.ferrovault/vault.pvlt".into(),
        entries: entries3,
        query: String::new(),
        selected: 1, // gitlab
        revealed: true,
        now: 1700000000,
        status: "Password revealed".into(),
    };
    println!("=== Screen 3: revealed + TOTP ===");
    print!("{}", snapshot(&st3, 96, 30));
    println!();

    // ── Screen 4: search 'git' ────────────────────────────────────────────
    let st4 = UiState {
        vault_path: "~/.ferrovault/vault.pvlt".into(),
        entries: base_entries(),
        query: "git".into(),
        selected: 0,
        revealed: false,
        now: 1700000000,
        status: "Search: git".into(),
    };
    println!("=== Screen 4: search 'git' ===");
    print!("{}", snapshot(&st4, 96, 30));
    println!();
}
