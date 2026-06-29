//! Snapshot tests for the TUI rendering.

use ferrovault::tui::{snapshot, EntryView, UiState};

fn make_state(entries: Vec<EntryView>, selected: usize, revealed: bool, query: &str) -> UiState {
    UiState {
        vault_path: "~/.ferrovault/vault.pvlt".into(),
        entries,
        query: query.into(),
        selected,
        revealed,
        now: 1700000000,
        status: "Ready".into(),
    }
}

#[test]
fn snapshot_non_empty_contains_entry_name_and_title() {
    let st = make_state(
        vec![EntryView {
            name: "mygithub".into(),
            username: "testuser".into(),
            password: "hunter2".into(),
            url: None,
            notes: None,
            totp_secret: None,
        }],
        0,
        false,
        "",
    );
    let out = snapshot(&st, 96, 30);
    assert!(!out.is_empty(), "snapshot must produce non-empty output");
    assert!(
        out.contains("mygithub"),
        "snapshot must contain the entry name 'mygithub'"
    );
    assert!(
        out.to_lowercase().contains("ferrovault"),
        "snapshot must contain the app title 'ferrovault'"
    );
}

#[test]
fn masked_vs_revealed_differ() {
    let make = |revealed: bool| {
        make_state(
            vec![EntryView {
                name: "secret-entry".into(),
                username: "user".into(),
                password: "s3cr3tP@ss".into(),
                url: None,
                notes: None,
                totp_secret: None,
            }],
            0,
            revealed,
            "",
        )
    };

    let masked = snapshot(&make(false), 96, 30);
    assert!(
        !masked.contains("s3cr3tP@ss"),
        "masked snapshot must NOT contain the plaintext password"
    );

    let revealed = snapshot(&make(true), 96, 30);
    assert!(
        revealed.contains("s3cr3tP@ss"),
        "revealed snapshot MUST contain the plaintext password"
    );
}
