//! Ratatui terminal UI for ferrovault.

use crate::vault::VaultStore;
use crate::Result;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

// ──────────────────────────────────────────────────────────────────────────────
// Data types
// ──────────────────────────────────────────────────────────────────────────────

pub struct EntryView {
    pub name: String,
    pub username: String,
    pub password: String,
    pub url: Option<String>,
    pub notes: Option<String>,
    pub totp_secret: Option<String>,
}

pub struct UiState {
    pub vault_path: String,
    pub entries: Vec<EntryView>,
    pub query: String,
    pub selected: usize,
    pub revealed: bool,
    pub now: u64,
    pub status: String,
}

impl UiState {
    /// Indices of entries whose name or username contains `query` (case-insensitive).
    pub fn filtered_indices(&self) -> Vec<usize> {
        if self.query.is_empty() {
            return (0..self.entries.len()).collect();
        }
        let q = self.query.to_lowercase();
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| {
                e.name.to_lowercase().contains(&q) || e.username.to_lowercase().contains(&q)
            })
            .map(|(i, _)| i)
            .collect()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Drawing
// ──────────────────────────────────────────────────────────────────────────────

pub fn draw(f: &mut Frame, st: &UiState) {
    let area = f.area();

    // Outer vertical split: header | body | status | footer
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Min(0),    // body
            Constraint::Length(1), // status
            Constraint::Length(1), // footer
        ])
        .split(area);

    // ── Header ──────────────────────────────────────────────────────────────
    let filtered = st.filtered_indices();
    let count = filtered.len();
    let dim = Style::default().fg(Color::DarkGray);
    let mut header_spans = vec![
        Span::styled(
            "▌ ferrovault ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("│ ", dim),
        Span::styled(st.vault_path.clone(), Style::default().fg(Color::White)),
        Span::styled("  │ ", dim),
        Span::styled(format!("{count} entries"), dim),
    ];
    if !st.query.is_empty() {
        header_spans.push(Span::styled("  │ ", dim));
        header_spans.push(Span::styled(
            format!("search: {}", st.query),
            Style::default().fg(Color::Yellow),
        ));
    }
    let header = Paragraph::new(Line::from(header_spans))
        .block(Block::default().borders(Borders::BOTTOM).border_style(dim));
    f.render_widget(header, outer[0]);

    // ── Body: left list + right detail ──────────────────────────────────────
    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(outer[1]);

    // Left: entry list
    if st.entries.is_empty() {
        let empty = Paragraph::new("\n  No entries yet.\n  Press 'a' to add one.")
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(Span::styled(
                        " Entries ",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )),
            );
        f.render_widget(empty, body[0]);
    } else {
        let items: Vec<ListItem> = filtered
            .iter()
            .enumerate()
            .map(|(vis_idx, &real_idx)| {
                let e = &st.entries[real_idx];
                let is_sel = filtered
                    .get(st.selected.min(filtered.len().saturating_sub(1)))
                    .copied()
                    == Some(real_idx);
                let name_style = if is_sel {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                let user_style = Style::default().fg(Color::DarkGray);
                let _ = vis_idx; // suppressed
                ListItem::new(Line::from(vec![
                    Span::styled(e.name.clone(), name_style),
                    Span::raw("  "),
                    Span::styled(e.username.clone(), user_style),
                ]))
            })
            .collect();

        let mut list_state = ListState::default();
        if !filtered.is_empty() {
            list_state.select(Some(st.selected.min(filtered.len() - 1)));
        }
        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(Style::default().fg(Color::DarkGray))
                    .title(Span::styled(
                        " Entries ",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )),
            )
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▌ ");
        f.render_stateful_widget(list, body[0], &mut list_state);
    }

    // Right: detail pane
    let detail_block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray))
        .padding(ratatui::widgets::Padding::new(1, 1, 1, 0))
        .title(Span::styled(
            " Detail ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
    if st.entries.is_empty() || filtered.is_empty() {
        let detail = Paragraph::new("Select an entry to view details.")
            .style(Style::default().fg(Color::DarkGray))
            .block(detail_block);
        f.render_widget(detail, body[1]);
    } else {
        let sel_idx = filtered[st.selected.min(filtered.len() - 1)];
        let e = &st.entries[sel_idx];
        let password_display = if st.revealed {
            e.password.clone()
        } else {
            "●".repeat(e.password.len().min(20))
        };

        let mut lines: Vec<Line> = vec![
            Line::from(vec![
                Span::styled("  Name:      ", Style::default().fg(Color::Cyan)),
                Span::raw(e.name.clone()),
            ]),
            Line::from(vec![
                Span::styled("  Username:  ", Style::default().fg(Color::Cyan)),
                Span::raw(e.username.clone()),
            ]),
            Line::from(vec![
                Span::styled("  Password:  ", Style::default().fg(Color::Cyan)),
                Span::styled(
                    password_display,
                    if st.revealed {
                        Style::default().fg(Color::Green)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    },
                ),
            ]),
        ];

        if let Some(url) = &e.url {
            lines.push(Line::from(vec![
                Span::styled("  URL:       ", Style::default().fg(Color::Cyan)),
                Span::styled(url.clone(), Style::default().fg(Color::Blue)),
            ]));
        }

        if let Some(notes) = &e.notes {
            lines.push(Line::from(vec![
                Span::styled("  Notes:     ", Style::default().fg(Color::Cyan)),
                Span::raw(notes.clone()),
            ]));
        }

        if let Some(secret) = &e.totp_secret {
            match crate::totp::current_code(secret, st.now) {
                Ok((code, remaining)) => {
                    lines.push(Line::from(vec![
                        Span::styled("  TOTP:      ", Style::default().fg(Color::Cyan)),
                        Span::styled(
                            format!("{}  ({}s remaining)", code, remaining),
                            Style::default().fg(Color::Magenta),
                        ),
                    ]));
                }
                Err(_) => {
                    lines.push(Line::from(vec![
                        Span::styled("  TOTP:      ", Style::default().fg(Color::Cyan)),
                        Span::styled("invalid secret", Style::default().fg(Color::Red)),
                    ]));
                }
            }
        }

        let detail = Paragraph::new(lines)
            .block(detail_block)
            .wrap(Wrap { trim: false });
        f.render_widget(detail, body[1]);
    }

    // ── Status bar ──────────────────────────────────────────────────────────
    let status_style = if st.status.starts_with("Error") || st.status.starts_with("error") {
        Style::default().fg(Color::Red)
    } else {
        Style::default().fg(Color::Green)
    };
    let status = Paragraph::new(format!(" {}", st.status)).style(status_style);
    f.render_widget(status, outer[2]);

    // ── Footer / key hints ───────────────────────────────────────────────────
    let key = |s: &str| {
        Span::styled(
            s.to_string(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    };
    let lbl = |s: &str| Span::styled(s.to_string(), Style::default().fg(Color::DarkGray));
    let footer = Paragraph::new(Line::from(vec![
        lbl(" "),
        key("↑↓"),
        lbl(" move  "),
        key("/"),
        lbl(" search  "),
        key("⏎"),
        lbl(" reveal  "),
        key("c"),
        lbl(" copy  "),
        key("u"),
        lbl(" user  "),
        key("t"),
        lbl(" totp  "),
        key("a"),
        lbl(" add  "),
        key("d"),
        lbl(" del  "),
        key("q"),
        lbl(" quit"),
    ]));
    f.render_widget(footer, outer[3]);
}

// ──────────────────────────────────────────────────────────────────────────────
// Snapshot (headless render for tests / demo)
// ──────────────────────────────────────────────────────────────────────────────

pub fn snapshot(st: &UiState, width: u16, height: u16) -> String {
    let backend = ratatui::backend::TestBackend::new(width, height);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, st)).unwrap();
    let buffer = terminal.backend().buffer().clone();
    let w = buffer.area.width as usize;
    let h = buffer.area.height as usize;
    let mut out = String::new();
    for row in 0..h {
        let line: String = (0..w)
            .map(|col| {
                let cell = &buffer[(col as u16, row as u16)];
                cell.symbol().to_string()
            })
            .collect::<Vec<_>>()
            .join("");
        let trimmed = line.trim_end().to_string();
        out.push_str(&trimmed);
        out.push('\n');
    }
    out
}

// ──────────────────────────────────────────────────────────────────────────────
// Real event loop
// ──────────────────────────────────────────────────────────────────────────────

#[derive(PartialEq)]
enum Mode {
    Normal,
    Searching,
    ConfirmDelete,
}

pub fn run(store: &VaultStore, master: &[u8]) -> Result<()> {
    use crossterm::event::{Event, KeyCode, KeyEvent};
    use crossterm::execute;
    use crossterm::terminal::{
        disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
    };
    use ratatui::backend::CrosstermBackend;
    use std::io::stdout;
    use std::time::Duration;

    // Open vault
    let (vault, _) = store.open(master)?;

    // Build initial entries list
    let mut entries: Vec<EntryView> = vault
        .entries
        .iter()
        .map(|(name, e)| EntryView {
            name: name.clone(),
            username: e.username.clone(),
            password: e.password.clone(),
            url: e.url.clone(),
            notes: e.notes.clone(),
            totp_secret: e.totp.clone(),
        })
        .collect();
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let vault_path = store.path().display().to_string();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut st = UiState {
        vault_path: vault_path.clone(),
        entries,
        query: String::new(),
        selected: 0,
        revealed: false,
        now,
        status: String::from("Ready"),
    };

    let mut mode = Mode::Normal;

    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let restore = || {
        let _ = disable_raw_mode();
        let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
    };

    loop {
        // Refresh now each frame
        st.now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        terminal.draw(|f| draw(f, &st))?;

        if !crossterm::event::poll(Duration::from_millis(200))? {
            continue;
        }

        let event = crossterm::event::read()?;
        let Event::Key(KeyEvent { code, .. }) = event else {
            continue;
        };

        match mode {
            Mode::Normal => {
                let filtered = st.filtered_indices();
                match code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Up | KeyCode::Char('k') if !filtered.is_empty() && st.selected > 0 => {
                        st.selected -= 1;
                    }
                    KeyCode::Down | KeyCode::Char('j')
                        if !filtered.is_empty() && st.selected + 1 < filtered.len() =>
                    {
                        st.selected += 1;
                    }
                    KeyCode::Up | KeyCode::Char('k') | KeyCode::Down | KeyCode::Char('j') => {}
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        st.revealed = !st.revealed;
                    }
                    KeyCode::Char('/') => {
                        mode = Mode::Searching;
                        st.status = format!("Search: {}", st.query);
                    }
                    KeyCode::Char('c') if !filtered.is_empty() => {
                        let sel = filtered[st.selected.min(filtered.len() - 1)];
                        let pw = st.entries[sel].password.clone();
                        match crate::clipboard::copy_with_clear(&pw, 0) {
                            Ok(_) => st.status = "Password copied to clipboard.".into(),
                            Err(e) => st.status = format!("Error: {e}"),
                        }
                    }
                    KeyCode::Char('u') if !filtered.is_empty() => {
                        let sel = filtered[st.selected.min(filtered.len() - 1)];
                        let user = st.entries[sel].username.clone();
                        match crate::clipboard::copy_with_clear(&user, 0) {
                            Ok(_) => st.status = "Username copied to clipboard.".into(),
                            Err(e) => st.status = format!("Error: {e}"),
                        }
                    }
                    KeyCode::Char('t') if !filtered.is_empty() => {
                        let sel = filtered[st.selected.min(filtered.len() - 1)];
                        if let Some(secret) = st.entries[sel].totp_secret.clone() {
                            match crate::totp::current_code(&secret, st.now) {
                                Ok((code, _)) => {
                                    match crate::clipboard::copy_with_clear(&code, 15) {
                                        Ok(_) => st.status = "TOTP copied (clears in 15s).".into(),
                                        Err(e) => st.status = format!("Error: {e}"),
                                    }
                                }
                                Err(_) => st.status = "Error: invalid TOTP secret".into(),
                            }
                        } else {
                            st.status = "No TOTP secret for this entry.".into();
                        }
                    }
                    KeyCode::Char('d') if !filtered.is_empty() => {
                        let sel = filtered[st.selected.min(filtered.len() - 1)];
                        st.status = format!(
                            "Delete '{}'? Press y to confirm, n to cancel.",
                            st.entries[sel].name
                        );
                        mode = Mode::ConfirmDelete;
                    }
                    KeyCode::Char('a') => {
                        st.status = "Adding new entry — follow prompts in terminal.".into();
                        // We need to drop raw mode temporarily to read input
                        terminal.draw(|f| draw(f, &st))?;
                        disable_raw_mode()?;
                        execute!(std::io::stdout(), LeaveAlternateScreen)?;

                        let result = add_entry_interactive(store, master, &mut st);
                        if let Err(e) = result {
                            st.status = format!("Error adding entry: {e}");
                        }

                        enable_raw_mode()?;
                        execute!(std::io::stdout(), EnterAlternateScreen)?;
                        terminal.clear()?;
                        mode = Mode::Normal;
                    }
                    _ => {}
                }
            }
            Mode::Searching => match code {
                KeyCode::Esc => {
                    st.query.clear();
                    st.selected = 0;
                    st.status = "Search cleared.".into();
                    mode = Mode::Normal;
                }
                KeyCode::Backspace => {
                    st.query.pop();
                    st.selected = 0;
                    st.status = format!("Search: {}", st.query);
                }
                KeyCode::Enter => {
                    st.status = format!("Filtered: {} results", st.filtered_indices().len());
                    mode = Mode::Normal;
                }
                KeyCode::Char(c) => {
                    st.query.push(c);
                    st.selected = 0;
                    st.status = format!("Search: {}", st.query);
                }
                _ => {}
            },
            Mode::ConfirmDelete => match code {
                KeyCode::Char('y') => {
                    let filtered = st.filtered_indices();
                    if !filtered.is_empty() {
                        let sel = filtered[st.selected.min(filtered.len() - 1)];
                        let name = st.entries[sel].name.clone();
                        match store.update(master, |v| {
                            v.entries.remove(&name);
                            Ok(())
                        }) {
                            Ok(_) => {
                                st.entries.remove(sel);
                                if st.selected > 0 && st.selected >= st.entries.len() {
                                    st.selected = st.entries.len().saturating_sub(1);
                                }
                                st.status = format!("Deleted '{}'.", name);
                            }
                            Err(e) => st.status = format!("Error: {e}"),
                        }
                    }
                    mode = Mode::Normal;
                }
                KeyCode::Char('n') | KeyCode::Esc => {
                    st.status = "Delete cancelled.".into();
                    mode = Mode::Normal;
                }
                _ => {}
            },
        }
    }

    restore();
    Ok(())
}

fn add_entry_interactive(store: &VaultStore, master: &[u8], st: &mut UiState) -> Result<()> {
    use std::io::Write;

    let read_line = |prompt: &str| -> String {
        eprint!("{prompt}");
        let _ = std::io::stderr().flush();
        let mut s = String::new();
        let _ = std::io::stdin().read_line(&mut s);
        s.trim().to_string()
    };

    eprintln!("--- Add new entry ---");
    let name = read_line("Name: ");
    if name.is_empty() {
        st.status = "Add cancelled (empty name).".into();
        return Ok(());
    }
    let username = read_line("Username: ");
    let password = rpassword::prompt_password("Password (hidden): ").map_err(crate::Error::Io)?;
    let url = read_line("URL (optional): ");
    let notes = read_line("Notes (optional): ");
    let totp = read_line("TOTP secret (optional): ");

    let now = crate::commands::now_rfc3339();
    let entry = crate::model::Entry {
        username: username.clone(),
        password: password.clone(),
        url: if url.is_empty() {
            None
        } else {
            Some(url.clone())
        },
        notes: if notes.is_empty() {
            None
        } else {
            Some(notes.clone())
        },
        totp: if totp.is_empty() {
            None
        } else {
            Some(totp.clone())
        },
        created: now.clone(),
        updated: now,
    };

    let name_clone = name.clone();
    store.update(master, move |v| {
        if v.entries.contains_key(&name_clone) {
            return Err(crate::Error::EntryExists(name_clone.clone()));
        }
        v.entries.insert(name_clone, entry);
        Ok(())
    })?;

    st.entries.push(EntryView {
        name: name.clone(),
        username,
        password,
        url: if url.is_empty() { None } else { Some(url) },
        notes: if notes.is_empty() { None } else { Some(notes) },
        totp_secret: if totp.is_empty() { None } else { Some(totp) },
    });
    st.entries.sort_by(|a, b| a.name.cmp(&b.name));
    st.status = format!("Added '{}'.", name);
    Ok(())
}
