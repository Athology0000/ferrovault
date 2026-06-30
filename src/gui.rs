//! egui desktop GUI for ferrovault.

use crate::model::Vault;
use crate::tui::EntryView;
use crate::vault::VaultStore;
use egui::{Color32, RichText};
use std::path::PathBuf;
use zeroize::Zeroizing;

// ── Catppuccin Mocha palette ─────────────────────────────────────────────────
const BASE: Color32 = Color32::from_rgb(30, 30, 46);
const SURFACE0: Color32 = Color32::from_rgb(49, 50, 68);
const TEXT: Color32 = Color32::from_rgb(205, 214, 244);
const BLUE: Color32 = Color32::from_rgb(137, 180, 250);
const CYAN: Color32 = Color32::from_rgb(137, 220, 235);
const MAUVE: Color32 = Color32::from_rgb(203, 166, 247);
const RED: Color32 = Color32::from_rgb(243, 139, 168);
const GREEN: Color32 = Color32::from_rgb(166, 227, 161);
const MANTLE: Color32 = Color32::from_rgb(24, 24, 37);
const SURFACE1: Color32 = Color32::from_rgb(69, 71, 90);
const OVERLAY: Color32 = Color32::from_rgb(127, 132, 156);
const CARD: Color32 = Color32::from_rgb(36, 37, 54);

pub struct GuiApp {
    store: VaultStore,
    vault_path: String,
    master: Zeroizing<String>,
    locked: bool,
    password_input: String,
    entries: Vec<EntryView>,
    query: String,
    selected: Option<usize>,
    revealed: bool,
    status: String,
    error: String,
    adding: bool,
    add_name: String,
    add_username: String,
    add_password: String,
    add_url: String,
    add_totp: String,
}

impl GuiApp {
    pub fn new(vault_path: PathBuf) -> Self {
        let vault_path_str = vault_path.display().to_string();
        Self {
            store: VaultStore::new(vault_path),
            vault_path: vault_path_str,
            master: Zeroizing::new(String::new()),
            locked: true,
            password_input: String::new(),
            entries: Vec::new(),
            query: String::new(),
            selected: None,
            revealed: false,
            status: String::from("Enter master password to unlock."),
            error: String::new(),
            adding: false,
            add_name: String::new(),
            add_username: String::new(),
            add_password: String::new(),
            add_url: String::new(),
            add_totp: String::new(),
        }
    }

    pub fn demo(
        vault_path: String,
        entries: Vec<EntryView>,
        locked: bool,
        revealed: bool,
        selected: Option<usize>,
    ) -> Self {
        let path = PathBuf::from(&vault_path);
        let status = if locked {
            String::from("Enter master password to unlock.")
        } else {
            String::from("Ready")
        };
        Self {
            store: VaultStore::new(path),
            vault_path,
            master: Zeroizing::new(String::new()),
            locked,
            password_input: String::new(),
            entries,
            query: String::new(),
            selected,
            revealed,
            status,
            error: String::new(),
            adding: false,
            add_name: String::new(),
            add_username: String::new(),
            add_password: String::new(),
            add_url: String::new(),
            add_totp: String::new(),
        }
    }

    fn now(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn filtered(&self) -> Vec<usize> {
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

    fn unlock(&mut self) {
        match self.store.open(self.password_input.as_bytes()) {
            Ok((vault, _)) => {
                self.master = Zeroizing::new(self.password_input.clone());
                self.refresh_entries_from(vault);
                self.locked = false;
                self.password_input.clear();
                self.error.clear();
                self.status = String::from("Vault unlocked.");
                if !self.entries.is_empty() {
                    self.selected = Some(0);
                }
            }
            Err(e) => {
                self.error = format!("{e}");
            }
        }
    }

    fn refresh_entries_from(&mut self, vault: Vault) {
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
        self.entries = entries;
    }

    fn apply_theme(ctx: &egui::Context) {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = BASE;
        visuals.window_fill = BASE;
        visuals.selection.bg_fill = SURFACE0;
        visuals.hyperlink_color = BLUE;
        visuals.widgets.noninteractive.bg_fill = SURFACE0;
        visuals.widgets.inactive.bg_fill = SURFACE0;
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(69, 71, 90);
        visuals.widgets.active.bg_fill = Color32::from_rgb(88, 91, 112);
        visuals.widgets.noninteractive.fg_stroke.color = TEXT;
        visuals.widgets.inactive.fg_stroke.color = TEXT;
        visuals.override_text_color = Some(TEXT);
        visuals.selection.bg_fill = SURFACE1;
        let rounding = egui::Rounding::same(6.0);
        visuals.widgets.noninteractive.rounding = rounding;
        visuals.widgets.inactive.rounding = rounding;
        visuals.widgets.hovered.rounding = rounding;
        visuals.widgets.active.rounding = rounding;
        ctx.set_visuals(visuals);
        ctx.style_mut(|s| {
            s.spacing.item_spacing = egui::vec2(8.0, 9.0);
            s.spacing.button_padding = egui::vec2(12.0, 7.0);
        });
    }

    fn build_ui(&mut self, ctx: &egui::Context) {
        if self.locked {
            self.build_lock_screen(ctx);
        } else {
            self.build_main_ui(ctx);
        }
    }

    fn build_lock_screen(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(160.0);
                ui.label(RichText::new("ferrovault").size(30.0).color(CYAN).strong());
                ui.add_space(8.0);
                ui.label(
                    RichText::new("Encrypted password manager")
                        .size(14.0)
                        .color(Color32::from_rgb(108, 112, 134)),
                );
                ui.add_space(24.0);

                let pw_resp = ui.add(
                    egui::TextEdit::singleline(&mut self.password_input)
                        .password(true)
                        .hint_text("Master password")
                        .desired_width(280.0),
                );
                let enter = pw_resp.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter));

                ui.add_space(12.0);
                let unlock_btn = ui.add_sized(
                    [280.0, 36.0],
                    egui::Button::new(RichText::new("Unlock").color(BASE)).fill(CYAN),
                );
                if enter || unlock_btn.clicked() {
                    self.unlock();
                }

                if !self.error.is_empty() {
                    ui.add_space(12.0);
                    ui.label(RichText::new(&self.error).color(RED));
                }
            });
        });
    }

    fn build_main_ui(&mut self, ctx: &egui::Context) {
        let filtered = self.filtered();
        let entry_count = filtered.len();

        // ── Top bar ──────────────────────────────────────────────────────────
        egui::TopBottomPanel::top("top_bar")
            .frame(
                egui::Frame::default()
                    .fill(MANTLE)
                    .inner_margin(egui::Margin::symmetric(16.0, 11.0)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("ferrovault").color(CYAN).strong().size(18.0));
                    ui.add_space(12.0);
                    ui.label(RichText::new(&self.vault_path).size(12.0).color(OVERLAY));
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(format!("· {entry_count} entries"))
                            .size(12.0)
                            .color(OVERLAY),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut self.query)
                                .hint_text("Search…")
                                .desired_width(220.0),
                        );
                        if resp.changed() {
                            self.selected = self.filtered().into_iter().next();
                        }
                    });
                });
            });

        // ── Status bar ───────────────────────────────────────────────────────
        let status_snapshot = self.status.clone();
        egui::TopBottomPanel::bottom("status_bar")
            .frame(
                egui::Frame::default()
                    .fill(MANTLE)
                    .inner_margin(egui::Margin::symmetric(16.0, 6.0)),
            )
            .show(ctx, |ui| {
                if !status_snapshot.is_empty() {
                    let col = if status_snapshot.starts_with("Error") {
                        RED
                    } else {
                        OVERLAY
                    };
                    ui.label(RichText::new(&status_snapshot).color(col).size(12.0));
                }
            });

        // ── Left sidebar ─────────────────────────────────────────────────────
        egui::SidePanel::left("entries_list")
            .default_width(260.0)
            .frame(
                egui::Frame::default()
                    .fill(BASE)
                    .inner_margin(egui::Margin::same(10.0)),
            )
            .show(ctx, |ui| {
                ui.add_space(2.0);
                ui.label(RichText::new("ENTRIES").size(11.0).color(OVERLAY).strong());
                ui.add_space(6.0);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for &idx in &filtered {
                        let e = &self.entries[idx];
                        let is_sel = self.selected == Some(idx);
                        let resp = ui.add_sized(
                            [ui.available_width(), 30.0],
                            egui::SelectableLabel::new(is_sel, RichText::new(&e.name).strong()),
                        );
                        if resp.clicked() {
                            self.selected = Some(idx);
                        }
                    }
                });
            });

        // ── Central panel ────────────────────────────────────────────────────
        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(BASE)
                    .inner_margin(egui::Margin::same(20.0)),
            )
            .show(ctx, |ui| {
                // Toolbar: selected-entry title (left) + add/cancel button (right).
                let title = self
                    .selected
                    .and_then(|i| self.entries.get(i))
                    .map(|e| e.name.clone());
                ui.horizontal(|ui| {
                    if self.adding {
                        ui.label(RichText::new("New entry").size(20.0).color(TEXT).strong());
                    } else if let Some(ref t) = title {
                        ui.label(RichText::new(t).size(20.0).color(TEXT).strong());
                    } else {
                        ui.label(RichText::new("ferrovault").size(20.0).color(OVERLAY));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let (lbl, col) = if self.adding {
                            ("✕  Cancel", RED)
                        } else {
                            ("+  Add entry", MAUVE)
                        };
                        if ui
                            .add(egui::Button::new(RichText::new(lbl).color(col)))
                            .clicked()
                        {
                            self.adding = !self.adding;
                            if !self.adding {
                                self.add_name.clear();
                                self.add_username.clear();
                                self.add_password.clear();
                                self.add_url.clear();
                                self.add_totp.clear();
                            }
                        }
                    });
                });
                ui.add_space(14.0);

                if self.adding {
                    egui::Frame::default()
                        .fill(CARD)
                        .rounding(10.0)
                        .inner_margin(egui::Margin::same(18.0))
                        .show(ui, |ui| {
                            self.show_add_form(ui);
                        });
                    return;
                }

                let sel_idx = match self.selected {
                    Some(i) if self.entries.get(i).is_some() => i,
                    _ => {
                        ui.label(RichText::new("Select an entry from the list.").color(OVERLAY));
                        return;
                    }
                };

                let now = self.now();
                let name = self.entries[sel_idx].name.clone();
                let username = self.entries[sel_idx].username.clone();
                let password = self.entries[sel_idx].password.clone();
                let url = self.entries[sel_idx].url.clone();
                let notes = self.entries[sel_idx].notes.clone();
                let totp_secret = self.entries[sel_idx].totp_secret.clone();

                // Detail card.
                egui::Frame::default()
                    .fill(CARD)
                    .rounding(10.0)
                    .inner_margin(egui::Margin::same(20.0))
                    .show(ui, |ui| {
                        egui::Grid::new("detail_grid")
                            .num_columns(2)
                            .spacing([16.0, 12.0])
                            .min_col_width(92.0)
                            .show(ui, |ui| {
                                ui.label(RichText::new("Username").color(CYAN));
                                ui.label(RichText::new(&username).color(TEXT));
                                ui.end_row();

                                ui.label(RichText::new("Password").color(CYAN));
                                if self.revealed {
                                    ui.label(RichText::new(&password).color(GREEN).monospace());
                                } else {
                                    ui.label(
                                        RichText::new("•".repeat(password.len().min(24)))
                                            .color(OVERLAY)
                                            .monospace(),
                                    );
                                }
                                ui.end_row();

                                if let Some(ref u) = url {
                                    ui.label(RichText::new("URL").color(CYAN));
                                    ui.hyperlink(u);
                                    ui.end_row();
                                }
                                if let Some(ref n) = notes {
                                    ui.label(RichText::new("Notes").color(CYAN));
                                    ui.label(RichText::new(n).color(TEXT));
                                    ui.end_row();
                                }
                                if let Some(ref secret) = totp_secret {
                                    ui.label(RichText::new("TOTP").color(CYAN));
                                    match crate::totp::current_code(secret, now) {
                                        Ok((code, remaining)) => {
                                            ui.label(
                                                RichText::new(format!("{code}   ({remaining}s)"))
                                                    .color(MAUVE)
                                                    .monospace()
                                                    .size(15.0),
                                            );
                                        }
                                        Err(_) => {
                                            ui.label(RichText::new("invalid secret").color(RED));
                                        }
                                    }
                                    ui.end_row();
                                }
                            });
                    });

                ui.add_space(16.0);
                ui.horizontal(|ui| {
                    let reveal_label = if self.revealed { "Hide" } else { "Reveal" };
                    if ui.button(reveal_label).clicked() {
                        self.revealed = !self.revealed;
                    }
                    if ui.button("Copy password").clicked() {
                        match crate::clipboard::copy_with_clear(&password, 15) {
                            Ok(_) => self.status = "Password copied (clears in 15s).".into(),
                            Err(e) => self.status = format!("Error: {e}"),
                        }
                    }
                    if ui.button("Copy username").clicked() {
                        match crate::clipboard::copy_with_clear(&username, 0) {
                            Ok(_) => self.status = "Username copied.".into(),
                            Err(e) => self.status = format!("Error: {e}"),
                        }
                    }
                    if let Some(ref secret) = totp_secret {
                        if ui.button("Copy TOTP").clicked() {
                            match crate::totp::current_code(secret, now) {
                                Ok((code, _)) => {
                                    match crate::clipboard::copy_with_clear(&code, 15) {
                                        Ok(_) => {
                                            self.status = "TOTP copied (clears in 15s).".into()
                                        }
                                        Err(e) => self.status = format!("Error: {e}"),
                                    }
                                }
                                Err(_) => self.status = "Error: invalid TOTP secret.".into(),
                            }
                        }
                    }
                    if ui
                        .add(egui::Button::new(RichText::new("Delete").color(RED)))
                        .clicked()
                    {
                        let del_name = name.clone();
                        let master_bytes = self.master.as_bytes().to_vec();
                        match self.store.update(&master_bytes, |v| {
                            v.entries.remove(&del_name);
                            Ok(())
                        }) {
                            Ok(_) => {
                                if let Ok((vault, _)) = self.store.open(&master_bytes) {
                                    self.refresh_entries_from(vault);
                                }
                                self.selected = if self.entries.is_empty() {
                                    None
                                } else {
                                    Some(0)
                                };
                                self.status = format!("Deleted '{name}'.");
                            }
                            Err(e) => self.status = format!("Error: {e}"),
                        }
                    }
                });
            });
    }

    fn show_add_form(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("add_form")
            .num_columns(2)
            .spacing([8.0, 6.0])
            .show(ui, |ui| {
                ui.label(RichText::new("Name *").color(CYAN));
                ui.text_edit_singleline(&mut self.add_name);
                ui.end_row();

                ui.label(RichText::new("Username").color(CYAN));
                ui.text_edit_singleline(&mut self.add_username);
                ui.end_row();

                ui.label(RichText::new("Password").color(CYAN));
                ui.add(egui::TextEdit::singleline(&mut self.add_password).password(true));
                ui.end_row();

                ui.label(RichText::new("URL").color(CYAN));
                ui.text_edit_singleline(&mut self.add_url);
                ui.end_row();

                ui.label(RichText::new("TOTP secret").color(CYAN));
                ui.text_edit_singleline(&mut self.add_totp);
                ui.end_row();
            });

        ui.add_space(8.0);
        if ui
            .button(RichText::new("Save entry").color(GREEN))
            .clicked()
        {
            let name = self.add_name.trim().to_string();
            if name.is_empty() {
                self.status = "Name cannot be empty.".into();
                return;
            }
            let now = crate::commands::now_rfc3339();
            let url_val = self.add_url.trim().to_string();
            let totp_val = self.add_totp.trim().to_string();
            let entry = crate::model::Entry {
                username: self.add_username.trim().to_string(),
                password: self.add_password.clone(),
                url: if url_val.is_empty() {
                    None
                } else {
                    Some(url_val)
                },
                notes: None,
                totp: if totp_val.is_empty() {
                    None
                } else {
                    Some(totp_val)
                },
                created: now.clone(),
                updated: now,
            };
            let master_bytes = self.master.as_bytes().to_vec();
            let name_clone = name.clone();
            match self.store.update(&master_bytes, move |v| {
                if v.entries.contains_key(&name_clone) {
                    return Err(crate::Error::EntryExists(name_clone.clone()));
                }
                v.entries.insert(name_clone, entry);
                Ok(())
            }) {
                Ok(_) => {
                    if let Ok((vault, _)) = self.store.open(&master_bytes) {
                        self.refresh_entries_from(vault);
                        self.selected = self.entries.iter().position(|e| e.name == name);
                    }
                    self.status = format!("Added '{name}'.");
                    self.adding = false;
                    self.add_name.clear();
                    self.add_username.clear();
                    self.add_password.clear();
                    self.add_url.clear();
                    self.add_totp.clear();
                }
                Err(e) => self.status = format!("Error: {e}"),
            }
        }
    }
}

impl eframe::App for GuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        Self::apply_theme(ctx);
        self.build_ui(ctx);
    }
}

pub fn run(vault_path: PathBuf) -> crate::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1000.0, 640.0])
            .with_title("ferrovault"),
        ..Default::default()
    };
    eframe::run_native(
        "ferrovault",
        options,
        Box::new(|_cc| Ok(Box::new(GuiApp::new(vault_path)))),
    )
    .map_err(|e| crate::Error::Clipboard(format!("gui: {e}")))
}
