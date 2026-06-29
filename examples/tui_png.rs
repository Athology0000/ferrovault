//! Dev tool: render the ferrovault TUI to PNG images for visual review.
//!
//! Run: `cargo run --example tui_png`
//! Outputs PNGs under `screenshots/`. Loads a monospace font from the system
//! (Cascadia Mono / Consolas), or set FERROVAULT_FONT to a .ttf path.

use ab_glyph::{point, Font, FontVec, PxScale, ScaleFont};
use ferrovault::tui::{draw, EntryView, UiState};
use image::{Rgba, RgbaImage};
use ratatui::backend::TestBackend;
use ratatui::style::{Color, Modifier};
use ratatui::Terminal;

// ── Catppuccin Mocha palette (for a sleek, modern look) ─────────────────────
const BASE: [u8; 3] = [30, 30, 46]; // #1e1e2e  window background
const SURFACE0: [u8; 3] = [49, 50, 68]; // #313244  selection / subtle bg
const TEXT: [u8; 3] = [205, 214, 244]; // #cdd6f4  default foreground
const OVERLAY: [u8; 3] = [127, 132, 156]; // #7f849c dim / borders / hints
const RED: [u8; 3] = [243, 139, 168];
const GREEN: [u8; 3] = [166, 227, 161];
const YELLOW: [u8; 3] = [249, 226, 175];
const BLUE: [u8; 3] = [137, 180, 250];
const MAUVE: [u8; 3] = [203, 166, 247];
const SKY: [u8; 3] = [137, 220, 235];
const MANTLE: [u8; 3] = [24, 24, 37];

fn map_fg(c: Color) -> [u8; 3] {
    match c {
        Color::Reset | Color::White | Color::Gray => TEXT,
        Color::Black => MANTLE,
        Color::Red | Color::LightRed => RED,
        Color::Green | Color::LightGreen => GREEN,
        Color::Yellow | Color::LightYellow => YELLOW,
        Color::Blue | Color::LightBlue => BLUE,
        Color::Magenta | Color::LightMagenta => MAUVE,
        Color::Cyan | Color::LightCyan => SKY,
        Color::DarkGray => OVERLAY,
        Color::Rgb(r, g, b) => [r, g, b],
        _ => TEXT,
    }
}

fn map_bg(c: Color) -> [u8; 3] {
    match c {
        Color::Reset => BASE,
        Color::DarkGray => SURFACE0, // list selection highlight
        Color::Rgb(r, g, b) => [r, g, b],
        other => map_fg(other),
    }
}

fn blend(dst: [u8; 3], src: [u8; 3], a: f32) -> [u8; 3] {
    let a = a.clamp(0.0, 1.0);
    [
        (dst[0] as f32 * (1.0 - a) + src[0] as f32 * a).round() as u8,
        (dst[1] as f32 * (1.0 - a) + src[1] as f32 * a).round() as u8,
        (dst[2] as f32 * (1.0 - a) + src[2] as f32 * a).round() as u8,
    ]
}

fn load_font() -> FontVec {
    let candidates = [
        std::env::var("FERROVAULT_FONT").unwrap_or_default(),
        r"C:\Windows\Fonts\CascadiaMono.ttf".to_string(),
        r"C:\Windows\Fonts\CascadiaCode.ttf".to_string(),
        r"C:\Windows\Fonts\consola.ttf".to_string(),
    ];
    for path in candidates.iter().filter(|p| !p.is_empty()) {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(font) = FontVec::try_from_vec(bytes) {
                eprintln!("font: {path}");
                return font;
            }
        }
    }
    panic!("no monospace font found; set FERROVAULT_FONT to a .ttf path");
}

/// Render a UiState to a PNG file.
fn render_png(st: &UiState, cols: u16, rows: u16, font: &FontVec, out: &str) {
    // 1. Render the TUI into a ratatui cell buffer.
    let backend = TestBackend::new(cols, rows);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(|f| draw(f, st)).unwrap();
    let buf = terminal.backend().buffer().clone();

    // 2. Font metrics → cell size.
    let px = 26.0_f32;
    let scale = PxScale::from(px);
    let sf = font.as_scaled(scale);
    let cell_w = sf.h_advance(font.glyph_id('M')).round().max(1.0) as u32;
    let cell_h = (sf.ascent() - sf.descent() + sf.line_gap())
        .round()
        .max(1.0) as u32;
    let ascent = sf.ascent();

    let pad = 20u32;
    let img_w = cols as u32 * cell_w + pad * 2;
    let img_h = rows as u32 * cell_h + pad * 2;
    let mut img = RgbaImage::from_pixel(img_w, img_h, Rgba([BASE[0], BASE[1], BASE[2], 255]));

    let put = |img: &mut RgbaImage, x: i32, y: i32, c: [u8; 3]| {
        if x >= 0 && y >= 0 && (x as u32) < img_w && (y as u32) < img_h {
            img.put_pixel(x as u32, y as u32, Rgba([c[0], c[1], c[2], 255]));
        }
    };

    for row in 0..rows {
        for col in 0..cols {
            let cell = &buf[(col, row)];
            let mut fg = map_fg(cell.fg);
            let mut bg = map_bg(cell.bg);
            let m = cell.modifier;
            if m.contains(Modifier::REVERSED) {
                std::mem::swap(&mut fg, &mut bg);
            }
            if m.contains(Modifier::DIM) {
                fg = blend(bg, fg, 0.55);
            }

            let cx = pad + col as u32 * cell_w;
            let cy = pad + row as u32 * cell_h;

            // Cell background (skip if it equals window base, to save work).
            if bg != BASE {
                for yy in 0..cell_h {
                    for xx in 0..cell_w {
                        put(&mut img, (cx + xx) as i32, (cy + yy) as i32, bg);
                    }
                }
            }

            // Glyph.
            let ch = cell.symbol().chars().next().unwrap_or(' ');
            if ch == ' ' || ch == '\0' {
                continue;
            }
            let glyph = font
                .glyph_id(ch)
                .with_scale_and_position(scale, point(cx as f32, cy as f32 + ascent));
            if let Some(outline) = font.outline_glyph(glyph) {
                let bounds = outline.px_bounds();
                outline.draw(|gx, gy, cov| {
                    let x = bounds.min.x as i32 + gx as i32;
                    let y = bounds.min.y as i32 + gy as i32;
                    if x >= 0 && y >= 0 && (x as u32) < img_w && (y as u32) < img_h {
                        let base = img.get_pixel(x as u32, y as u32);
                        let dst = [base[0], base[1], base[2]];
                        let blended = blend(dst, fg, cov);
                        img.put_pixel(
                            x as u32,
                            y as u32,
                            Rgba([blended[0], blended[1], blended[2], 255]),
                        );
                    }
                });
            }
        }
    }

    img.save(out).unwrap();
    eprintln!("wrote {out}  ({img_w}x{img_h})");
}

fn entries() -> Vec<EntryView> {
    let mk = |name: &str, user: &str, pw: &str, url: Option<&str>, totp: Option<&str>| EntryView {
        name: name.into(),
        username: user.into(),
        password: pw.into(),
        url: url.map(|s| s.into()),
        notes: None,
        totp_secret: totp.map(|s| s.into()),
    };
    vec![
        mk(
            "aws-prod",
            "root",
            "Tr0ub4dor&3xY!",
            Some("https://console.aws.amazon.com"),
            None,
        ),
        mk(
            "github",
            "althology",
            "g1thubP@ss!w0rd",
            Some("https://github.com"),
            Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        ),
        mk(
            "gmail",
            "alice@gmail.com",
            "c0rrectHorse",
            Some("https://mail.google.com"),
            None,
        ),
        mk(
            "stripe",
            "ops@acme.io",
            "sk_live_x9f2",
            Some("https://dashboard.stripe.com"),
            None,
        ),
        mk("vault-server", "admin", "h4rd2gu3ss", None, None),
    ]
}

fn main() {
    std::fs::create_dir_all("screenshots").unwrap();
    let font = load_font();
    let (cols, rows) = (96u16, 28u16);

    // 1. Browsing the list, password masked.
    let s1 = UiState {
        vault_path: "~/.ferrovault/vault.pvlt".into(),
        entries: entries(),
        query: String::new(),
        selected: 0,
        revealed: false,
        now: 1_700_000_000,
        status: "Ready".into(),
    };
    render_png(&s1, cols, rows, &font, "screenshots/01-browse.png");

    // 2. Entry revealed, with a live TOTP code (github @ index 1).
    let s2 = UiState {
        selected: 1,
        revealed: true,
        status: "Password copied to clipboard.".into(),
        ..UiState {
            vault_path: "~/.ferrovault/vault.pvlt".into(),
            entries: entries(),
            query: String::new(),
            selected: 0,
            revealed: false,
            now: 1_700_000_000,
            status: String::new(),
        }
    };
    render_png(&s2, cols, rows, &font, "screenshots/02-revealed-totp.png");

    // 3. Search active, filtering.
    let s3 = UiState {
        vault_path: "~/.ferrovault/vault.pvlt".into(),
        entries: entries(),
        query: "a".into(),
        selected: 0,
        revealed: false,
        now: 1_700_000_000,
        status: "Search: a".into(),
    };
    render_png(&s3, cols, rows, &font, "screenshots/03-search.png");

    eprintln!("done");
}
