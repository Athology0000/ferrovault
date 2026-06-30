//! Render ferrovault GUI scenes to PNG files (headless, no display needed).
//! Run: `cargo run --example gui_png`  → screenshots/gui-01-lock.png, gui-02-browse.png, gui-03-revealed.png

use eframe::egui;
use ferrovault::tui::EntryView;

fn save_color_image(img: &egui::ColorImage, path: &str) {
    let [w, h] = img.size;
    let mut buf = image::RgbaImage::new(w as u32, h as u32);
    for y in 0..h {
        for x in 0..w {
            let p = img.pixels[y * w + x];
            buf.put_pixel(
                x as u32,
                y as u32,
                image::Rgba([p.r(), p.g(), p.b(), p.a()]),
            );
        }
    }
    buf.save(path).unwrap();
    eprintln!("saved {path} ({w}x{h})");
}

struct SnapshotApp {
    scenes: Vec<(ferrovault::gui::GuiApp, String)>,
    index: usize,
    requested: bool,
}

impl eframe::App for SnapshotApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if self.index >= self.scenes.len() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            return;
        }

        // Draw current scene
        self.scenes[self.index].0.update(ctx, frame);

        // Check for screenshot events
        let shots: Vec<_> = ctx.input(|i| {
            i.raw
                .events
                .iter()
                .filter_map(|e| match e {
                    egui::Event::Screenshot { image, .. } => Some(image.clone()),
                    _ => None,
                })
                .collect()
        });

        for img in shots {
            let path = self.scenes[self.index].1.clone();
            save_color_image(&img, &path);
            self.index += 1;
            self.requested = false;
            ctx.request_repaint();
        }

        if !self.requested {
            self.requested = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
            ctx.request_repaint();
        }
    }
}

fn main() {
    std::fs::create_dir_all("screenshots").unwrap();

    let entries = vec![
        EntryView {
            name: "GitHub".to_string(),
            username: "dev@example.com".to_string(),
            password: "gh_pat_XXXXX_secret_token".to_string(),
            url: Some("https://github.com".to_string()),
            notes: Some("Main dev account".to_string()),
            totp_secret: Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_string()),
        },
        EntryView {
            name: "GitLab".to_string(),
            username: "dev@example.com".to_string(),
            password: "glpat-XXXXX_token".to_string(),
            url: Some("https://gitlab.com".to_string()),
            notes: None,
            totp_secret: None,
        },
        EntryView {
            name: "AWS Production".to_string(),
            username: "admin@company.com".to_string(),
            password: "Sup3rS3cr3t!Aws2024".to_string(),
            url: Some("https://aws.amazon.com".to_string()),
            notes: Some("Root account - handle with care".to_string()),
            totp_secret: None,
        },
        EntryView {
            name: "Gmail".to_string(),
            username: "personal@gmail.com".to_string(),
            password: "app_specific_pwd_2024".to_string(),
            url: Some("https://mail.google.com".to_string()),
            notes: None,
            totp_secret: None,
        },
        EntryView {
            name: "Vault Server".to_string(),
            username: "root".to_string(),
            password: "root_token_here_secret".to_string(),
            url: Some("https://vault.internal".to_string()),
            notes: Some("HashiCorp Vault - production".to_string()),
            totp_secret: None,
        },
    ];

    let scenes = vec![
        (
            ferrovault::gui::GuiApp::demo("demo-vault".to_string(), vec![], true, false, None),
            "screenshots/gui-01-lock.png".to_string(),
        ),
        (
            ferrovault::gui::GuiApp::demo(
                "~/.ferrovault/vault.pvlt".to_string(),
                entries.clone(),
                false,
                false,
                Some(0),
            ),
            "screenshots/gui-02-browse.png".to_string(),
        ),
        (
            ferrovault::gui::GuiApp::demo(
                "~/.ferrovault/vault.pvlt".to_string(),
                entries.clone(),
                false,
                true,
                Some(0),
            ),
            "screenshots/gui-03-revealed.png".to_string(),
        ),
    ];

    let app = SnapshotApp {
        scenes,
        index: 0,
        requested: false,
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1000.0, 640.0]),
        ..Default::default()
    };
    eframe::run_native(
        "ferrovault-snapshots",
        options,
        Box::new(|_cc| Ok(Box::new(app))),
    )
    .unwrap();
}
