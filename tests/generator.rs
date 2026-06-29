use ferrovault::generator::{generate, GenOptions};
use ferrovault::Error;

#[test]
fn honors_length() {
    let pw = generate(&GenOptions {
        length: 32,
        symbols: true,
    })
    .unwrap();
    assert_eq!(pw.chars().count(), 32);
}

#[test]
fn too_short_errors() {
    assert!(matches!(
        generate(&GenOptions {
            length: 3,
            symbols: true
        })
        .unwrap_err(),
        Error::TooShort(_)
    ));
}

#[test]
fn includes_each_required_class() {
    // Over several samples, every required class must appear in each password.
    for _ in 0..50 {
        let pw = generate(&GenOptions {
            length: 12,
            symbols: true,
        })
        .unwrap();
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_digit()));
        assert!(pw.chars().any(|c| !c.is_ascii_alphanumeric()));
    }
}

#[test]
fn no_symbols_excludes_symbols() {
    for _ in 0..50 {
        let pw = generate(&GenOptions {
            length: 16,
            symbols: false,
        })
        .unwrap();
        assert!(pw.chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
