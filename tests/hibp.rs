use ferrovault::hibp::{pwned_count, RangeFetcher};
use ferrovault::Result;
use std::cell::RefCell;

// Records the prefix it was asked for and returns a canned range body.
struct FakeFetcher {
    body: String,
    seen_prefix: RefCell<String>,
}

impl RangeFetcher for FakeFetcher {
    fn fetch(&self, prefix: &str) -> Result<String> {
        *self.seen_prefix.borrow_mut() = prefix.to_string();
        Ok(self.body.clone())
    }
}

#[test]
fn finds_pwned_password_and_sends_only_prefix() {
    // SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
    // prefix = 5BAA6 ; suffix = 1E4C9B93F3F0682250B6CF8331B7EE68FD8
    let fake = FakeFetcher {
        body: "1E4C9B93F3F0682250B6CF8331B7EE68FD8:99\r\n0018A45C4D1DEF81644B54AB7F969B88D65:1"
            .into(),
        seen_prefix: RefCell::new(String::new()),
    };
    let count = pwned_count(&fake, "password").unwrap();
    assert_eq!(count, 99);
    assert_eq!(*fake.seen_prefix.borrow(), "5BAA6"); // only 5 hex chars leave
}

#[test]
fn clean_password_returns_zero() {
    let fake = FakeFetcher {
        body: "0018A45C4D1DEF81644B54AB7F969B88D65:1".into(),
        seen_prefix: RefCell::new(String::new()),
    };
    assert_eq!(pwned_count(&fake, "password").unwrap(), 0);
}
