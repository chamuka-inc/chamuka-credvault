//! The headline invariant: plaintext never appears in Debug output.
use credvault::secret::secret;

#[test]
fn debug_does_not_leak_plaintext() {
    let s = secret("super-secret-value");
    assert!(!format!("{s:?}").contains("super-secret-value"));
}

#[test]
fn debug_inside_a_struct_does_not_leak() {
    #[derive(Debug)]
    #[allow(dead_code)]
    struct Holder {
        token: credvault::secret::SecretString,
        label: String,
    }
    let h = Holder {
        token: secret("leak-me-please"),
        label: "ok".into(),
    };
    let rendered = format!("{h:?}");
    assert!(!rendered.contains("leak-me-please"));
    assert!(rendered.contains("ok")); // non-secret fields still print
}
