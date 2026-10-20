// SPDX-License-Identifier: AGPL-3.0-only
use std::process::Command;

fn wutong(args: &[&str], stdin: Option<&str>) -> (bool, String) {
    use std::io::Write;
    let mut c = Command::new(env!("CARGO_BIN_EXE_wutong"))
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(s) = stdin {
        c.stdin.take().unwrap().write_all(s.as_bytes()).unwrap();
    }
    let o = c.wait_with_output().unwrap();
    (
        o.status.success(),
        String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr),
    )
}

const PRINCIPAL: &str = r#"{"protocol":"wutong/0.1","kind":"wutong.principal","id":"urn:uuid:019a1111-1111-7111-8111-000000000064","occurred_at":"2026-10-18T10:00:00Z","payload":{"principal_id":"urn:uuid:019a1111-1111-7111-8111-000000000065","principal_type":"agent"}}"#;

#[test]
fn validate_and_canon() {
    let (ok, out) = wutong(&["validate", "-"], Some(PRINCIPAL));
    assert!(ok, "{out}");
    assert!(out.starts_with("ok wutong.principal"));
    let (ok, out) = wutong(&["canon", "-"], Some(r#"{"b":1,"a":2}"#));
    assert!(ok);
    assert_eq!(out.trim(), r#"{"a":2,"b":1}"#);
    let (ok, out) = wutong(&["validate", "-"], Some(r#"{"a":1,"a":2}"#));
    assert!(!ok);
    assert!(out.contains("ERR_SCHEMA"));
}

#[test]
fn digest_empty() {
    let (ok, out) = wutong(&["digest", "-"], Some(""));
    assert!(ok);
    assert_eq!(
        out.trim(),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn verify_golden_signed_object() {
    let signed = r#"{"protocol":"wutong/0.1","kind":"wutong.object","id":"urn:uuid:019a1111-1111-7111-8111-000000002713","occurred_at":"2026-10-18T10:00:00Z","payload":{"object_id":"urn:uuid:019a1111-1111-7111-8111-00000000012d","space_id":"urn:uuid:019a1111-1111-7111-8111-00000000012e","owner_id":"urn:uuid:019a1111-1111-7111-8111-00000000012f","object_type":"document","content_digest":"sha256:47ad8cc78b24bcb0b6e13b2657e96f1c915055f3f872d3c2c92b25343a6ff5b6","media_type":"text/markdown","byte_length":0},"auth":{"signer_id":"urn:uuid:019a1111-1111-7111-8111-000000000001","key_id":"local-key-01","issued_at":"2026-10-18T10:00:00Z","nonce":"AAAAAAAAAAAAAAAAAAAAAAAA"},"proof":{"alg":"Ed25519","sig":"91bbF7H1wMhm5Pif0c6nG6uvkwf02UX3wbX54wsBbB2-KYPl63TLqCKke2LGYakkrDCW4Fzq93_LYB4mkhFjCQ"}}"#;
    let pk = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
    let (ok, out) = wutong(&["verify", "-", "--public-key", pk], Some(signed));
    assert!(ok, "{out}");
    let tampered = signed.replace("document", "Document");
    let (ok, _) = wutong(&["verify", "-", "--public-key", pk], Some(&tampered));
    assert!(!ok);
}
