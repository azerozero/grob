use super::*;

fn filter(kind: &str, values: &[&str]) -> ResponseFilter {
    ResponseFilter::new(
        kind,
        EchoFilter::new(values.iter().map(|v| (*v).to_owned())),
    )
    .unwrap()
}

#[test]
fn punctuation_password_does_not_replace_json_delimiters() {
    let mut f = filter("application/json", &["user", "\""]);
    let out = f.push(br#"{"ok":true,"echo":"\u0022"}"#, true).unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["echo"], "[redacted]");
}

#[test]
fn redaction_preserves_large_numbers_without_float_rounding() {
    let mut f = filter("application/json", &["secret"]);
    let input = br#"{"id":1234567890123456789012345678901234567890,"echo":"secret"}"#;
    let out = String::from_utf8(f.push(input, true).unwrap()).unwrap();
    assert!(out.contains("1234567890123456789012345678901234567890"));
    assert!(out.contains("[redacted]"));
}

#[test]
fn long_secret_never_holds_an_unrelated_complete_event() {
    let token = "z".repeat(4096);
    let input = b"data: {\"ok\":true}\n\n";
    let mut f = filter("text/event-stream", &[&token]);
    for _ in 0..100 {
        assert_eq!(f.push(input, false).unwrap(), input);
    }
}

#[test]
fn sse_handles_every_boundary_crlf_multiline_and_encoded_echoes() {
    let input = b"event: update\r\ndata: {\"echo\":\r\ndata: \"s\\u0065cret\",\"ok\":true}\r\n\r\ndata: [DONE]\r\n\r\n";
    for size in 1..=input.len() {
        let mut f = filter("text/event-stream", &["secret", "\""]);
        let mut out = Vec::new();
        for chunk in input.chunks(size) {
            out.extend(f.push(chunk, false).unwrap());
        }
        out.extend(f.push(&[], true).unwrap());
        let out = String::from_utf8(out).unwrap();
        assert!(out.starts_with("event: update\ndata: "));
        let json = out
            .lines()
            .find_map(|l| l.strip_prefix("data: {").map(|s| format!("{{{s}")))
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["echo"], "[redacted]");
        assert_eq!(parsed["ok"], true);
        assert!(out.ends_with("data: [DONE]\n\n"));
    }
}

#[test]
fn forms_decode_values_before_filtering_and_preserve_structure() {
    let mut f = filter("application/x-www-form-urlencoded", &["a&b", "user"]);
    let out = f.push(b"name=a%26b&ok=yes", true).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "name=%5Bredacted%5D&ok=yes"
    );
}

#[test]
fn rejects_binary_oversize_malformed_and_secret_keys() {
    assert!(ResponseFilter::new(
        "application/octet-stream",
        EchoFilter::new(["secret".into()])
    )
    .is_err());
    for input in [br#"{"secret":"x"}"#.as_slice(), b"invalid"] {
        assert!(filter("application/json", &["secret"])
            .push(input, true)
            .is_err());
    }
    assert!(filter("application/json", &["secret"])
        .push(&vec![b' '; DOCUMENT_LIMIT + 1], false)
        .is_err());
    assert!(filter("text/event-stream", &["secret"])
        .push(&vec![b'x'; EVENT_LIMIT + 1], false)
        .is_err());
}

#[test]
fn scalar_literals_and_replacement_collisions_remain_valid_json() {
    let mut f = filter("application/json", &["true", "[redacted]"]);
    let out = f.push(b"[true,12,\"[redacted]\"]", true).unwrap();
    let value: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert!(value[0].is_string());
    assert_eq!(value[1], 12);
    assert!(!String::from_utf8(out).unwrap().contains("[redacted]"));
}

#[test]
fn replacement_must_not_create_another_secret_across_emitted_chunks() {
    let mut f = filter("text/plain", &["a!", "[redacted]"]);
    assert!(f.push(b"a[redacted]", false).is_err());
}
