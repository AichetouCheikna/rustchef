use rustchef::ops::*;

#[test]
fn test_base64_encode() {
    assert_eq!(base64_encode("hello"), "aGVsbG8=");
}
#[test]
fn test_base64_decode() {
    assert_eq!(base64_decode("aGVsbG8=").unwrap(), "hello");
}
#[test]
fn test_base64_roundtrip() {
    let s = "RustChef is awesome!";
    assert_eq!(base64_decode(&base64_encode(s)).unwrap(), s);
}
#[test]
fn test_base64_decode_invalid() {
    assert!(base64_decode("!!!invalid!!!").is_err());
}
#[test]
fn test_hex_encode() {
    assert_eq!(hex_encode("hi"), "6869");
}
#[test]
fn test_hex_decode() {
    assert_eq!(hex_decode("6869").unwrap(), "hi");
}
#[test]
fn test_hex_roundtrip() {
    let s = "security";
    assert_eq!(hex_decode(&hex_encode(s)).unwrap(), s);
}
#[test]
fn test_hex_decode_invalid() {
    assert!(hex_decode("zzzz").is_err());
}
#[test]
fn test_url_encode() {
    assert_eq!(url_encode("hello world"), "hello%20world");
}
#[test]
fn test_url_decode() {
    assert_eq!(url_decode("hello%20world").unwrap(), "hello world");
}
#[test]
fn test_url_roundtrip() {
    let s = "user=admin&pass=s3cr3t!";
    assert_eq!(url_decode(&url_encode(s)).unwrap(), s);
}
#[test]
fn test_md5_known() {
    assert_eq!(hash_md5(""), "d41d8cd98f00b204e9800998ecf8427e");
}
#[test]
fn test_sha1_known() {
    assert_eq!(hash_sha1(""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
}
#[test]
fn test_sha256_known() {
    assert_eq!(
        hash_sha256(""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}
#[test]
fn test_sha256_hello() {
    assert_eq!(
        hash_sha256("hello"),
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}
#[test]
fn test_rot13_hello() {
    assert_eq!(rot13("Hello"), "Uryyb");
}
#[test]
fn test_rot13_idempotent() {
    let s = "The Quick Brown Fox";
    assert_eq!(rot13(&rot13(s)), s);
}
#[test]
fn test_rot13_non_alpha_unchanged() {
    assert_eq!(rot13("123!@#"), "123!@#");
}
#[test]
fn test_caesar_shift13_equals_rot13() {
    let s = "Hello World";
    assert_eq!(caesar(s, 13), rot13(s));
}
#[test]
fn test_caesar_roundtrip() {
    let s = "AttackAtDawn";
    assert_eq!(caesar(&caesar(s, 7), 19), s);
}
#[test]
fn test_xor_roundtrip() {
    let original = "secret";
    let encoded_hex = xor_bytes(original, 0x42);
    let bytes = hex::decode(&encoded_hex).unwrap();
    let decoded: String = bytes.iter().map(|b| (b ^ 0x42u8) as char).collect();
    assert_eq!(decoded, original);
}
#[test]
fn test_reverse() {
    assert_eq!(reverse("rustchef"), "fehctsur");
}
#[test]
fn test_reverse_empty() {
    assert_eq!(reverse(""), "");
}
#[test]
fn test_uppercase() {
    assert_eq!(to_uppercase("hello"), "HELLO");
}
#[test]
fn test_lowercase() {
    assert_eq!(to_lowercase("HELLO"), "hello");
}
#[test]
fn test_binary_encode() {
    assert_eq!(binary_encode("A"), "01000001");
}
#[test]
fn test_binary_decode() {
    assert_eq!(binary_decode("01000001").unwrap(), "A");
}
#[test]
fn test_binary_roundtrip() {
    let s = "Hi!";
    assert_eq!(binary_decode(&binary_encode(s)).unwrap(), s);
}
#[test]
fn test_binary_decode_invalid() {
    assert!(binary_decode("99999999").is_err());
}
#[test]
fn test_entropy_empty() {
    assert_eq!(entropy(""), 0.0);
}
#[test]
fn test_entropy_uniform() {
    assert_eq!(entropy("aaaa"), 0.0);
}
#[test]
fn test_entropy_positive() {
    assert!(entropy("hello world") > 0.0);
}
#[test]
fn test_text_stats_words() {
    let s = text_stats("hello world foo");
    assert_eq!(s.words, 3);
    assert_eq!(s.chars, 15);
}
#[test]
fn test_extract_ips() {
    let text = "Attacker from 192.168.1.1 and also 10.0.0.1";
    let ips = extract_ips(text);
    assert_eq!(ips.len(), 2);
    assert!(ips.contains(&"192.168.1.1".to_string()));
}
#[test]
fn test_extract_ips_none() {
    assert!(extract_ips("no ip here").is_empty());
}
#[test]
fn test_extract_urls() {
    let text = "Visit https://example.com and http://test.org";
    let urls = extract_urls(text);
    assert_eq!(urls.len(), 2);
}
#[test]
fn test_extract_emails() {
    let text = "Contact admin@example.com or security@test.org";
    let emails = extract_emails(text);
    assert_eq!(emails.len(), 2);
}
#[test]
fn test_extract_emails_none() {
    assert!(extract_emails("no email here").is_empty());
}
#[test]
fn test_word_frequency() {
    let freq = word_frequency("the cat sat on the mat the cat");
    assert_eq!(freq[0].0, "the");
    assert_eq!(freq[0].1, 3);
}
#[test]
fn test_detect_hex() {
    assert!(detect_encoding("48656c6c6f").contains("HEX"));
}
#[test]
fn test_detect_base64() {
    assert!(detect_encoding("aGVsbG8=").contains("Base64"));
}
#[test]
fn test_detect_binary() {
    assert!(detect_encoding("01001000 01101001").contains("Binary"));
}
#[test]
fn test_detect_url_encoded() {
    assert!(detect_encoding("hello%20world").contains("URL"));
}
