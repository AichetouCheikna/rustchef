use base64::Engine;
use md5::Md5;
use regex::Regex;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;

pub fn base64_encode(input: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(input.as_bytes())
}
pub fn base64_decode(input: &str) -> Result<String, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    String::from_utf8(bytes).map_err(|e| format!("UTF-8 error: {}", e))
}
pub fn hex_encode(input: &str) -> String {
    hex::encode(input.as_bytes())
}
pub fn hex_decode(input: &str) -> Result<String, String> {
    let bytes = hex::decode(input.trim().replace(' ', ""))
        .map_err(|e| format!("Hex decode error: {}", e))?;
    String::from_utf8(bytes).map_err(|e| format!("UTF-8 error: {}", e))
}
pub fn url_encode(input: &str) -> String {
    urlencoding::encode(input).to_string()
}
pub fn url_decode(input: &str) -> Result<String, String> {
    urlencoding::decode(input)
        .map(|s| s.to_string())
        .map_err(|e| format!("URL decode error: {}", e))
}
pub fn hash_md5(input: &str) -> String {
    let mut h = Md5::new();
    h.update(input.as_bytes());
    format!("{:x}", h.finalize())
}
pub fn hash_sha1(input: &str) -> String {
    let mut h = Sha1::new();
    h.update(input.as_bytes());
    format!("{:x}", h.finalize())
}
pub fn hash_sha256(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    format!("{:x}", h.finalize())
}
pub fn hash_sha512(input: &str) -> String {
    let mut h = Sha512::new();
    h.update(input.as_bytes());
    format!("{:x}", h.finalize())
}
pub fn rot13(input: &str) -> String {
    input
        .chars()
        .map(|c| match c {
            'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
            'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
            _ => c,
        })
        .collect()
}
pub fn xor_bytes(input: &str, key: u8) -> String {
    let xored: Vec<u8> = input.as_bytes().iter().map(|b| b ^ key).collect();
    hex::encode(xored)
}
pub fn reverse(input: &str) -> String {
    input.chars().rev().collect()
}
pub fn to_uppercase(input: &str) -> String {
    input.to_uppercase()
}
pub fn to_lowercase(input: &str) -> String {
    input.to_lowercase()
}
pub fn entropy(input: &str) -> f64 {
    if input.is_empty() {
        return 0.0;
    }
    let len = input.len() as f64;
    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in input.chars() {
        *freq.entry(c).or_insert(0) += 1;
    }
    -freq
        .values()
        .map(|&count| {
            let p = count as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}
pub struct TextStats {
    pub chars: usize,
    pub words: usize,
    pub lines: usize,
    pub bytes: usize,
    pub unique_chars: usize,
}
pub fn text_stats(input: &str) -> TextStats {
    let chars: Vec<char> = input.chars().collect();
    let mut unique: std::collections::HashSet<char> = std::collections::HashSet::new();
    for c in &chars {
        unique.insert(*c);
    }
    TextStats {
        chars: chars.len(),
        words: input.split_whitespace().count(),
        lines: input.lines().count(),
        bytes: input.len(),
        unique_chars: unique.len(),
    }
}
pub fn extract_ips(input: &str) -> Vec<String> {
    let re =
        Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
            .unwrap();
    re.find_iter(input)
        .map(|m| m.as_str().to_string())
        .collect()
}
pub fn extract_urls(input: &str) -> Vec<String> {
    let re = Regex::new(r#"https?://[^ \t<>]+"#).unwrap();
    re.find_iter(input)
        .map(|m| m.as_str().to_string())
        .collect()
}
pub fn extract_emails(input: &str) -> Vec<String> {
    let re = Regex::new(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}").unwrap();
    re.find_iter(input)
        .map(|m| m.as_str().to_string())
        .collect()
}
pub fn binary_encode(input: &str) -> String {
    input
        .bytes()
        .map(|b| format!("{:08b}", b))
        .collect::<Vec<_>>()
        .join(" ")
}
pub fn binary_decode(input: &str) -> Result<String, String> {
    let bytes: Result<Vec<u8>, _> = input
        .split_whitespace()
        .map(|s| u8::from_str_radix(s, 2).map_err(|e| format!("Binary parse error: {}", e)))
        .collect();
    let bytes = bytes?;
    String::from_utf8(bytes).map_err(|e| format!("UTF-8 error: {}", e))
}
pub fn caesar(input: &str, shift: u8) -> String {
    let shift = shift % 26;
    input
        .chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + shift) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + shift) % 26) + b'A') as char,
            _ => c,
        })
        .collect()
}
pub fn word_frequency(input: &str) -> Vec<(String, usize)> {
    let mut freq: HashMap<String, usize> = HashMap::new();
    for word in input.split_whitespace() {
        let cleaned: String = word.chars().filter(|c| c.is_alphabetic()).collect();
        let lower = cleaned.to_lowercase();
        if !lower.is_empty() {
            *freq.entry(lower).or_insert(0) += 1;
        }
    }
    let mut result: Vec<(String, usize)> = freq.into_iter().collect();
    result.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    result
}
pub fn detect_encoding(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.chars().all(|c| c.is_ascii_hexdigit()) && trimmed.len() % 2 == 0 {
        return "Likely HEX encoded".to_string();
    }
    let b64_re = Regex::new(r"^[A-Za-z0-9+/]+=*$").unwrap();
    if b64_re.is_match(trimmed) && trimmed.len() % 4 == 0 {
        return "Likely Base64 encoded".to_string();
    }
    if trimmed
        .split_whitespace()
        .all(|s| s.chars().all(|c| c == '0' || c == '1') && s.len() == 8)
    {
        return "Likely Binary encoded".to_string();
    }
    if trimmed.contains('%') {
        return "Likely URL encoded".to_string();
    }
    "Unknown / plain text".to_string()
}
