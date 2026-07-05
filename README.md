# RustChef

A CyberChef-inspired CLI data transformation tool written in Rust.

## Features (25 operations)

| Category | Operations |
|---|---|
| Encoding | Base64 encode/decode, Hex encode/decode, URL encode/decode, Binary encode/decode |
| Hashing | MD5, SHA-1, SHA-256, SHA-512 |
| Ciphers | ROT13, XOR, Caesar |
| Text | Reverse, Uppercase, Lowercase |
| Analysis | Entropy, Stats, Word frequency, Detect encoding |
| Extraction | Extract IPs, Extract URLs, Extract emails |
| Chaining | Chain multiple operations |

## Quick start

`ash
docker build -t rustchef .
docker run --rm rustchef --help
echo "hello" | docker run --rm -i rustchef b64-encode
`

## Usage examples

`ash
echo "hello" | cargo run --quiet -- b64-encode
echo "hello" | cargo run --quiet -- sha256
echo "Hello World" | cargo run --quiet -- rot13
cargo run --quiet -- extract-ips -i samples/sample.txt
echo "hello" | cargo run --quiet -- chain --ops b64encode,hexencode
`

## Testing

`ash
cargo test
cargo fmt --check
cargo clippy -- -D warnings
`

## Author

AichetouCheikna - Master Cybersecurity 2025-2026
