mod ops;

use clap::{Parser, Subcommand};
use std::io::{self, Read};

#[derive(Parser)]
#[command(
    name = "rustchef",
    version = "0.1.0",
    about = "CyberChef-inspired CLI data transformation tool"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(short, long, global = true)]
    input: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    B64Encode,
    B64Decode,
    HexEncode,
    HexDecode,
    UrlEncode,
    UrlDecode,
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Rot13,
    Xor {
        #[arg(short, long, default_value = "42")]
        key: u8,
    },
    Reverse,
    Upper,
    Lower,
    Entropy,
    Stats,
    ExtractIps,
    ExtractUrls,
    ExtractEmails,
    BinEncode,
    BinDecode,
    Caesar {
        #[arg(short, long, default_value = "13")]
        shift: u8,
    },
    WordFreq,
    Detect,
    Chain {
        #[arg(short, long)]
        ops: String,
    },
}

fn read_stdin() -> Result<String, String> {
    let mut buf = String::new();
    io::stdin()
        .read_to_string(&mut buf)
        .map_err(|e| format!("Error reading stdin: {}", e))?;
    Ok(buf.trim_end_matches('\n').to_string())
}

fn get_input(cli: &Cli) -> Result<String, String> {
    match &cli.input {
        Some(s) if s == "-" => read_stdin(),
        Some(path) => {
            if std::path::Path::new(path).is_file() {
                std::fs::read_to_string(path)
                    .map(|s| s.trim_end_matches('\n').to_string())
                    .map_err(|e| format!("Error reading file '{}': {}", path, e))
            } else {
                Ok(path.clone())
            }
        }
        None => read_stdin(),
    }
}

fn run_op(op: &str, data: &str) -> Result<String, String> {
    match op.trim().to_lowercase().as_str() {
        "b64encode" => Ok(ops::base64_encode(data)),
        "b64decode" => ops::base64_decode(data),
        "hexencode" => Ok(ops::hex_encode(data)),
        "hexdecode" => ops::hex_decode(data),
        "urlencode" => Ok(ops::url_encode(data)),
        "urldecode" => ops::url_decode(data),
        "md5" => Ok(ops::hash_md5(data)),
        "sha1" => Ok(ops::hash_sha1(data)),
        "sha256" => Ok(ops::hash_sha256(data)),
        "sha512" => Ok(ops::hash_sha512(data)),
        "rot13" => Ok(ops::rot13(data)),
        "reverse" => Ok(ops::reverse(data)),
        "upper" => Ok(ops::to_uppercase(data)),
        "lower" => Ok(ops::to_lowercase(data)),
        "binencode" => Ok(ops::binary_encode(data)),
        "bindecode" => ops::binary_decode(data),
        other => Err(format!("Unknown op in chain: '{}'", other)),
    }
}

fn main() {
    let cli = Cli::parse();
    let input = match get_input(&cli) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    let result: Result<String, String> = match &cli.command {
        Commands::B64Encode => Ok(ops::base64_encode(&input)),
        Commands::B64Decode => ops::base64_decode(&input),
        Commands::HexEncode => Ok(ops::hex_encode(&input)),
        Commands::HexDecode => ops::hex_decode(&input),
        Commands::UrlEncode => Ok(ops::url_encode(&input)),
        Commands::UrlDecode => ops::url_decode(&input),
        Commands::Md5 => Ok(ops::hash_md5(&input)),
        Commands::Sha1 => Ok(ops::hash_sha1(&input)),
        Commands::Sha256 => Ok(ops::hash_sha256(&input)),
        Commands::Sha512 => Ok(ops::hash_sha512(&input)),
        Commands::Rot13 => Ok(ops::rot13(&input)),
        Commands::Xor { key } => Ok(ops::xor_bytes(&input, *key)),
        Commands::Reverse => Ok(ops::reverse(&input)),
        Commands::Upper => Ok(ops::to_uppercase(&input)),
        Commands::Lower => Ok(ops::to_lowercase(&input)),
        Commands::BinEncode => Ok(ops::binary_encode(&input)),
        Commands::BinDecode => ops::binary_decode(&input),
        Commands::Caesar { shift } => Ok(ops::caesar(&input, *shift)),
        Commands::Detect => Ok(ops::detect_encoding(&input)),
        Commands::Entropy => Ok(format!("{:.4} bits/symbol", ops::entropy(&input))),
        Commands::Stats => {
            let s = ops::text_stats(&input);
            Ok(format!(
                "Characters  : {}\nWords       : {}\nLines       : {}\nBytes       : {}\nUnique chars: {}",
                s.chars, s.words, s.lines, s.bytes, s.unique_chars
            ))
        }
        Commands::ExtractIps => {
            let v = ops::extract_ips(&input);
            if v.is_empty() {
                Ok("No IP addresses found.".to_string())
            } else {
                Ok(v.join("\n"))
            }
        }
        Commands::ExtractUrls => {
            let v = ops::extract_urls(&input);
            if v.is_empty() {
                Ok("No URLs found.".to_string())
            } else {
                Ok(v.join("\n"))
            }
        }
        Commands::ExtractEmails => {
            let v = ops::extract_emails(&input);
            if v.is_empty() {
                Ok("No emails found.".to_string())
            } else {
                Ok(v.join("\n"))
            }
        }
        Commands::WordFreq => {
            let freq = ops::word_frequency(&input);
            let top: Vec<String> = freq
                .iter()
                .take(10)
                .map(|(w, c)| format!("{:<20} {}", w, c))
                .collect();
            Ok(format!("{:<20} {}\n{}", "word", "count", top.join("\n")))
        }
        Commands::Chain { ops: chain_ops } => {
            let mut data = input.clone();
            for op in chain_ops.split(',') {
                data = match run_op(op, &data) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Chain error at '{}': {}", op.trim(), e);
                        std::process::exit(1);
                    }
                };
            }
            Ok(data)
        }
    };

    match result {
        Ok(out) => println!("{}", out),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}
