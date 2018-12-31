use std::env;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::process;

use challenge::utils::encode_hex;
use challenge::xor::{repeating_key, xor};

fn usage() {
    println!("Usage: encrypt_xor_bin <plain text file> <key>");
    std::process::exit(-1);
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        usage();
        process::exit(1);
    }

    let mut plaintext_str = String::new();
    let f = File::open(&args[1]).expect("Unable to open file");
    let mut br = BufReader::new(f);
    br.read_to_string(&mut plaintext_str)
        .expect("Can not read string");

    let plaintext_bytes = plaintext_str.into_bytes();

    let key = args[2].clone();
    let key_bytes = key.into_bytes();

    let full_key = repeating_key(&key_bytes, plaintext_bytes.len());

    let ciphertext = xor(&plaintext_bytes, &full_key);

    let ciphertext_hex = encode_hex(&ciphertext);

    println!("{}", ciphertext_hex);
}
