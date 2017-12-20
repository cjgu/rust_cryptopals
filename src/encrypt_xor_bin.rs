extern crate itertools;

mod utils;
mod xor;

use std::env;
use std::char;
use std::process;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;

use utils::decode_hex;
use utils::encode_hex;
use xor::search_single_char_key;
use xor::repeating_key;
use xor::xor;

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
    br.read_to_string(&mut plaintext_str).expect(
        "Can not read string",
    );

    let plaintext_bytes = plaintext_str.into_bytes();

    let key = args[2].clone();
    let key_bytes = key.into_bytes();

    let full_key = repeating_key(&key_bytes, plaintext_bytes.len());

    let ciphertext = xor(&plaintext_bytes, &full_key);

    let ciphertext_hex = encode_hex(&ciphertext);

    println!("{}", ciphertext_hex);
}
