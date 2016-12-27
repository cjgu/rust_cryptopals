extern crate itertools;
mod utils;
mod xor;

use std::env;
use std::char;
use std::process;

use utils::decode_hex;
use utils::encode_hex;
use xor::search_single_char_key;
use xor::repeating_key;
use xor::xor;

fn usage() {
    println!("Usage: xor_search_single_char_bin <hex-encoded-string>");
    std::process::exit(-1);
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        usage();
        process::exit(1);
    }

    let ciphertext = decode_hex(&args[1]).expect("Invalid hex string");

    let (key, _) = search_single_char_key(&ciphertext);
    println!("Key: {:?}", char::from_u32(key as u32).unwrap());

    let key_vec: Vec<u8> = vec![key];
    let full_key = repeating_key(&key_vec, ciphertext.len());

    let plaintext = xor(&ciphertext, &full_key);
    println!("Plaintext: {:?}", String::from_utf8(plaintext).unwrap());
}
