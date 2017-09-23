extern crate openssl;
extern crate itertools;

mod utils;
mod aes;
mod xor;

use std::env;
use std::process;

use aes::decrypt_128_cbc;

use utils::decode_b64;
use utils::load_file;

fn usage() {
    println!("Usage: aes_cbc <file> <key>");
    std::process::exit(-1);
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        usage();
        process::exit(1);
    }

    let ciphertext_b64 = load_file(&args[1]);
    let ciphertext_bytes = decode_b64(&ciphertext_b64);

    let key = args[2].clone();
    let key_bytes = key.into_bytes();
    let iv: Vec<u8> = vec![0; 16];

    let plaintext = decrypt_128_cbc(&key_bytes, &ciphertext_bytes, &iv);

    println!("Plaintext:\n{}", String::from_utf8(plaintext).unwrap());
}

