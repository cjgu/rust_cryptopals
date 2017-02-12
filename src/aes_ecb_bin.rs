extern crate openssl;

mod utils;

use std::env;
use std::process;


use openssl::symm;

use utils::decode_b64;
use utils::load_file;

fn usage() {
    println!("Usage: aes_ecb <base64 encoded aes128 ecb ciphertext>> <key>");
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

    let plaintext = symm::decrypt(symm::Cipher::aes_128_ecb(),
                                  &key_bytes,
                                  None,
                                  &ciphertext_bytes).unwrap();

    println!("Plaintext:\n{}", String::from_utf8(plaintext).unwrap());
}
