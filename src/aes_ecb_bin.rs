extern crate openssl;

mod utils;

use std::env;
use std::process;

use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::BufRead;

use openssl::symm;

use utils::decode_b64;

fn usage() {
    println!("Usage: aes_ecb <base64 encoded aes128 ecb ciphertext>> <key>");
    std::process::exit(-1);
}

fn load_file(file_path: &str) -> String {
    let mut content = String::new();
    let f = File::open(file_path).expect("Unable to open file");
    let mut br = BufReader::new(f);
    for line in br.lines() {
        let l = line.unwrap();
        content.push_str(&l);
    }
    content
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

