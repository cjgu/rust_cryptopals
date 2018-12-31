use std::env;
use std::process;

use challenge::aes_oracle::{detection_oracle_random_method, encrypt_random_method};
use challenge::utils::encode_hex;

fn usage() {
    println!("Usage: oracle_ecb <data>");
    std::process::exit(-1);
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        usage();
        process::exit(1);
    }
    let data = args[1].clone().into_bytes();

    let encrypted = encrypt_random_method(&data);

    println!("Encrypted: {}", encode_hex(&encrypted));
    let guessed_method = detection_oracle_random_method(&encrypted);
    println!("Guessed method: {:?}", guessed_method);
}
