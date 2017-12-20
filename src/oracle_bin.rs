extern crate openssl;
extern crate itertools;
extern crate rand;

mod utils;
mod aes;
mod xor;
mod random;
mod aes_oracle;

use std::env;
use std::process;

use utils::encode_hex;
use aes_oracle::{encrypt_randomly, detection_oracle};

fn usage() {
    println!("Usage: oracle <data>");
    std::process::exit(-1);
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        usage();
        process::exit(1);
    }
    let data = args[1].clone().into_bytes();

    let encrypted = encrypt_randomly(&data);

    println!("Encrypted: {}", encode_hex(&encrypted));
    let guessed_method = detection_oracle(&encrypted);
    println!("Guessed method: {:?}", guessed_method);

}
