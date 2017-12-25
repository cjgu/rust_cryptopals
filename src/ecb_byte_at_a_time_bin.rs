extern crate itertools;
extern crate openssl;
extern crate rand;

mod utils;
mod aes;
mod xor;
mod random;
mod aes_oracle;

use std::env;
use std::process;

use utils::encode_hex;
use aes_oracle::detection_oracle_ecb_extra;

fn usage() {
    println!("Usage: ecb_byte_at_a_time");
    std::process::exit(-1);
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 1 {
        usage();
        process::exit(1);
    }

    detection_oracle_ecb_extra();
}
