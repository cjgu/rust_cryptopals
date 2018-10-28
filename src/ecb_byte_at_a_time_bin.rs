extern crate challenge;

use std::env;
use std::process;

use challenge::aes_oracle::{detection_oracle_ecb_extra, detection_oracle_ecb_extra_and_random};

fn usage() {
    println!("Usage: ecb_byte_at_a_time (simple|harder)");
    std::process::exit(-1);
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        usage();
        process::exit(1);
    }

    if args[1] == "simple" {
        detection_oracle_ecb_extra();
    }
    else {
        detection_oracle_ecb_extra_and_random();
    }
}
