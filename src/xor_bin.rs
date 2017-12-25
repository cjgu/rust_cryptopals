extern crate itertools;
mod utils;
mod xor;

use std::env;

use utils::decode_hex;
use utils::encode_hex;
use xor::xor;

fn usage() {
    println!("Usage: xor_bin <hex-encoded-string> <hex-encoded-string>");
    std::process::exit(-1);
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 3 {
        usage();
    } else {
        let a = decode_hex(&args[1]);
        let b = decode_hex(&args[2]);

        match (a, b) {
            (Some(a_bytes), Some(b_bytes)) => {
                let res = xor(&a_bytes, &b_bytes);
                let encoded = encode_hex(&res);
                println!("{:?}", encoded);
            }
            _ => {
                println!("Invalid hex string");
            }
        }
    }
}
