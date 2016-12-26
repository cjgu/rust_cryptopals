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
use utils::decode_b64;
use xor::search_single_char_key;
use xor::repeating_key;
use xor::xor;

fn usage() {
    println!("Usage: break_repeating_key_xor <ciphertext-file>");
    std::process::exit(-1);
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        usage();
        process::exit(1);
    }

    let mut ciphertext_b64 = String::new();
    let f = File::open(&args[1]).expect("Unable to open file");
    let mut br = BufReader::new(f);
    br.read_to_string(&mut ciphertext_b64).expect("Can not read string");

    let ciphertext_bytes = decode_b64(&ciphertext_b64);
}
