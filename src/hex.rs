mod utils;

use std::env;

use utils::decode_hex;
use utils::encode_b64;

fn usage() {
    println!("Usage: hex <hex-encoded-string>");
    std::process::exit(-1);
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        usage();
    } else {
        let res = decode_hex(&args[1]);

        match res {
            Some(bytes) => {
                println!("Decoded: {:?}", &bytes);
                let encoded = encode_b64(&bytes);
                println!("Encoded b64: {:?}", encoded);
            }
            None => {
                println!("Invalid hex string");
            }
        }
    }
}
