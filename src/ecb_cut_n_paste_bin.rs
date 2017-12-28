extern crate itertools;
extern crate openssl;

mod xor;
mod aes;
mod cookie;
mod utils;

use std::env;
use std::process;

fn usage() {
    println!("Usage:
    ecb_cut_n_paste encrypt <email> <key>
    ecb_cut_n_paste decrypt <cookie> <key>
    ecb_cut_n_paste cut-n-paste <key>
");
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args[1] == "encrypt" {
        let key = utils::decode_hex(&args[3]).expect("Invalid hex key");

        let encrypted = cookie::encrypt_cookie(&args[2], &key);

        println!("{:?}", utils::encode_hex(&encrypted));
    }
    else if args[1] == "decrypt" {
        let cookie  = utils::decode_hex(&args[2]).expect("Invalid cookie");
        let key = utils::decode_hex(&args[3]).expect("Invalid hex key");

        println!("{:?}", cookie::decrypt_cookie(cookie, &key));
    }
    else if args[1] == "cut-n-paste" {
        let key = utils::decode_hex(&args[2]).expect("Invalid hex key");

        let first = "aaaaaa@aa.com";
        let encrypted = cookie::encrypt_cookie(&first, &key);

        let prefix = "XXXXXXXXXX";
        let admin = String::from("admin").into_bytes();
        let admin_padded =  utils::pkcs_7_padding(&admin, 16);
        let admin_padded_str = String::from_utf8(admin_padded).expect("Bad utf");

        let cookie_2 = format!("{}{}", prefix, admin_padded_str);

        let encrypted_2 = cookie::encrypt_cookie(&cookie_2, &key);

        let mut cutnpaste = encrypted[..32].to_vec();
        let mut cutnpaste_2 = encrypted_2[16..32].to_vec();

        cutnpaste.append(&mut cutnpaste_2);

        println!("{:?}", cookie::decrypt_cookie(cutnpaste, &key));
    }
    else {
        println!("Invalid argument");
        usage();
        process::exit(-1);
    }
}
