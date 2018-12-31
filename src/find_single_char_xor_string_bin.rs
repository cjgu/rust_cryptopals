use std::char;
use std::env;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::process;

use challenge::utils::decode_hex;
use challenge::xor::{repeating_key, search_single_char_key, xor};

fn usage() {
    println!("Usage: find_single_single_char_xor_string <file>");
    std::process::exit(-1);
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        usage();
        process::exit(1);
    }

    let f = File::open(&args[1]).expect("Unable to open file");
    let br = BufReader::new(f);

    let mut highest_score = 0;
    let mut high_score_key = 0;
    let mut high_score_ciphertext: Vec<u8> = vec![];
    for line in br.lines() {
        let l = line.unwrap();
        let ciphertext = decode_hex(&l).expect("Invalid hex");
        let (key, score) = search_single_char_key(&ciphertext);

        if score > highest_score {
            highest_score = score;
            high_score_key = key;
            high_score_ciphertext = ciphertext.clone();
        }
    }

    println!("Key: {:?}", char::from_u32(high_score_key as u32).unwrap());
    let key_vec: Vec<u8> = vec![high_score_key];
    let full_key = repeating_key(&key_vec, high_score_ciphertext.len());

    let plaintext = xor(&high_score_ciphertext, &full_key);
    println!("Plaintext: {:?}", String::from_utf8(plaintext).unwrap());
}
