use std::collections::HashSet;
use std::env;
use std::process;

use challenge::utils::{decode_hex, load_file_per_line};

fn usage() {
    println!("Usage: find_aes_ecb_bin <file>");
    std::process::exit(-1);
}

fn count_duplicates(bytes: &[u8], block_size: usize) -> u32 {
    let mut duplicates = 0;
    let mut chunks_seen = HashSet::new();

    for chunk in bytes.chunks(block_size) {
        if !chunks_seen.contains(chunk) {
            chunks_seen.insert(chunk);
        } else {
            duplicates += 1;
        }
    }
    if duplicates > 0 {
        println!("Num duplicates: {:?}", duplicates);
        println!("Chunks: {:?}", chunks_seen);
    }
    duplicates
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        usage();
        process::exit(-1);
    }

    let lines = load_file_per_line(&args[1]);

    let duplicate_counts = lines
        .iter()
        .map(|line| decode_hex(&line.clone()).unwrap())
        .map(|line| count_duplicates(&line, 16));

    let max_line = duplicate_counts
        .enumerate()
        .map(|(x, y)| (y, x))
        .max()
        .unwrap();

    println!("{:?}", max_line);

    println!("ECB line: {:?}", lines[max_line.1]);
}
