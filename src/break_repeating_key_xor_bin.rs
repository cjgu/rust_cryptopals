use std::env;
use std::process;

use challenge::utils::{decode_b64, load_file};
use challenge::xor::{break_repeating_key, hamming_distance, repeating_key, xor};

fn usage() {
    println!("Usage: break_repeating_key_xor <ciphertext-file>");
    std::process::exit(-1);
}

fn find_key_size(ciphertext: &[u8]) -> usize {
    let mut min_norm_dist: f32 = 100 as f32;
    let mut min_key_size = 0;

    for key_size in 2..40 {
        let distances = vec![
            hamming_distance(
                &ciphertext[0..key_size].to_vec(),
                &ciphertext[key_size..key_size * 2].to_vec(),
            ),
            hamming_distance(
                &ciphertext[key_size * 2..key_size * 3].to_vec(),
                &ciphertext[key_size * 3..key_size * 4].to_vec(),
            ),
            hamming_distance(
                &ciphertext[0..key_size].to_vec(),
                &ciphertext[key_size * 3..key_size * 4].to_vec(),
            ),
            hamming_distance(
                &ciphertext[0..key_size].to_vec(),
                &ciphertext[key_size * 2..key_size * 3].to_vec(),
            ),
        ];
        let sum_distances = distances
            .iter()
            .map(|&x| x as f32 / key_size as f32)
            .fold(0.0, |acc, x| acc + x);
        let norm_avg_dist = sum_distances / distances.len() as f32;

        if norm_avg_dist < min_norm_dist {
            min_norm_dist = norm_avg_dist;
            min_key_size = key_size;
        }
    }

    min_key_size
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        usage();
        process::exit(1);
    }

    let ciphertext_b64 = load_file(&args[1]);

    let ciphertext_bytes = decode_b64(&ciphertext_b64);
    println!("Input bytes: {:?}", ciphertext_bytes.len());

    let key_size = find_key_size(&ciphertext_bytes);
    println!("Min key size: {:?}", key_size);

    let key = break_repeating_key(key_size, &ciphertext_bytes);
    println!("Key: {:?}", String::from_utf8(key.clone()).unwrap());

    let full_key = repeating_key(&key, ciphertext_bytes.len());

    let plaintext = xor(&full_key, &ciphertext_bytes);

    println!("Plaintext:\n{}", String::from_utf8(plaintext).unwrap());
}
