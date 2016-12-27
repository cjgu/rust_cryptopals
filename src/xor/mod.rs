use std::char;
use itertools::Itertools;

pub fn xor(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    assert_eq!(a.len(), b.len());

    a.iter().zip(b.iter()).map(|(&x,&y)| x ^ y).collect::<Vec<u8>>()
}

pub fn repeating_key(key: &Vec<u8>, length: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(length);
    for i in 0..length {
        out.push(key[i % key.len()]);
    }
    out
}

pub fn break_repeating_key(key_size: usize, cryptotext: &Vec<u8>) -> Vec<u8> {
    let mut full_key = Vec::with_capacity(key_size);
    for i in 0..key_size {
        let (key, score) = search_single_char_key(
            &cryptotext.iter().dropping(i).step(key_size).map(|&x| x).collect_vec()
        );
        full_key.push(key);
    }

    full_key
}

pub fn search_single_char_key(ciphertext: &Vec<u8>) -> (u8, u32) {
    // For each key in 0x00 -> 0xFF
    //  - generate key
    //  - xor key with ciphertext
    //  - score plaintext, store key => score mapping
    //
    // Find highest scoring key
    let mut highest_score = 0;
    let mut high_score_key = 0;
    for ascii_key in 0..0xFF {
        let key: Vec<u8> = vec![ascii_key];
        let full_key = repeating_key(&key, ciphertext.len());

        let plaintext = xor(&ciphertext, &full_key);

        let score = score_plaintext(&plaintext);

        if score >= highest_score {
            highest_score = score;
            high_score_key = ascii_key;
        }
    }
    (high_score_key, highest_score)
}

pub fn score_plaintext(plaintext: &Vec<u8>) -> u32 {
    plaintext.iter()
        .map(| &x | match x {
            10 => 1, // '\n'
            32 => 1, // ' '
            39 => 1, // '\''
            45 => 1, // -
            48 ... 57 => 1, // 0-9
            58 => 1, // :
            65 ... 90 => 1, // A-Z
            97 ... 122 => 1, // a-z
            _ => 0
        })
        .fold(0, |acc, x| acc + x)
}

pub fn hamming_distance(a: &Vec<u8>, b: &Vec<u8>) -> u32 {
    let c = xor(a, b);

    c.iter().map(|&x| x.count_ones()).fold(0, | acc, x| acc + x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_1() {
        let a: Vec<u8> = vec![0, 1, 1, 0];
        let b: Vec<u8> = vec![1, 0, 1, 0];
        let res: Vec<u8> = vec![1, 1, 0, 0];
        assert_eq!(res, xor(&a, &b));
    }

    #[test]
    fn test_repeating_key_short() {
        let b: Vec<u8> = vec![1];
        let res_2: Vec<u8> = vec![1, 1, 1, 1];
        assert_eq!(res_2, repeating_key(&b, 4));
    }

    #[test]
    fn test_repeating_key_long() {
        let a: Vec<u8> = vec![1, 2, 3];
        let res: Vec<u8> = vec![1, 2, 3, 1, 2, 3];
        assert_eq!(res, repeating_key(&a, 6));
    }

    #[test]
    fn test_hamming_distance() {
        let a: Vec<u8> = vec![1, 1, 1, 1];
        let b: Vec<u8> = vec![0, 1, 1, 1];
        assert_eq!(1, hamming_distance(&a, &b));

        let c: Vec<u8> = vec![1, 1, 1, 1];
        let d: Vec<u8> = vec![2, 1, 1, 1];
        assert_eq!(2, hamming_distance(&c, &d));

        let e: Vec<u8> = b"this is a test".to_vec();
        let f: Vec<u8> = b"wokka wokka!!!".to_vec();
        assert_eq!(37, hamming_distance(&e, &f));
    }
}
