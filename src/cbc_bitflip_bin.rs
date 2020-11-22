use std::collections::HashMap;
use std::env;

use challenge::aes;
use challenge::random;
use challenge::utils;

fn usage() {
    println!("Usage: cbc_bitflip_bin <input>");
    std::process::exit(-1);
}

pub fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 2 {
        usage();
    } else {
        println!("Starting");
        cbc_bitflip_attack(&args[1]);
    }
}

fn encrypt(key: &Vec<u8>, iv: &Vec<u8>, input: &str) -> Vec<u8> {
    // quote ; and = in input
    let input = input.replace(";", "%3B").replace("=", "%3D");

    println!("quoted input: {}", input);

    // prepend + append
    let input = format!(
        "{}{}{}",
        "comment1=cooking%20MCs;userdata=", input, ";comment2=%20like%20a%20pound%20of%20bacon"
    );
    let padded = utils::pkcs_7_padding(&input.into_bytes(), 16);

    let ciphertext = aes::encrypt_128_cbc(&key, &padded, &iv, false);

    ciphertext
}

fn check_admin(input: &str) -> bool {
    let map: HashMap<_, _> = input
        .split(";")
        .into_iter()
        .map(|s| {
            let parts: Vec<&str> = s.split("=").collect();
            (parts[0], parts[1])
        })
        .collect();

    match map.get("admin") {
        Some(&"true") => true,
        _ => false,
    }
}

fn decrypt_and_verify_admin(key: &Vec<u8>, iv: &Vec<u8>, ciphertext: &Vec<u8>) -> bool {
    let plaintext = aes::decrypt_128_cbc(key, ciphertext, iv);
    println!("decrypted binary: {:?}", plaintext);
    let padded_str = String::from_utf8_lossy(&plaintext);

    println!("decrypted: {}", padded_str);
    check_admin(&padded_str)
}

fn cbc_bitflip_attack(input: &str) -> bool {
    // generate key
    let key = random::random_key(16);
    let iv = random::random_key(16);

    let mut ciphertext = encrypt(&key, &iv, &input);

    // modify ciphertext
    //
    // : = 3a = 0011 1010
    // ; = 3b = 0011 1011
    // pos 5:   0000 0001
    //
    // < = 3c  = 0011 1101
    // = = 3d  = 0011 1100
    // pos 11:   0000 0001
    //
    //
    // "comment1=cooking%20MCs;userdata="
    // "aaaaaaaaaaaaaaaa
    // "aaaaa:admin<true
    // ";comment2=%20like%20a%20pound%20of%20bacon"
    //
    ciphertext[2 * 16 + 5] ^= 0b0000_0001;
    ciphertext[2 * 16 + 11] ^= 0b0000_0001;

    let admin = decrypt_and_verify_admin(&key, &iv, &ciphertext);

    println!("Admin: {}", admin);

    admin
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_admin_1() {
        assert_eq!(true, check_admin("asdf=1;admin=true;qwerty=2"));
    }

    #[test]
    fn test_check_admin_2() {
        assert_eq!(false, check_admin("asdf=1;admin=false;qwerty=2"));
    }

    #[test]
    fn test_check_admin_3() {
        assert_eq!(false, check_admin("asdf=1;qwerty=2"));
    }

    #[test]
    fn test_cbc_bitflip_attack() {
        assert_eq!(true, cbc_bitflip_attack("aaaaaaaaaaaaaaaaaaaaa:admin<true"));
    }
}
