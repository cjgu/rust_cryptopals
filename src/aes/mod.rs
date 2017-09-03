use openssl::symm;

use utils::pkcs_7_padding;
use xor::xor;

pub fn decrypt_128_ecb(key: &Vec<u8>, data: &Vec<u8>) -> Vec<u8> {
    let plaintext = symm::decrypt(symm::Cipher::aes_128_ecb(),
                                  &key,
                                  None,
                                  &data).unwrap();
    plaintext
}

pub fn encrypt_128_ecb(key: &Vec<u8>, data: &Vec<u8>) -> Vec<u8> {
    let ciphertext = symm::encrypt(symm::Cipher::aes_128_ecb(),
                                  &key,
                                  None,
                                  &data).unwrap();
    ciphertext
}

pub fn encrypt_128_cbc(key: &Vec<u8>, data: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    assert!(iv.len() == 16);

    let bytes = pkcs_7_padding(data, 16);

    let mut prev = iv.clone();

    let mut output = Vec::new();

    for chunk in bytes.chunks(16)  {
        let mixed = xor(&chunk.to_vec(), &prev);
        let encrypted = encrypt_128_ecb(key, &mixed);

        output.extend_from_slice(&encrypted);

        prev = encrypted;
    }

    output
}
