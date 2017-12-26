use openssl::symm;

use xor::xor;
use utils::pkcs_7_padding;

pub fn decrypt_128_ecb(key: &Vec<u8>, data: &Vec<u8>, pad: bool) -> Vec<u8> {
    assert!(key.len() == 16);
    assert!(
        pad == true || data.len() % 16 == 0,
        "Data must be multiple of 16 bytes if not padding is enabled"
    );

    let mut c =
        symm::Crypter::new(symm::Cipher::aes_128_ecb(), symm::Mode::Decrypt, &key, None).unwrap();
    c.pad(pad);

    let mut plaintext = vec![0; data.len() + symm::Cipher::aes_128_ecb().block_size()];
    let count = c.update(&data, &mut plaintext).unwrap();
    let rest = c.finalize(&mut plaintext[count..]).unwrap();
    plaintext.truncate(count + rest);

    plaintext
}

pub fn encrypt_128_ecb(key: &Vec<u8>, data: &Vec<u8>, pad: bool) -> Vec<u8> {
    assert!(key.len() == 16, "Key must have length 16 bytes");
    assert!(
        pad == true || data.len() % 16 == 0,
        "Data must be multiple of 16 bytes if not padding is enabled"
    );
    let mut c =
        symm::Crypter::new(symm::Cipher::aes_128_ecb(), symm::Mode::Encrypt, &key, None).unwrap();
    c.pad(pad);

    let mut ciphertext = vec![0; data.len() + symm::Cipher::aes_128_ecb().block_size()];
    let count = c.update(&data, &mut ciphertext).unwrap();
    let rest = c.finalize(&mut ciphertext[count..]).unwrap();
    ciphertext.truncate(count + rest);

    ciphertext
}

pub fn encrypt_128_cbc(key: &Vec<u8>, data: &Vec<u8>, iv: &Vec<u8>, pad: bool) -> Vec<u8> {
    assert!(iv.len() == 16, "IV must have length 16 bytes");
    assert!(key.len() == 16, "Key must have length 16 bytes");
    assert!(
        pad == true || data.len() % 16 == 0,
        "Data must be multiple of 16 bytes or padding must be enabled"
    );

    let mut prev = iv.clone();

    let mut output = Vec::new();

    let plaintext: Vec<u8>;
    if pad {
        plaintext = pkcs_7_padding(&data, 16);
    } else {
        plaintext = data.clone();
    }

    assert!(plaintext.len() % 16 == 0);

    for chunk in plaintext.chunks(16) {
        assert!(chunk.len() == 16);
        assert!(prev.len() == 16);
        let mixed = xor(&chunk.to_vec(), &prev);
        assert!(mixed.len() == 16);
        let encrypted = encrypt_128_ecb(key, &mixed, false);
        assert!(encrypted.len() == 16);

        output.extend_from_slice(&encrypted);

        prev = encrypted;
    }

    output
}

pub fn decrypt_128_cbc(key: &Vec<u8>, data: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    assert!(iv.len() == 16, "IV must have length 16 bytes");
    assert!(key.len() == 16, "Key must have length 16 bytes");
    assert!(data.len() % 16 == 0, "Data must be multiple of 16 bytes");

    let mut prev = iv.clone();

    let mut output = Vec::new();

    for chunk in data.chunks(16) {
        let decrypted = decrypt_128_ecb(&key, &chunk.to_vec(), false);
        let mixed = xor(&decrypted, &prev);

        output.extend_from_slice(&mixed);

        prev = chunk.to_vec();
    }

    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_ecb() {
        let key: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6];
        let input: Vec<u8> = vec![255, 0, 128, 0, 64, 0, 32, 0, 255, 1, 128, 2, 64, 3, 32, 4];
        assert_eq!(input.len(), 16);
        let encrypted = encrypt_128_ecb(&key, &input, false);

        assert_eq!(encrypted.len(), 16);
        let decrypted = decrypt_128_ecb(&key, &encrypted, false);

        assert_eq!(input, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_ecb_multiple_blocks_no_pad() {
        let key: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6];
        let input: Vec<u8> = vec![255, 0, 128, 0, 64, 0, 32, 0, 255, 1, 128, 2, 64, 3, 32, 4, 255, 0, 128, 0, 64, 0, 32, 0, 255, 1, 128, 2, 64, 3, 32, 4];
        assert_eq!(input.len(), 32);
        let encrypted = encrypt_128_ecb(&key, &input, false);

        assert_eq!(encrypted.len(), 32);
        let decrypted = decrypt_128_ecb(&key, &encrypted, false);

        assert_eq!(input, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_ecb_multiple_blocks_pad() {
        let key: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6];
        let input: Vec<u8> = vec![255, 0, 128, 0, 64, 0, 32, 0, 255, 1, 128, 2, 64, 3, 32, 4, 255, 0, 128, 0, 64, 0, 32, 0, 255, 1, 128, 2, 64, 3, 32, 4, 1];
        assert_eq!(input.len(), 33);
        let encrypted = encrypt_128_ecb(&key, &input, true);

        assert_eq!(encrypted.len(), 48);
        let decrypted = decrypt_128_ecb(&key, &encrypted, true);
        assert_eq!(decrypted.len(), 33);

        assert_eq!(input, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_cbc() {
        let key: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6];
        let input: Vec<u8> = vec![
            255, 0, 128, 0, 64, 0, 32, 0, 255, 1, 128, 2, 64, 3, 32, 4, 255, 254, 253, 252, 251,
            250, 249, 248, 1, 2, 3, 4, 5, 6, 7, 8,
        ];
        let iv: Vec<u8> = vec![0; 16];

        let encrypted = encrypt_128_cbc(&key, &input, &iv, false);
        let decrypted = decrypt_128_cbc(&key, &encrypted, &iv);

        assert_eq!(input, decrypted);
    }
}
