use aes;
use random;
use utils;

#[derive(Debug)]
pub enum CipherMode {
    CBC,
    ECB,
}

pub fn detection_oracle(ciphertext: &Vec<u8>) -> CipherMode {
    let (duplicates, chunks) = utils::count_duplicate_blocks(&ciphertext, 16);

    println!("Duplicates: {:?}", duplicates);
    println!("Chunks: {:?}", chunks);

    if duplicates > 0 {
        CipherMode::ECB
    } else {
        CipherMode::CBC
    }
}

pub fn encrypt_randomly(data: &Vec<u8>) -> Vec<u8> {
    let key = random::random_key(16);
    assert!(key.len() == 16);

    let cipher_mode =
        if random::random_bool() {
            CipherMode::ECB
        }
        else {
            CipherMode::CBC
        };

    let mut prefix = random::random_prefix(5, 10);
    let mut postfix = random::random_prefix(5, 10);

    let mut plaintext = data.clone();

    prefix.append(&mut plaintext);
    prefix.append(&mut postfix);

    println!("Random method: {:?}", cipher_mode);

    match cipher_mode {
        CipherMode::ECB => aes::encrypt_128_ecb(&key, &prefix, true),
        CipherMode::CBC => {
            let iv = random::random_key(16);
            aes::encrypt_128_cbc(&key, &prefix, &iv, true)
        }
    }
}
