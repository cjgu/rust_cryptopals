use std::collections::HashMap;

use crate::aes;
use crate::random;
use crate::utils;

#[derive(Debug)]
pub enum CipherMode {
    CBC,
    ECB,
}

pub fn detection_oracle_random_method(ciphertext: &Vec<u8>) -> CipherMode {
    let (duplicates, chunks) = utils::count_duplicate_blocks(&ciphertext, 16);

    println!("Duplicates: {:?}", duplicates);
    println!("Chunks: {:?}", chunks);

    if duplicates > 0 {
        CipherMode::ECB
    } else {
        CipherMode::CBC
    }
}

pub fn detection_oracle_ecb_extra() {
    let key = random::random_key(16);
    // Detect block size
    // - Encrypt A, AA, AAA until ciphertext length changes
    //   block size is the difference in size.
    let mut pad_len = 0;
    let mut prev_size = 0;
    let block_size: usize;
    loop {
        let pad = vec![65; pad_len];
        let encrypted = encrypt_ecb_extra(&pad, &key);
        let cur_size = encrypted.len();
        if prev_size != 0 && prev_size != cur_size {
            block_size = cur_size - prev_size;
            break;
        }
        prev_size = cur_size;
        pad_len += 1;
    }
    println!("Detected block_size={:?}", block_size);

    // Detect ECB
    // - 2x block size of A should encrypt to two equal blocks
    let data = vec![65; block_size * 2];
    let ciphertext = encrypt_ecb_extra(&data, &key);

    if ciphertext[0..block_size] == ciphertext[block_size..block_size * 2] {
        println!("Detected ECB");
    } else {
        println!("Detected non-ECB, bailing");
        return;
    }


    let mut decrypted: Vec<u8> = Vec::with_capacity(block_size);

    let minimal = vec![0; 0];
    let encrypted = encrypt_ecb_extra(&minimal, &key);
    let num_blocks = encrypted.len() / block_size;

    let mut prev_decrypted_block: Vec<u8> = vec![65; block_size];

    for block_no in 0..num_blocks {
        let mut decrypted_block: Vec<u8> = Vec::with_capacity(block_size);

        for block_pos in 1..block_size + 1 {
            let mut dict = HashMap::new();

            let mut data = vec![0; block_size];
            for i in 0..block_size - decrypted_block.len() - 1 {
                data[i] = prev_decrypted_block[decrypted_block.len() + i + 1];
            }

            for i in 0..decrypted_block.len() {
                data[block_size - decrypted_block.len() + i - 1] = decrypted_block[i];
            }

            for last_byte in 0..256 {
                data[block_size - 1] = last_byte as u8;
                let ciphertext = encrypt_ecb_extra(&data, &key);

                dict.insert(ciphertext[0..block_size].to_vec(), last_byte as u8);
            }

            let short = vec![65; block_size - block_pos];
            let ciphertext = encrypt_ecb_extra(&short, &key);

            let block_start_pos = block_no * block_size;
            let block_end_pos = (block_no + 1) * block_size;

            if block_end_pos >= ciphertext.len() {
                // We're now extracted all bytes
                break;
            }

            let block_to_lookup = &ciphertext[block_start_pos..block_end_pos].to_vec();
            let found_block = dict.get(block_to_lookup);
            if let Some(&next_byte) = found_block {
                decrypted_block.push(next_byte);
            } else {
                panic!("Block not found, bug...");
            }
        }
        prev_decrypted_block = decrypted_block.clone();
        decrypted.extend(decrypted_block);
    }
    let extra_text = unsafe { String::from_utf8_unchecked(decrypted) };
    println!("Extra text: {:?}", extra_text);
}

pub fn detection_oracle_ecb_extra_and_random() {
    let key = random::random_key(16);

    // Detect block size
    // - Encrypt A, AA, AAA until ciphertext length changes
    //   block size is the difference in size.
    let mut pad_len = 0;
    let mut prev_size = 0;
    let block_size: usize;
    loop {
        let pad = vec![65; pad_len];
        let encrypted = encrypt_ecb_extra(&pad, &key);
        let cur_size = encrypted.len();
        if prev_size != 0 && prev_size != cur_size {
            block_size = cur_size - prev_size;
            break;
        }
        prev_size = cur_size;
        pad_len += 1;
    }
    println!("Detected block_size={:?}", block_size);

    // Detect ECB
    // - A few block size times A should encrypt to a few equal blocks
    let data = vec![65; block_size * 4];
    let ciphertext = encrypt_ecb_extra_and_random(&data, &key);

    let (duplicates, _) = utils::count_duplicate_blocks(&ciphertext, block_size);

    if duplicates > 1 {
        println!("Detected ECB, {:?} duplicates", duplicates);
    } else {
        println!("Detected non-ECB, bailing");
        return;
    }

    println!("Start extracting one byte at a time");

    let mut decrypted: Vec<u8> = Vec::with_capacity(block_size);

    let minimal = vec![0; 0];
    let encrypted = encrypt_ecb_extra_and_random(&minimal, &key);
    let num_blocks = encrypted.len() / block_size;

    let mut prev_decrypted_block: Vec<u8> = vec![65; block_size];

    for block_no in 0..num_blocks {
        println!("Working on block no {:?}", block_no);

        let mut decrypted_block: Vec<u8> = Vec::with_capacity(block_size);
        
        for block_pos in 1..block_size + 1 {
            let mut dict = HashMap::new();

            let mut data = vec![0; block_size];
            for i in 0..block_size - decrypted_block.len() - 1 {
                data[i] = prev_decrypted_block[decrypted_block.len() + i + 1];
            }

            for i in 0..decrypted_block.len() {
                data[block_size - decrypted_block.len() + i - 1] = decrypted_block[i];
            }

            for last_byte in 0..256 {
                data[block_size - 1] = last_byte as u8;
                let ciphertext = encrypt_ecb_extra_and_random(&data, &key);

                dict.insert(ciphertext[0..block_size].to_vec(), last_byte as u8);
            }

            let short = vec![65; block_size - block_pos];
            let ciphertext = encrypt_ecb_extra_and_random(&short, &key);

            let block_start_pos = block_no * block_size;
            let block_end_pos = (block_no + 1) * block_size;

            if block_end_pos > ciphertext.len() {
                // We're now extracted all bytes
                break;
            }

            let block_to_lookup = &ciphertext[block_start_pos..block_end_pos].to_vec();
            let found_block = dict.get(block_to_lookup);
            if let Some(&next_byte) = found_block {
                decrypted_block.push(next_byte);
            } else {
                // panic!("Block not found, bug...");
                continue;
            }
        }
        prev_decrypted_block = decrypted_block.clone();
        decrypted.extend(decrypted_block);
    }
    let extra_text = unsafe { String::from_utf8_unchecked(decrypted) };
    println!("Extra text: {:?}", extra_text);
}

pub fn encrypt_ecb_extra_and_random(data: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut prefix = random::random_prefix(8, 32);

    let mut extra = utils::decode_b64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

    let mut plaintext = data.clone();

    plaintext.append(&mut extra);
    prefix.append(&mut plaintext);

    aes::encrypt_128_ecb(&key, &prefix, true)
}

pub fn encrypt_ecb_extra(data: &Vec<u8>, key: &Vec<u8>) -> Vec<u8> {
    let mut extra = utils::decode_b64("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK");

    let mut plaintext = data.clone();

    plaintext.append(&mut extra);

    aes::encrypt_128_ecb(&key, &plaintext, true)
}

pub fn encrypt_random_method(data: &Vec<u8>) -> Vec<u8> {
    let key = random::random_key(16);
    assert!(key.len() == 16);

    let cipher_mode = if random::random_bool() {
        CipherMode::ECB
    } else {
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
