use std::collections::HashSet;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;

pub fn decode_hex(hex_str: &str) -> Option<Vec<u8>> {
    let len = hex_str.len();

    assert_eq!(len % 2, 0);

    let mut v: Vec<u8> = Vec::with_capacity(len / 2);

    let mut prev: u8 = 0;
    for (i, c) in hex_str.chars().enumerate() {
        match c.to_digit(16) {
            Some(x) => {
                if i % 2 == 0 {
                    prev = x as u8;
                } else {
                    v.push((prev << 4) | x as u8);
                }
            }
            None => return None,
        }
    }

    Some(v)
}

const HEX_MAP: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

pub fn encode_hex(bytes: &[u8]) -> String {
    assert!(!bytes.is_empty());
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes.iter() {
        out.push(HEX_MAP[((b & 0xF0) >> 4) as usize] as u8);
        out.push(HEX_MAP[(b & 0x0F) as usize] as u8);
    }

    unsafe { String::from_utf8_unchecked(out) }
}

const B64_MAP: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

pub fn encode_b64(bytes: &[u8]) -> String {
    let in_len = bytes.len();
    let mod_len = in_len % 3;
    let out_len = if mod_len == 0 {
        4 * in_len / 3
    } else {
        4 * (in_len / 3) + 4
    };

    let mut out: Vec<u8> = vec![b'='; out_len];

    {
        let mut s_out = out.iter_mut();

        let mut s_in = bytes[..in_len - mod_len].iter().map(|&x| x as u32);

        let mut write = |val| *s_out.next().unwrap() = val;

        while let (Some(first), Some(second), Some(third)) = (s_in.next(), s_in.next(), s_in.next())
        {
            let n = first << 16 | second << 8 | third; // 24 bits

            write(B64_MAP[((n >> 18) & 0x3F) as usize] as u8);
            write(B64_MAP[((n >> 12) & 0x3F) as usize] as u8);
            write(B64_MAP[((n >> 6) & 0x3F) as usize] as u8);
            write(B64_MAP[((n >> 0) & 0x3F) as usize] as u8);
        }

        match mod_len {
            0 => {}
            1 => {
                let n = (bytes[in_len - 1] as u32) << 16;
                write(B64_MAP[((n >> 18) & 0x3F) as usize] as u8);
                write(B64_MAP[((n >> 12) & 0x3F) as usize] as u8);
            }
            2 => {
                let n = (bytes[in_len - 2] as u32) << 16 | (bytes[in_len - 1] as u32) << 8;
                write(B64_MAP[((n >> 18) & 0x3F) as usize] as u8);
                write(B64_MAP[((n >> 12) & 0x3F) as usize] as u8);
                write(B64_MAP[((n >> 6) & 0x3F) as usize] as u8);
            }
            _ => {}
        }
    }

    unsafe { String::from_utf8_unchecked(out) }
}

fn b64_char_to_u8(c: char) -> u8 {
    let d = c as u8;
    match d {
        65..=90 => d - b'A',          // A-Z
        97..=122 => d - b'a' + 26,    // a-z
        48..=57 => d - b'0' + 2 * 26, // 0-9
        43 => 62,                     // +
        47 => 63,                     // /
        61 => 0xFF,                   // =
        _ => panic!("Invalid b64 char '{:?}'", d),
    }
}

pub fn decode_b64(b64_str: &str) -> Vec<u8> {
    assert!(b64_str.len() % 4 == 0, "b64_str need to be a multiple of 4");

    let out_len = 3 * b64_str.len() / 4;
    let mut out: Vec<u8> = Vec::with_capacity(out_len);

    {
        let mut s_in = b64_str.chars();

        while let (Some(first), Some(second), Some(third), Some(fourth)) =
            (s_in.next(), s_in.next(), s_in.next(), s_in.next())
        {
            // 4 bytes - > 3 bytes
            let c1 = b64_char_to_u8(first);
            let c2 = b64_char_to_u8(second);
            let c3 = b64_char_to_u8(third);
            let c4 = b64_char_to_u8(fourth);

            out.push(c1 << 2 | (c2 & 0x30) >> 4);

            if c3 != 0xFF {
                out.push(((c2 & 0x0F) << 4) | ((c3 >> 2) & 0xF));

                if c4 != 0xFF {
                    out.push(((c3 & 0x03) << 6) | (0x3F & c4));
                }
            }
        }
    }

    out
}

pub fn load_file(file_path: &str) -> String {
    let mut content = String::new();
    let f = File::open(file_path).expect("Unable to open file");
    let br = BufReader::new(f);
    for line in br.lines() {
        let l = line.unwrap();
        content.push_str(&l);
    }
    content
}

pub fn load_file_per_line(file_path: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let f = File::open(file_path).expect("Unable to open file");
    let br = BufReader::new(f);
    for line in br.lines() {
        let l = line.unwrap();
        lines.push(l);
    }
    lines
}

fn pad_length(data_len: usize, block_size: usize) -> usize {
    if data_len % block_size == 0 {
        block_size
    } else {
        (block_size - (data_len % block_size)) % block_size
    }
}

pub fn pkcs_7_padding(buf: &[u8], block_size: usize) -> Vec<u8> {
    let output_size = buf.len() + pad_length(buf.len(), block_size);
    let pad_char: u8 = (output_size - buf.len()) as u8;
    let mut output = buf.to_vec();
    output.resize(output_size, pad_char);

    output
}

pub fn pkcs_7_padding_validate(buf: &[u8], block_size: usize) -> Option<Vec<u8>> {
    let pad_char = buf[buf.len() - 1];

    let pad_length = pad_char as usize;

    if pad_length > block_size {
        return None;
    }

    let padding = &buf[buf.len() - pad_length..buf.len()];

    for char in padding {
        if char != &pad_char {
            return None;
        }
    }

    Some(buf[0..buf.len() - pad_length].to_vec())
}

pub fn count_duplicate_blocks(bytes: &[u8], block_size: usize) -> (u32, u32) {
    let mut duplicates = 0;
    let mut chunks = 0;
    let mut chunks_seen = HashSet::new();

    for chunk in bytes.chunks(block_size) {
        if !chunks_seen.contains(chunk) {
            chunks_seen.insert(chunk);
        } else {
            duplicates += 1;
        }
        chunks += 1;
    }
    (duplicates, chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_hex_1() {
        let input: Vec<u8> = vec![255];
        assert_eq!("ff", encode_hex(&input));
    }

    #[test]
    fn test_decode_hex_1() {
        let res: Option<Vec<u8>> = Some(vec![255]);
        assert_eq!(res, decode_hex("FF"));
        assert_eq!(res, decode_hex("ff"));
    }

    #[test]
    fn test_decode_hex_2() {
        let res: Vec<u8> = vec![0];
        assert_eq!(Some(res), decode_hex("00"));
    }

    #[test]
    fn test_decode_hex_3() {
        let res: Vec<u8> = vec![0, 255];
        assert_eq!(Some(res), decode_hex("00FF"));
    }

    #[test]
    fn test_decode_hex_4() {
        let res: Vec<u8> = vec![222, 173, 190, 239];
        assert_eq!(Some(res), decode_hex("DEADBEEF"));
    }

    #[test]
    fn test_encode_b64_1() {
        let input: Vec<u8> = vec![0, 0, 255];
        assert_eq!("AAD/", encode_b64(&input));
    }

    #[test]
    fn test_encode_b64_2() {
        let input: Vec<u8> = vec![222, 173, 190, 239];
        assert_eq!("3q2+7w==", encode_b64(&input));
    }

    #[test]
    fn test_encode_b64_3() {
        let input: Vec<u8> = vec![255, 255];
        assert_eq!("//8=", encode_b64(&input));
    }

    #[test]
    fn test_decode_hex_encode_b64() {
        // This is the test case from the web page
        let input: Vec<u8> = decode_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
        assert_eq!(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            encode_b64(&input)
        );
    }

    #[test]
    fn test_decode_hex_encode_hex() {
        let input = decode_hex("deadbeef").unwrap();
        assert_eq!("deadbeef", encode_hex(&input));
    }

    #[test]
    fn test_b64_char_to_u8() {
        assert_eq!(0, super::b64_char_to_u8('A'));
        assert_eq!(25, super::b64_char_to_u8('Z'));
        assert_eq!(26, super::b64_char_to_u8('a'));
        assert_eq!(51, super::b64_char_to_u8('z'));
        assert_eq!(52, super::b64_char_to_u8('0'));
        assert_eq!(61, super::b64_char_to_u8('9'));
        assert_eq!(62, super::b64_char_to_u8('+'));
        assert_eq!(63, super::b64_char_to_u8('/'));
        assert_eq!(0xFF, super::b64_char_to_u8('='));
    }

    #[test]
    fn test_decode_b64_1() {
        assert_eq!(vec![0, 0, 255], decode_b64("AAD/"));
    }

    #[test]
    fn test_decode_b64_2() {
        assert_eq!(vec![222, 173, 190, 239], decode_b64("3q2+7w=="));
    }

    #[test]
    fn test_decode_b64_3() {
        assert_eq!(vec![255, 255], decode_b64("//8="));
    }

    #[test]
    fn test_decode_b64_4() {
        // This is the test case from the web page
        let output: Vec<u8> = decode_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d").unwrap();
        assert_eq!(
            output,
            decode_b64("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",)
        );
    }

    #[test]
    fn test_pad_length() {
        assert_eq!(16, pad_length(16, 16));
        assert_eq!(1, pad_length(15, 16));
        assert_eq!(15, pad_length(17, 16));
        assert_eq!(12, pad_length(20, 16));
        assert_eq!(16, pad_length(32, 16));
        assert_eq!(1, pad_length(32, 1));
    }

    #[test]
    fn test_pkcs_7_pad_20() {
        let input = b"YELLOW SUBMARINE".to_vec();
        assert_eq!(
            b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec(),
            pkcs_7_padding(&input, 20)
        )
    }

    #[test]
    fn test_pkcs_7_pad_16() {
        let input = b"YELLOW SUBMARINE".to_vec();
        assert_eq!(
            b"YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
                .to_vec(),
            pkcs_7_padding(&input, 16)
        )
    }

    #[test]
    fn test_pkcs_7_validate_1_valid() {
        let input = b"ICE ICE BABY\x04\x04\x04\x04".to_vec();
        let expected = b"ICE ICE BABY".to_vec();

        assert_eq!(expected, pkcs_7_padding_validate(&input, 16).unwrap());
    }

    #[test]
    fn test_pkcs_7_validate_2_invalid() {
        let input = b"ICE ICE BABY\x05\x05\x05\x05".to_vec();
        assert!(pkcs_7_padding_validate(&input, 16).is_none());
    }

    #[test]
    fn test_pkcs_7_validate_3_invalid() {
        let input = b"ICE ICE BABY\x01\x02\x03\x04".to_vec();
        assert!(pkcs_7_padding_validate(&input, 16).is_none());
    }

    #[test]
    fn test_pkcs_7_validate_4_invalid() {
        let input = b"ICE ICE BABY\x01\x02\x03\x40".to_vec();
        assert!(pkcs_7_padding_validate(&input, 16).is_none());
    }
}
