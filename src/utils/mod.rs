use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::io::BufRead;

pub fn decode_hex(hex_str: &str) -> Option<Vec<u8>> {
    let len = hex_str.len();

    assert_eq!(len % 2, 0);

    let mut v: Vec<u8> = Vec::with_capacity(len/2);

    let mut prev: u8 = 0;
    for (i, c) in hex_str.chars().enumerate() {
        match c.to_digit(16) {
            Some(x) => {
                if i % 2 == 0 {
                    prev = x as u8;
                }
                else {
                    v.push((prev << 4) | x as u8);
                }
            },
            None => {
                return None
            }
        }
    }

    Some(v)
}

const HEX_MAP: [char; 16] = [
    '0', '1', '2', '3',
    '4', '5', '6', '7',
    '8', '9', 'a', 'b',
    'c', 'd', 'e', 'f',
];

pub fn encode_hex(bytes: &Vec<u8>) -> String {
    assert!(bytes.len() > 0);
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes.iter() {
        out.push(HEX_MAP[((b & 0xF0) >> 4) as usize] as u8);
        out.push(HEX_MAP[(b & 0x0F) as usize] as u8);
    }

    unsafe { String::from_utf8_unchecked(out) }
}

const B64_MAP: [char; 64] = [
  'A', 'B', 'C', 'D', 'E',
  'F', 'G', 'H', 'I', 'J',
  'K', 'L', 'M', 'N', 'O',
  'P', 'Q', 'R', 'S', 'T',
  'U', 'V', 'W', 'X', 'Y',
  'Z', 'a', 'b', 'c', 'd',
  'e', 'f', 'g', 'h', 'i',
  'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's',
  't', 'u', 'v', 'w', 'x',
  'y', 'z', '0', '1', '2',
  '3', '4', '5', '6', '7',
  '8', '9', '+', '/'
];


pub fn encode_b64(bytes: &Vec<u8>) -> String {
    let in_len = bytes.len();
    let out_len: usize;

    let mod_len = in_len % 3;
    if mod_len == 0 {
        out_len = 4 * in_len / 3;
    } else {
        out_len = 4 * (in_len / 3) + 4;
    }

    let mut out: Vec<u8> = vec![b'='; out_len];

    {
        let mut s_out = out.iter_mut();

        let mut s_in = bytes[..in_len - mod_len].iter().map(|&x| x as u32);

        let mut write = |val| *s_out.next().unwrap() = val;

        while let (Some(first), Some(second), Some(third)) =
            (s_in.next(), s_in.next(), s_in.next()) {

            let n = first << 16 | second << 8 | third;  // 24 bits

            write(B64_MAP[((n >> 18) & 0x3F) as usize] as u8);
            write(B64_MAP[((n >> 12) & 0x3F) as usize] as u8);
            write(B64_MAP[((n >> 6) & 0x3F) as usize] as u8);
            write(B64_MAP[((n >> 0) & 0x3F) as usize] as u8);
        }

        match mod_len {
            0 => {},
            1 => {
                let n =  (bytes[in_len - 1] as u32) << 16;
                write(B64_MAP[((n >> 18) & 0x3F) as usize] as u8);
                write(B64_MAP[((n >> 12) & 0x3F) as usize] as u8);
            },
            2 => {
                let n = (bytes[in_len - 2] as u32) << 16 |
                        (bytes[in_len - 1] as u32) << 8;
                write(B64_MAP[((n >> 18) & 0x3F) as usize] as u8);
                write(B64_MAP[((n >> 12) & 0x3F) as usize] as u8);
                write(B64_MAP[((n >> 6) & 0x3F) as usize] as u8);
            },
            _ => {}
        }
    }

    unsafe { String::from_utf8_unchecked(out) }
}

fn b64_char_to_u8(c: char) -> u8 {
    let d = c as u8;
    match d {
        65 ... 90 => d - ('A' as u8), // A-Z
        97 ... 122 => d - ('a' as u8) + 26, // a-z
        48 ... 57 => d - ('0' as u8) + 2*26, // 0-9
        43 => 62,  // +
        47 => 63,  // /
        61 => 0xFF,  // =
        _ => panic!("Invalid b64 char")
    }
}

pub fn decode_b64(b64_str: &str) -> Vec<u8> {
    assert!(b64_str.len() % 4 == 0, "b64_str need to be a multiple of 4");

    let out_len = 3 * b64_str.len() / 4;
    let mut out: Vec<u8> = Vec::with_capacity(out_len);

    let mut byte_count = 0;
    {
        let mut s_in = b64_str.chars();

        while let (Some(first), Some(second), Some(third), Some(fourth)) =
            (s_in.next(), s_in.next(), s_in.next(), s_in.next()) {

            // 4 bytes - > 3 bytes
            let c1 = b64_char_to_u8(first);
            let c2 = b64_char_to_u8(second);
            let c3 = b64_char_to_u8(third);
            let c4 = b64_char_to_u8(fourth);

            out.push(c1 << 2 | (c2 & 0x30) >> 4);
            byte_count += 1;

            if c3 != 0xFF {
                out.push(((c2 & 0x0F) << 4) | ((c3 >> 2) & 0xF));
                byte_count += 1;

                if c4 != 0xFF {
                    out.push(((c3 & 0x03) << 6) | (0x3F & c4));
                    byte_count += 1;
                }
            }
        }
    }

    out
}

pub fn load_file(file_path: &str) -> String {
    let mut content = String::new();
    let f = File::open(file_path).expect("Unable to open file");
    let mut br = BufReader::new(f);
    for line in br.lines() {
        let l = line.unwrap();
        content.push_str(&l);
    }
    content
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
        assert_eq!(Some(res),decode_hex("00"));
    }

    #[test]
    fn test_decode_hex_3() {
        let res: Vec<u8> = vec![0, 255];
        assert_eq!(Some(res),decode_hex("00FF"));
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
        assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", 
                   encode_b64(&input));
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
        assert_eq!(output, decode_b64("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"));
    }

}
