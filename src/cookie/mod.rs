use crate::aes;

#[derive(Debug)]
pub struct KV {
    key: String,
    value: String,
}

pub fn parse_querystring(querystring: &str) -> Vec<KV> {
    let parts: Vec<&str> = querystring.split('&').collect();

    parts
        .into_iter()
        .map(|part| {
            let part_list: Vec<&str> = part.split('=').collect();
            KV {
                key: part_list[0].to_string(),
                value: part_list[1].to_string(),
            }
        })
        .collect()
}

pub fn encode_querystring(items: Vec<KV>) -> String {
    items
        .into_iter()
        .map(|item| format!("{}={}", item.key, item.value))
        .collect::<Vec<String>>()
        .join("&")
}

pub fn profile_for(email: &str) -> String {
    let scrubbed_email = email.replace("=", "").replace("&", "");
    let items = vec![
        KV {
            key: "email".to_string(),
            value: scrubbed_email.to_string(),
        },
        KV {
            key: "uid".to_string(),
            value: "10".to_string(),
        },
        KV {
            key: "role".to_string(),
            value: "user".to_string(),
        },
    ];

    encode_querystring(items)
}

pub fn encrypt_cookie(email: &str, key: &[u8]) -> Vec<u8> {
    let profile = profile_for(email);
    println!("Profile: {:?}", profile);
    let profile_bytes = profile.into_bytes();

    aes::encrypt_128_ecb(key, &profile_bytes, true)
}

pub fn decrypt_cookie(cookie: Vec<u8>, key: &[u8]) -> Vec<KV> {
    let encoded = aes::decrypt_128_ecb(key, &cookie, true);
    let querystring = String::from_utf8(encoded).expect("Invalid string");
    parse_querystring(&querystring)
}
