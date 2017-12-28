extern crate rand;

mod random;
mod utils;


pub fn main() {
    let key = random::random_key(16);

    println!("Key: {:?}", utils::encode_hex(&key));
}
