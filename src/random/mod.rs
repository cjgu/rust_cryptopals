use rand::{OsRng, Rng};

pub fn random_key(size: usize) -> Vec<u8> {
    let mut key = vec![0; size];
    let mut rng = OsRng::new().expect("Cant load random");
    rng.fill_bytes(&mut key);

    key
}

pub fn random_bool() -> bool {
    let mut rng = OsRng::new().expect("Cant load random");
    rng.gen_weighted_bool(2)
}

pub fn random_prefix(min: usize, max: usize) -> Vec<u8> {
    let mut rng = OsRng::new().expect("Cant load random");

    let len = rng.gen_range(min, max);

    let mut prefix = vec![0; len];

    rng.fill_bytes(&mut prefix);

    prefix
}
