use hex;
use rand::thread_rng;
use rand::Rng;

pub fn get_random_key32() -> Vec<u8> {
    let mut x = vec![0; 32];
    thread_rng()
        .try_fill(&mut x[..])
        .expect("Error while generating random number!");
    x
}

pub fn get_random_key88() -> Vec<u8> {
    let mut x = vec![0; 88];
    thread_rng()
        .try_fill(&mut x[..])
        .expect("Error while generating random number!");
    x
}

pub fn get_nonce() -> Vec<u8> {
    let mut x = vec![0; 12];
    thread_rng()
        .try_fill(&mut x[..])
        .expect("Error while generating random number!");
    x
}

pub fn print_hex(arr: &Vec<u8>, name: &str) {
    println!("{:}: 0x{:}", name, hex::encode(&arr));
}

pub fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    let z: Vec<u8> = x.iter().zip(y).map(|(a, b)| a ^ b).collect();
    z
}
