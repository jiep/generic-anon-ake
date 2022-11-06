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

pub fn to_hex(arr: &Vec<u8>) -> String {
    hex::encode(arr)
}

pub fn print_hex(arr: &Vec<u8>, name: &str) {
    println!("{:} 0x{:}", name, to_hex(arr));
}

pub fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    let z: Vec<u8> = x.iter().zip(y).map(|(a, b)| a ^ b).collect();
    z
}

#[cfg(test)]
mod tests {
    use crate::protocol::utils::{get_nonce, get_random_key32, get_random_key88, to_hex, xor};

    #[test]
    fn get_random_key32_works() {
        let key = get_random_key32();

        assert_eq!(key.len(), 32);
        assert_ne!(key, vec![0u8, 32]);
    }

    #[test]
    fn get_random_key88_works() {
        let key = get_random_key88();

        assert_eq!(key.len(), 88);
        assert_ne!(key, vec![0u8, 88]);
    }

    #[test]
    fn get_nonce_works() {
        let key = get_nonce();

        assert_eq!(key.len(), 12);
        assert_ne!(key, vec![0u8, 12]);
    }

    #[test]
    fn xor_works() {
        let x: Vec<u8> = vec![81, 123, 255, 0, 48, 72];
        let y: Vec<u8> = vec![70, 18, 15, 6, 91, 48];

        let z: Vec<u8> = xor(&x, &y);

        let t: Vec<u8> = xor(&z, &y);
        assert_eq!(z.len(), 6);

        assert_eq!(z, vec![23, 105, 240, 6, 107, 120]);

        assert_eq!(t, x);

        assert_eq!(xor(&y, &y), [0u8; 6]);
    }

    #[test]
    fn to_hex_works() {
        let x: Vec<u8> = vec![81, 123, 255, 0, 48, 72];

        let res: String = to_hex(&x);
        assert_eq!(res, "517bff003048");
    }
}
