use oqs::kem;

pub static SUPPORTED_KEMS: &[&str] = &[
    "Kyber512",
    "Kyber512_90s",
    "Kyber768",
    "Kyber768_90s",
    "Kyber1024",
    "Kyber1024_90s",
];

fn print_static_array(arr: &'static [&str]) {
    for elem in arr {
        println!("[!] * {}", elem);
    }
}

pub fn print_supported_kems() {
    print_static_array(SUPPORTED_KEMS);
}

pub fn get_kem_algorithm(kem: &str) -> Option<kem::Kem> {
    match kem {
        "Kyber512" => Some(kem::Kem::new(kem::Algorithm::Kyber512).unwrap()),
        "Kyber512_90s" => Some(kem::Kem::new(kem::Algorithm::Kyber512_90s).unwrap()),
        "Kyber768" => Some(kem::Kem::new(kem::Algorithm::Kyber768).unwrap()),
        "Kyber768_90s" => Some(kem::Kem::new(kem::Algorithm::Kyber768_90s).unwrap()),
        "Kyber1024" => Some(kem::Kem::new(kem::Algorithm::Kyber1024).unwrap()),
        "Kyber1024_90s" => Some(kem::Kem::new(kem::Algorithm::Kyber1024_90s).unwrap()),
        _ => None,
    }
}
