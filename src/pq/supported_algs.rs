use oqs::{kem, sig};

pub static SUPPORTED_KEMS: &[&str] = &["Kyber512", "Kyber768", "Kyber1024", "ClassicMcEliece348864f", "ClassicMcEliece460896f", "ClassicMcEliece6960119f"];

pub static SUPPORTED_SIGS: &[&str] = &["Dilithium2", "Dilithium3", "Dilithium5"];

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
        "Kyber768" => Some(kem::Kem::new(kem::Algorithm::Kyber768).unwrap()),
        "Kyber1024" => Some(kem::Kem::new(kem::Algorithm::Kyber1024).unwrap()),
        "ClassicMcEliece348864f" => Some(kem::Kem::new(kem::Algorithm::ClassicMcEliece348864f).unwrap()),
        "ClassicMcEliece460896f" => Some(kem::Kem::new(kem::Algorithm::ClassicMcEliece460896f).unwrap()),
        "ClassicMcEliece6960119f" => Some(kem::Kem::new(kem::Algorithm::ClassicMcEliece6960119f).unwrap()),
        _ => None,
    }
}

pub fn print_supported_signatures() {
    print_static_array(SUPPORTED_SIGS);
}

pub fn get_signature_algorithm(sig: &str) -> Option<sig::Sig> {
    match sig {
        "Dilithium2" => Some(sig::Sig::new(sig::Algorithm::Dilithium2).unwrap()),
        "Dilithium3" => Some(sig::Sig::new(sig::Algorithm::Dilithium3).unwrap()),
        "Dilithium5" => Some(sig::Sig::new(sig::Algorithm::Dilithium5).unwrap()),
        _ => None,
    }
}
