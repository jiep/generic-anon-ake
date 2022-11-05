use oqs::{kem, sig};

static SUPPORTED_KEMS: &[&str] = &[
    "Kyber512",
    "Kyber512_90s",
    "Kyber768",
    "Kyber768_90s",
    "Kyber1024",
    "Kyber1024_90s",
];

static SUPPORTED_SIGS: &[&str] = &[
    "Dilithium2",
    "Dilithium3",
    "Dilithium5",
    "Falcon512",
    "Falcon1024",
    "SphincsHaraka128fRobust",
    "SphincsHaraka128fSimple",
    "SphincsHaraka128sRobust",
    "SphincsHaraka128sSimple",
    "SphincsHaraka192fRobust",
    "SphincsHaraka192fSimple",
    "SphincsHaraka192sRobust",
    "SphincsHaraka192sSimple",
    "SphincsHaraka256fRobust",
    "SphincsHaraka256fSimple",
    "SphincsHaraka256sRobust",
    "SphincsHaraka256sSimple",
    "SphincsSha256128fRobust",
    "SphincsSha256128fSimple",
    "SphincsSha256128sRobust",
    "SphincsSha256128sSimple",
    "SphincsSha256192fRobust",
    "SphincsSha256192fSimple",
    "SphincsSha256192sRobust",
    "SphincsSha256192sSimple",
    "SphincsSha256256fRobust",
    "SphincsSha256256fSimple",
    "SphincsSha256256sRobust",
    "SphincsSha256256sSimple",
    "SphincsShake256128fRobust",
    "SphincsShake256128fSimple",
    "SphincsShake256128sRobust",
    "SphincsShake256128sSimple",
    "SphincsShake256192fRobust",
    "SphincsShake256192fSimple",
    "SphincsShake256192sRobust",
    "SphincsShake256192sSimple",
    "SphincsShake256256fRobust",
    "SphincsShake256256fSimple",
    "SphincsShake256256sRobust",
    "SphincsShake256256sSimple",
];

fn print_static_array(arr: &'static [&str]) {
    for elem in arr {
        println!("[!] * {}", elem);
    }
}

pub fn print_supported_kems() {
    print_static_array(SUPPORTED_KEMS);
}

pub fn print_supported_signatures() {
    print_static_array(SUPPORTED_SIGS);
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

pub fn get_signature_algorithm(sig: &str) -> Option<sig::Sig> {
    match sig {
        "Dilithium2" => Some(sig::Sig::new(sig::Algorithm::Dilithium2).unwrap()),
        "Dilithium3" => Some(sig::Sig::new(sig::Algorithm::Dilithium3).unwrap()),
        "Dilithium5" => Some(sig::Sig::new(sig::Algorithm::Dilithium5).unwrap()),
        "Falcon512" => Some(sig::Sig::new(sig::Algorithm::Falcon512).unwrap()),
        "Falcon1024" => Some(sig::Sig::new(sig::Algorithm::Falcon1024).unwrap()),
        "SphincsHaraka128fRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka128fRobust).unwrap())
        }
        "SphincsHaraka128fSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka128fSimple).unwrap())
        }
        "SphincsHaraka128sRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka128sRobust).unwrap())
        }
        "SphincsHaraka128sSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka128sSimple).unwrap())
        }
        "SphincsHaraka192fRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka192fRobust).unwrap())
        }
        "SphincsHaraka192fSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka192fSimple).unwrap())
        }
        "SphincsHaraka192sRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka192sRobust).unwrap())
        }
        "SphincsHaraka192sSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka192sSimple).unwrap())
        }
        "SphincsHaraka256fRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka256fRobust).unwrap())
        }
        "SphincsHaraka256fSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka256fSimple).unwrap())
        }
        "SphincsHaraka256sRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka256sRobust).unwrap())
        }
        "SphincsHaraka256sSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsHaraka256sSimple).unwrap())
        }
        "SphincsSha256128fRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsSha256128fRobust).unwrap())
        }
        "SphincsSha256128fSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsSha256128fSimple).unwrap())
        }
        "SphincsSha256128sRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsSha256128sRobust).unwrap())
        }
        "SphincsSha256128sSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsSha256128sSimple).unwrap())
        }
        "SphincsSha256192fRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsSha256192fRobust).unwrap())
        }
        "SphincsSha256192fSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsSha256192fSimple).unwrap())
        }
        "SphincsSha256192sRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsSha256192sRobust).unwrap())
        }
        "SphincsSha256192sSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsSha256192sSimple).unwrap())
        }
        "SphincsSha256256fRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsSha256256fRobust).unwrap())
        }
        "SphincsSha256256fSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsSha256256fSimple).unwrap())
        }
        "SphincsSha256256sRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsSha256256sRobust).unwrap())
        }
        "SphincsSha256256sSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsSha256256sSimple).unwrap())
        }
        "SphincsShake256128fRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsShake256128fRobust).unwrap())
        }
        "SphincsShake256128fSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsShake256128fSimple).unwrap())
        }
        "SphincsShake256128sRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsShake256128sRobust).unwrap())
        }
        "SphincsShake256128sSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsShake256128sSimple).unwrap())
        }
        "SphincsShake256192fRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsShake256192fRobust).unwrap())
        }
        "SphincsShake256192fSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsShake256192fSimple).unwrap())
        }
        "SphincsShake256192sRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsShake256192sRobust).unwrap())
        }
        "SphincsShake256192sSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsShake256192sSimple).unwrap())
        }
        "SphincsShake256256fRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsShake256256fRobust).unwrap())
        }
        "SphincsShake256256fSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsShake256256fSimple).unwrap())
        }
        "SphincsShake256256sRobust" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsShake256256sRobust).unwrap())
        }
        "SphincsShake256256sSimple" => {
            Some(sig::Sig::new(sig::Algorithm::SphincsShake256256sSimple).unwrap())
        }
        _ => None,
    }
}
