use oqs::sig;

pub fn concat_message(
    proofs_and_ciphertexts: &Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    r: &Vec<u8>,
    pk: &Vec<u8>,
) -> Vec<u8> {
    let mut c_i: Vec<u8> = Vec::new();
    let mut pi_i: Vec<u8> = Vec::new();

    for (_, pi, c) in proofs_and_ciphertexts {
        pi_i.append(&mut pi.clone());
        c_i.append(&mut c.clone());
    }

    c_i.append(&mut pi_i);
    c_i.append(&mut r.to_owned());
    c_i.append(&mut pk.to_owned());
    c_i
}

pub fn set_m2(
    proofs_and_ciphertexts: &Vec<(Vec<u8>, Vec<u8>, Vec<u8>)>,
    signature: sig::Signature,
    r: &[u8],
    pk: &[u8],
) -> (sig::Signature, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut c_i: Vec<u8> = Vec::new();
    let mut pi_i: Vec<u8> = Vec::new();

    for (_, pi, c) in proofs_and_ciphertexts {
        pi_i.append(&mut pi.clone());
        c_i.append(&mut c.clone());
    }

    (signature, c_i, pi_i, r.to_vec(), pk.to_vec())
}

pub fn to_verify(c_i: &Vec<u8>, pi_i: &Vec<u8>, r: &Vec<u8>, pk: &Vec<u8>) -> Vec<u8> {
    let mut res: Vec<u8> = Vec::new();

    res.append(&mut c_i.to_owned());
    res.append(&mut pi_i.to_owned());
    res.append(&mut r.to_owned());
    res.append(&mut pk.to_owned());
    res
}
