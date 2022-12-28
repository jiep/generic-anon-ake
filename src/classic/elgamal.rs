use secp256kfun::{g, marker::*, Point, Scalar, G};

pub fn pke_gen() -> (Point<NonNormal>, secp256kfun::Scalar) {
    let sk = Scalar::random(&mut rand::thread_rng());
    let pk = g!(sk * G);

    (pk, sk)
}

pub fn pke_enc(
    pk: &Point<NonNormal>,
    m: Vec<u8>,
    r: Vec<u8>,
) -> (
    Point<secp256kfun::marker::NonNormal, Public, secp256kfun::marker::Zero>,
    Point<secp256kfun::marker::NonNormal, Public, secp256kfun::marker::Zero>,
) {
    let r: [u8; 32] = r.try_into().unwrap();
    let r: secp256kfun::Scalar<Secret, secp256kfun::marker::Zero> = Scalar::from_bytes(r).unwrap();
    let m: [u8; 32] = m.try_into().unwrap();
    let m: Point<EvenY> = Point::from_xonly_bytes(m).unwrap();
    let y1 = g!(r * G);
    let y2 = g!(r * pk + m);

    (y1, y2)
}

pub fn pke_dec(sk: &secp256kfun::Scalar, ct: &(Point<NonNormal>, Point<NonNormal>)) -> [u8; 33] {
    let (y1, y2) = ct;
    let m = g!(-sk * y1 + y2);
    let m = m.normalize();
    m.to_bytes()
}
