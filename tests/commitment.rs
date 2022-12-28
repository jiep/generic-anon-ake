use anon_sym_ake::pq::commitment::{comm, comm_vfy};

#[test]
fn commitment_works() {
    let x: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
    let (commitment, open) = comm(&x);
    let (x, r) = open.clone();
    assert_eq!(commitment.len(), 32);
    assert_eq!(r.len(), 32);
    assert_eq!(x.len(), 6);

    let are_equal = comm_vfy(&commitment, &open);
    assert_eq!(are_equal, true);
}
