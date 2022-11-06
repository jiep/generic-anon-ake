use anon_sym_ake::protocol::commitment::{comm, comm_vfy};

#[test]
fn commitment_works() {
    let x: Vec<u8> = vec![1, 2, 3, 4, 5, 6];
    let (commitment, open) = comm(&x);
    assert_eq!(commitment.len(), 32);
    assert_eq!(open.len(), 32);

    let are_equal = comm_vfy(&commitment, &open, &x);
    assert_eq!(are_equal, true);
}
