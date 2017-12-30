extern crate blake2_rfc;
extern crate byteorder;
extern crate libc;
extern crate sapling_crypto;
extern crate pairing;

#[macro_use]
extern crate lazy_static;

use pairing::{
    BitIterator,
    PrimeFieldRepr,
    PrimeField,
    bls12_381::{
        Bls12,
        Fr,
        FrRepr
    }
};

use sapling_crypto::{
    jubjub::JubjubBls12,
    pedersen_hash::{
        pedersen_hash,
        Personalization
    }
};

use libc::{c_uchar, size_t, uint32_t, uint64_t};
use std::slice;

pub mod equihash;

lazy_static! {
    static ref JUBJUB: JubjubBls12 = {
        JubjubBls12::new()
    };
}

#[no_mangle]
pub extern "system" fn librustzcash_tree_uncommitted(
    result: *mut [c_uchar; 32]
)
{
    let tmp = sapling_crypto::primitives::Note::<Bls12>::uncommitted().into_repr();

    // Should be okay, caller is responsible for ensuring the pointer
    // is a valid pointer to 32 bytes that can be mutated.
    let result = unsafe { &mut *result };

    tmp.write_be(&mut result[..]).unwrap();
}

#[no_mangle]
pub extern "system" fn librustzcash_merkle_hash(
    depth: size_t,
    a: *const [c_uchar; 32],
    b: *const [c_uchar; 32],
    result: *mut [c_uchar; 32],
)
{
    let mut a_repr = FrRepr::default();
    let mut b_repr = FrRepr::default();

    // Should be okay, because caller is responsible for ensuring
    // the pointer is a valid pointer to 32 bytes, and that is the
    // size of the representation
    a_repr.read_be(unsafe { &(&*a)[..] }).unwrap();

    // Should be okay, because caller is responsible for ensuring
    // the pointer is a valid pointer to 32 bytes, and that is the
    // size of the representation
    b_repr.read_be(unsafe { &(&*b)[..] }).unwrap();

    let mut lhs = [false; 256];
    let mut rhs = [false; 256];

    for (a, b) in lhs.iter_mut().rev().zip(BitIterator::new(a_repr)) {
        *a = b;
    }

    for (a, b) in rhs.iter_mut().rev().zip(BitIterator::new(b_repr)) {
        *a = b;
    }
    
    let tmp = pedersen_hash::<Bls12, _>(
        Personalization::MerkleTree(depth),
        lhs.iter().map(|&x| x)
            .take(Fr::NUM_BITS as usize)
            .chain(rhs.iter().map(|&x| x).take(Fr::NUM_BITS as usize)),
        &JUBJUB
    ).into_xy().0.into_repr();

    // Should be okay, caller is responsible for ensuring the pointer
    // is a valid pointer to 32 bytes that can be mutated.
    let result = unsafe { &mut *result };

    tmp.write_be(&mut result[..]).unwrap();
}

/// XOR two uint64_t values and return the result, used
/// as a temporary mechanism for introducing Rust into
/// Zcash.
#[no_mangle]
pub extern "system" fn librustzcash_xor(a: uint64_t, b: uint64_t) -> uint64_t {
    a ^ b
}

#[no_mangle]
pub extern "system" fn librustzcash_eh_isvalid(
    n: uint32_t,
    k: uint32_t,
    input: *const c_uchar,
    input_len: size_t,
    nonce: *const c_uchar,
    nonce_len: size_t,
    soln: *const c_uchar,
    soln_len: size_t,
) -> bool {
    if (k >= n) || (n % 8 != 0) || (soln_len != (1 << k) * ((n / (k + 1)) as usize + 1) / 8) {
        return false;
    }
    let rs_input = unsafe { slice::from_raw_parts(input, input_len) };
    let rs_nonce = unsafe { slice::from_raw_parts(nonce, nonce_len) };
    let rs_soln = unsafe { slice::from_raw_parts(soln, soln_len) };
    equihash::is_valid_solution(n, k, rs_input, rs_nonce, rs_soln)
}

#[test]
fn test_xor() {
    assert_eq!(
        librustzcash_xor(0x0f0f0f0f0f0f0f0f, 0x1111111111111111),
        0x1e1e1e1e1e1e1e1e
    );
}
