use rayon::prelude::*;
use tfhe::integer::{RadixCiphertext, ServerKey};

use crate::BigInt;

pub fn vec_mul_vec(k: &ServerKey, m: &[RadixCiphertext], v: &[BigInt]) -> RadixCiphertext {
    let v: Vec<_> = m
        .par_iter()
        .zip(v)
        .map(|(a, b)| k.scalar_mul_parallelized(a, *b))
        .collect();
    k.unchecked_sum_ciphertexts_vec_parallelized(v).unwrap()
}

pub fn mat_mul_vec(
    k: &ServerKey,
    m: &[Vec<RadixCiphertext>],
    v: &[BigInt],
) -> Vec<RadixCiphertext> {
    m.par_iter().map(|row| vec_mul_vec(k, row, v)).collect()
}
