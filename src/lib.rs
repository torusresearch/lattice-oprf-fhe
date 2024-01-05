use digest::Digest;
use rayon::prelude::*;
use tfhe::core_crypto::commons::math::random::{ActivatedRandomGenerator, RandomGenerator};
use tfhe::core_crypto::seeders::new_seeder;
use tfhe::integer::bigint::static_unsigned::StaticUnsignedBigInt;
use tfhe::integer::{gen_keys_radix, RadixCiphertext, RadixClientKey, ServerKey};
use tfhe::shortint::parameters::PARAM_MESSAGE_2_CARRY_2_KS_PBS;
use tfhe::shortint::ClassicPBSParameters;
use vec::mat_mul_vec;

mod vec;

// PRF parameters.
const LATTICE_DIM: usize = 8; // 512;
const LOG2Q: usize = 12;
const LOG2P: usize = 8;
const OUT_LEN: usize = 16;

// FHE parameters.
const FHE_PARAMS: ClassicPBSParameters = PARAM_MESSAGE_2_CARRY_2_KS_PBS;
const NUM_BLOCKS: usize = LOG2Q / FHE_PARAMS.message_modulus.0.ilog2() as usize;

// Derived constants.
const Q_BYTES: usize = LOG2Q.div_ceil(u8::BITS as usize);
const P_BYTES: usize = LOG2P.div_ceil(u8::BITS as usize);

pub fn generate_fhe_keys() -> (RadixClientKey, ServerKey) {
    gen_keys_radix(PARAM_MESSAGE_2_CARRY_2_KS_PBS, NUM_BLOCKS)
}

pub fn generate_prf_key(k: &ServerKey) -> Vec<RadixCiphertext> {
    // Initialize PRNG.
    let mut seeder = new_seeder();
    let seed = seeder.seed();
    let mut rng = RandomGenerator::<ActivatedRandomGenerator>::new(seed);

    let mut bytes = [0u8; 32];
    rng.fill_slice_with_random_uniform(&mut bytes);

    (0..LATTICE_DIM)
        .map(|_| {
            // Generate random value in 0..q.
            const SIZE: usize = Q_BYTES.div_ceil((u64::BITS / u8::BITS) as usize);
            let mut buf = [0u8; SIZE * (u64::BITS / u8::BITS) as usize];
            rng.fill_slice_with_random_uniform(&mut buf);

            let mut r = StaticUnsignedBigInt::<SIZE>::default();
            r.copy_from_le_byte_slice(&buf);

            k.create_trivial_radix(r, NUM_BLOCKS)
        })
        .collect()
}

pub fn encode<D: Digest>(k: &RadixClientKey, x: &[u8]) -> Vec<Vec<RadixCiphertext>> {
    // Derive PRG seed from `x`.
    let hash = D::digest(x);
    const SIZE: usize = (u128::BITS / u8::BITS) as usize;
    let seed = u128::from_le_bytes(hash.as_slice()[..SIZE].try_into().unwrap());
    let seed = tfhe::Seed(seed);

    let mut rng = RandomGenerator::<ActivatedRandomGenerator>::new(seed);
    const NUM_ROWS: usize = OUT_LEN.div_ceil(P_BYTES);
    (0..NUM_ROWS)
        .map(|_| {
            (0..LATTICE_DIM)
                .map(|_| {
                    // Generate random value in 0..q.
                    const SIZE: usize = Q_BYTES.div_ceil((u64::BITS / u8::BITS) as usize);
                    let mut buf = [0u8; SIZE * (u64::BITS / u8::BITS) as usize];
                    rng.fill_slice_with_random_uniform(&mut buf);

                    let mut r = StaticUnsignedBigInt::<SIZE>::default();
                    r.copy_from_le_byte_slice(&buf);

                    k.encrypt(r)
                })
                .collect()
        })
        .collect()
}

pub fn eval(
    fhe_key: &ServerKey,
    prf_key: &[RadixCiphertext],
    h: &[Vec<RadixCiphertext>],
) -> Vec<RadixCiphertext> {
    let v = mat_mul_vec(fhe_key, h, prf_key);
    v.par_iter()
        .map(|x| fhe_key.scalar_right_shift_parallelized(x, LOG2Q - LOG2P))
        .collect()
}

pub fn decrypt(k: RadixClientKey, ct: &[RadixCiphertext]) -> [u8; OUT_LEN] {
    let v: Vec<_> = ct
        .par_iter()
        .flat_map(|cti| {
            const SIZE: usize = Q_BYTES.div_ceil((u64::BITS / u8::BITS) as usize);
            let dec = k.decrypt::<StaticUnsignedBigInt<SIZE>>(cti);

            let mut bytes = [0u8; SIZE * (u64::BITS / u8::BITS) as usize];
            dec.copy_to_le_byte_slice(&mut bytes);
            bytes[..P_BYTES].to_vec()
        })
        .collect();
    v.try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use sha2::Sha256;

    use crate::{decrypt, encode, eval, generate_fhe_keys, generate_prf_key};

    #[test]
    fn prf() {
        let (ck, sk) = generate_fhe_keys();
        let pk = generate_prf_key(&sk);

        // Encode input.
        let x = vec![1, 2, 3];
        let x_enc = encode::<Sha256>(&ck, &x);

        // Eval PRF.
        let y = eval(&sk, &pk, &x_enc);

        // Decrypt.
        let y_dec = decrypt(ck, &y);
        println!("y_dec = {:?}", y_dec);
    }
}
