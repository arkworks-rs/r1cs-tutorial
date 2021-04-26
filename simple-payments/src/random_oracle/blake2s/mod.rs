use super::RandomOracle;
use ark_crypto_primitives::Error;
use ark_std::rand::Rng;
use blake2::Blake2s as b2s;
use digest::Digest;

pub struct RO;

#[cfg(feature = "r1cs")]
pub mod constraints;

impl RandomOracle for RO {
    type Parameters = ();
    type Output = [u8; 32];

    fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, Error> {
        Ok(())
    }

    fn evaluate(_: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let mut h = b2s::new();
        h.update(input);
        let mut result = [0u8; 32];
        result.copy_from_slice(&h.finalize());
        Ok(result)
    }
}
