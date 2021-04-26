use ark_crypto_primitives::merkle_tree::{Config, Path, TwoToOneDigest};
use ark_crypto_primitives::crh::{CRH, TwoToOneCRH};
use ark_ff::prelude::*;
use ark_std::marker::PhantomData;

#[cfg(feature = "r1cs")]
mod constraints;

#[cfg(test)]
#[cfg(feature = "r1cs")]
mod constraints_test;

pub struct MerkleTreeProof<P>
where
    P: Config,
{
    pub root: TwoToOneDigest<P>,
    pub leaf: [u8; 3],
    pub authentication_path: Path<P>,

    pub leaf_hash_params: <P::LeafHash as CRH>::Parameters,
    pub two_to_one_hash_params: <P::TwoToOneHash as TwoToOneCRH>::Parameters,
}

impl<P: Config> MerkleTreeProof<P> {
    pub fn verify(&self) -> Result<bool, ark_crypto_primitives::Error> {
        self.authentication_path.verify(
            &self.leaf_hash_params, 
            &self.two_to_one_hash_params, 
            &self.root, 
            &self.leaf)
    }
}
