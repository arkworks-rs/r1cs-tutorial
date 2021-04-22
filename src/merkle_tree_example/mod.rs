use ark_relations::r1cs::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError, ConstraintSystemRef};
use ark_crypto_primitives::merkle_tree::{
    Config, TwoToOneDigest, LeafDigest,
    constraints::PathVar
};
use ark_crypto_primitives::crh::{CRHGadget, TwoToOneCRHGadget};

pub struct MerkleTreeVerification<P, LeafH, TwoToOneH, F>
where
    P: Config,
    LeafH: CRHGadget<P::LeafHash, F>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, F>,
    F: Field,
{
    root: TwoToOneDigest<P>,
    leaf: LeafDigest<P>,
    authentication_path: PathVar<P, LeafH, TwoToOneH, F>,
}

impl<P, LeafH, TwoToOneH, F> ConstraintSynthesizer<F> for MerkleTreeVerification<P, LeafH, TwoToOneH, F>
where
    P: Config,
    LeafH: CRHGadget<P::LeafHash, F>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, F>,
    F: Field,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        Ok(())
    }
}