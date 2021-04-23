use ark_relations::r1cs::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError, ConstraintSystemRef};
use ark_crypto_primitives::merkle_tree::{
    Config, TwoToOneDigest, LeafDigest, Path,
    constraints::PathVar
};
use ark_crypto_primitives::crh::{CRHGadget, TwoToOneCRHGadget};
use ark_std::marker::PhantomData;
use ark_r1cs_std::alloc::{AllocVar, AllocationMode};

pub struct MerkleTreeVerification<P, LeafH, TwoToOneH, F>
where
    P: Config,
    LeafH: CRHGadget<P::LeafHash, F>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, F>,
    F: Field,
{
    root: TwoToOneDigest<P>,
    leaf: LeafDigest<P>,
    authentication_path: Path<P>,

    _leaf_h: PhantomData<LeafH>,
    _two_to_one_h: PhantomData<TwoToOneH>,
    _f: PhantomData<F>,
}

impl<P, LeafH, TwoToOneH, F> ConstraintSynthesizer<F> for MerkleTreeVerification<P, LeafH, TwoToOneH, F>
where
    P: Config,
    LeafH: CRHGadget<P::LeafHash, F>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, F>,
    F: Field,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let path_var : PathVar<P, LeafH, TwoToOneH, F> = PathVar::new_variable(
            cs,
            || Ok(self.authentication_path),
            AllocationMode::Witness,
        )?;

        Ok(())
    }
}