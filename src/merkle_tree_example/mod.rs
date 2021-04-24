use ark_relations::r1cs::Field;
use ark_relations::r1cs::{ConstraintSynthesizer, SynthesisError, ConstraintSystemRef};
use ark_crypto_primitives::merkle_tree::{
    Config, TwoToOneDigest, LeafDigest, Path,
    constraints::PathVar
};
use ark_crypto_primitives::crh::{CRHGadget, TwoToOneCRHGadget};
use ark_std::marker::PhantomData;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::boolean::Boolean;

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

    leaf_hash_params: LeafH::ParametersVar,
    two_to_one_hash_params: TwoToOneH::ParametersVar,

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
        let path_var : PathVar<P, LeafH, TwoToOneH, F> = PathVar::new_witness(
            ark_relations::ns!(cs, "path_var"),
            || Ok(&self.authentication_path),
        )?;

        let root_var = <TwoToOneH as TwoToOneCRHGadget<_, _>>::OutputVar::new_input(
            ark_relations::ns!(cs, "root_var"),
            || Ok(&self.root),
        )?;

        let leaf_var = <LeafH as CRHGadget<_, _>>::OutputVar::new_input(
            ark_relations::ns!(cs, "leaf_var"),
            || Ok(&self.leaf),
        )?;

        let is_member = path_var.verify_membership(
            &self.leaf_hash_params,
            &self.two_to_one_hash_params,
            &root_var,
            &leaf_var,
        )?;

        is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}