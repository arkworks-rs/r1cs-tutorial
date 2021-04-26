use ark_crypto_primitives::crh::{CRHGadget, TwoToOneCRHGadget};
use ark_crypto_primitives::merkle_tree::{constraints::PathVar, Config, Path, TwoToOneDigest};
use ark_ff::PrimeField;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::uint8::UInt8;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::marker::PhantomData;

pub struct MerkleTreeVerification<P, LeafH, TwoToOneH, F>
where
    P: Config,
    LeafH: CRHGadget<P::LeafHash, F>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, F>,
    F: PrimeField,
{
    pub root: TwoToOneDigest<P>,
    pub leaf: [u8; 3],
    pub authentication_path: Path<P>,

    pub leaf_hash_params: LeafH::ParametersVar,
    pub two_to_one_hash_params: TwoToOneH::ParametersVar,

    pub _f: PhantomData<F>,
}

impl<P, LeafH, TwoToOneH, F> ConstraintSynthesizer<F>
    for MerkleTreeVerification<P, LeafH, TwoToOneH, F>
where
    P: Config,
    LeafH: CRHGadget<P::LeafHash, F>,
    TwoToOneH: TwoToOneCRHGadget<P::TwoToOneHash, F>,
    F: PrimeField,
{
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let path_var: PathVar<P, LeafH, TwoToOneH, F> =
            PathVar::new_witness(ark_relations::ns!(cs, "path_var"), || {
                Ok(&self.authentication_path)
            })?;

        let root_var = <TwoToOneH as TwoToOneCRHGadget<_, _>>::OutputVar::new_input(
            ark_relations::ns!(cs, "root_var"),
            || Ok(&self.root),
        )?;

        let leaf_var = <UInt8<F>>::new_input_vec(ark_relations::ns!(cs, "leaf_var"), &self.leaf)?;

        let is_member = path_var.verify_membership(
            &self.leaf_hash_params,
            &self.two_to_one_hash_params,
            &root_var,
            &leaf_var.as_slice(),
        )?;

        is_member.enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}
