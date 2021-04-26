use crate::ConstraintF;
use ark_crypto_primitives::crh::{
    injective_map::TECompressor,
    constraints::{TwoToOneCRHGadget, CRHGadget},
    pedersen, TwoToOneCRH, CRH,
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use ark_crypto_primitives::merkle_tree::{self, MerkleTree};
use ark_crypto_primitives::crh::injective_map::constraints::{PedersenCRHCompressorGadget, TECompressorGadget};
use ark_r1cs_std::bits::uint64::UInt64;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_simple_payments::ledger::*;
use std::borrow::Borrow;

/// Represents transaction amounts and account balances.
#[derive(Clone, Debug)]
pub struct AmountVar(UInt64<ConstraintF>);

impl AmountVar {
    pub fn to_bytes_le(&self) -> Vec<UInt8<ConstraintF>> {
        self.0.to_bytes().unwrap()
    }

    pub fn checked_add(&self, other: &Self) -> Option<Self> {
        unimplemented!()
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        unimplemented!()
    }
}

impl AllocVar<Amount, ConstraintF> for AmountVar {
    fn new_variable<T: Borrow<Amount>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        UInt64::new_variable(cs, || f().map(|u| u.borrow().0), mode).map(Self)
    }
}

pub type TwoToOneHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    TwoToOneWindow,
    EdwardsVar,
    TECompressorGadget,
>;

pub type LeafHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    LeafWindow,
    EdwardsVar,
    TECompressorGadget,
>;

/// The parameters that are used in transaction creation and validation.
pub struct Parameters {
    pub sig_params: schnorr::Parameters<EdwardsProjective, Blake2s>,
    pub leaf_crh_params: <LeafHashGadget as CRHGadget<LeafHash, ConstraintF>>::ParametersVar,
    pub two_to_one_crh_params: <TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::ParametersVar,
}
