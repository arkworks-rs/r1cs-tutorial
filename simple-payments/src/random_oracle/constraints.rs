use ark_ff::Field;
use core::fmt::Debug;

use crate::random_oracle::RandomOracle;
use ark_relations::r1cs::SynthesisError;

use ark_r1cs_std::prelude::*;

pub trait RandomOracleGadget<RO: RandomOracle, ConstraintF: Field>: Sized {
    type OutputVar: EqGadget<ConstraintF>
        + ToBytesGadget<ConstraintF>
        + AllocVar<RO::Output, ConstraintF>
        + R1CSVar<ConstraintF>
        + Debug
        + Clone
        + Sized;

    type ParametersVar: AllocVar<RO::Parameters, ConstraintF> + Clone;

    fn evaluate(
        parameters: &Self::ParametersVar,
        input: &[UInt8<ConstraintF>],
    ) -> Result<Self::OutputVar, SynthesisError>;
}
