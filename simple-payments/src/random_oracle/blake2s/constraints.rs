use crate::random_oracle::{blake2s, RandomOracleGadget};
use ark_crypto_primitives::prf::blake2s::constraints::{evaluate_blake2s, OutputVar};
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::vec::Vec;

use core::borrow::Borrow;

#[derive(Clone)]
pub struct ParametersVar;

pub struct ROGadget;

impl<F: PrimeField> RandomOracleGadget<blake2s::RO, F> for ROGadget {
    type OutputVar = OutputVar<F>;
    type ParametersVar = ParametersVar;

    // #[tracing::instrument(target = "r1cs", skip(input, r))]
    fn evaluate(
        _: &Self::ParametersVar,
        input: &[UInt8<F>],
    ) -> Result<Self::OutputVar, SynthesisError> {
        let mut input_bits = Vec::with_capacity(512);
        for byte in input.iter() {
            input_bits.extend_from_slice(&byte.to_bits_le()?);
        }
        let mut result = Vec::new();
        for int in evaluate_blake2s(&input_bits)?.into_iter() {
            let chunk = int.to_bytes()?;
            result.extend_from_slice(&chunk);
        }
        Ok(OutputVar(result))
    }
}

impl<ConstraintF: Field> AllocVar<(), ConstraintF> for ParametersVar {
    // #[tracing::instrument(target = "r1cs", skip(_cs, _f))]
    fn new_variable<T: Borrow<()>>(
        _cs: impl Into<Namespace<ConstraintF>>,
        _f: impl FnOnce() -> Result<T, SynthesisError>,
        _mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        Ok(ParametersVar)
    }
}

#[cfg(test)]
mod test {
    use crate::random_oracle::{
        blake2s::{constraints::ROGadget, RO},
        RandomOracle, RandomOracleGadget,
    };
    use ark_ed_on_bls12_381::Fq as Fr;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn random_oracle_gadget_test() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let input = [1u8; 32];

        type TestRO = RO;
        type TestROGadget = ROGadget;

        let parameters = ();
        let primitive_result = RO::evaluate(&parameters, &input).unwrap();

        let mut input_var = vec![];
        for byte in &input {
            input_var.push(UInt8::new_witness(cs.clone(), || Ok(*byte)).unwrap());
        }

        let parameters_var =
            <TestROGadget as RandomOracleGadget<TestRO, Fr>>::ParametersVar::new_witness(
                ark_relations::ns!(cs, "gadget_parameters"),
                || Ok(&parameters),
            )
            .unwrap();
        let result_var =
            <TestROGadget as RandomOracleGadget<TestRO, Fr>>::evaluate(&parameters_var, &input_var)
                .unwrap();

        for i in 0..32 {
            assert_eq!(primitive_result[i], result_var.0[i].value().unwrap());
        }
        assert!(cs.is_satisfied().unwrap());
    }
}
