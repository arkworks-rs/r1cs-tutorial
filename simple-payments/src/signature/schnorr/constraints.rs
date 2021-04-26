use ark_std::vec::Vec;
use ark_ec::ProjectiveCurve;
use ark_ff::{Field, PrimeField, to_bytes};
use ark_relations::r1cs::ConstraintSystemRef;
use ark_r1cs_std::{prelude::*, fields::fp::FpVar, bits::uint8::UInt8};
use ark_relations::r1cs::{Namespace, SynthesisError};

use crate::random_oracle::RandomOracleGadget;
use crate::random_oracle::blake2s::{*, constraints::ROGadget};
use crate::signature::SigVerifyGadget;
use ark_crypto_primitives::*;

extern crate derivative;
use derivative::Derivative;

use core::{borrow::Borrow, marker::PhantomData};

use crate::signature::schnorr::{Parameters, PublicKey, Signature, Schnorr};
use digest::Digest;

type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

#[derive(Clone)]
pub struct ParametersVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    generator: GC,
    salt: Option<[UInt8<ConstraintF<C>>; 32]>,
    _curve: PhantomData<C>,
}

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct PublicKeyVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    pub_key: GC,
    #[doc(hidden)]
    _group: PhantomData<*const C>,
}

pub struct SignatureVar<ConstraintF: PrimeField>
{
    prover_response: Vec<UInt8<ConstraintF>>,
    verifier_challenge: [UInt8<ConstraintF>; 32],
}

pub struct SchnorrSignatureVerifyGadget<
    C: ProjectiveCurve, 
    GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_gadget: PhantomData<*const GC>,
}

impl<C, GC> SigVerifyGadget<Schnorr<C>, ConstraintF<C>> 
    for SchnorrSignatureVerifyGadget<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    type ParametersVar = ParametersVar<C, GC>;
    type PublicKeyVar = PublicKeyVar<C, GC>;
    type SignatureVar = SignatureVar<ConstraintF<C>>;


    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<ConstraintF<C>>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError>
    {
        let prover_response = signature.prover_response;
        let verifier_challenge = signature.verifier_challenge;
        let mut claimed_prover_commitment = parameters.generator.scalar_mul_le(
            prover_response.to_bits_le()?.iter())?;
        let public_key_times_verifier_challenge = public_key.pub_key.scalar_mul_le(
            verifier_challenge.to_bits_le()?.iter())?;
        claimed_prover_commitment += &public_key_times_verifier_challenge;
        let claimed_prover_commitment = claimed_prover_commitment;

        let mut hash_input = Vec::new();
        if parameters.salt.is_some() {
            hash_input.extend_from_slice(&parameters.salt.unwrap());
        }
        hash_input.extend_from_slice(claimed_prover_commitment.to_bytes()?);
        hash_input.extend_from_slice(message);

        let parameters_var =
            <ROGadget as RandomOracleGadget<_, _>>::ParametersVar::new_constant(
                ConstraintSystemRef::None,
                (),
            )
            .unwrap();
        let obtained_verifier_challenge = ROGadget::evaluate(
            &parameters_var,
            &hash_input,
        )
        .unwrap().0;
        
        Ok(obtained_verifier_challenge.is_eq(&verifier_challenge.to_vec())?)
    }
}

impl<C, GC> AllocVar<Parameters<C>, ConstraintF<C>> for ParametersVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<Parameters<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let generator = GC::new_variable(cs, || f().map(|g| g.borrow().generator), mode)?;
        let native_salt = f().map(|b| b.borrow().salt)?;
        let constraint_salt = [UInt8::constant(0); 32];
        if native_salt.is_some() {
            for i in 0..32 {
                constraint_salt[i] = 
                    UInt8::<ConstraintF<C>>::new_variable(
                        ark_relations::ns!(cs, ""),
                        || Ok(native_salt.unwrap()[i].clone()),
                        mode,
                    )?;
            }

            return Ok(Self {
                generator,
                salt: Some(constraint_salt),
                _curve: PhantomData,
            });
        }
        Ok(Self {
            generator,
            salt: None,
            _curve: PhantomData,
        })
    }
}

impl<C, GC> AllocVar<PublicKey<C>, ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<PublicKey<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let pub_key = GC::new_variable(cs, f, mode)?;
        Ok(Self {
            pub_key,
            _group: PhantomData,
        })
    }
}

impl<ConstraintF: PrimeField> AllocVar<Signature<ConstraintF>, ConstraintF> for SignatureVar<ConstraintF>
where
    ConstraintF: ProjectiveCurve,
{
    fn new_variable<T: Borrow<Signature<ConstraintF>>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let response_bytes = to_bytes![val.borrow().prover_response].unwrap();
            let challenge_bytes = val.borrow().verifier_challenge;
            let mut prover_response = Vec::<UInt8::<ConstraintF>>::new();
            let mut verifier_challenge = [UInt8::<ConstraintF>::constant(0); 32];
            for i in 0..response_bytes.len() {
                prover_response.push(
                    UInt8::<ConstraintF>::new_variable(
                        ark_relations::ns!(cs, "prover_response"),
                        || Ok(response_bytes[i].clone()),
                        mode,
                    )?);
            }
            for i in 0..32 {
                verifier_challenge[i] = 
                    UInt8::<ConstraintF>::new_variable(
                        ark_relations::ns!(cs, "verifier_challenge"),
                        || Ok(challenge_bytes[i].clone()),
                        mode,
                    )?;
            }
            Ok(SignatureVar {
                prover_response,
                verifier_challenge,
            })
        })
    }
}

impl<C, GC> EqGadget<ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[inline]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        self.pub_key.is_eq(&other.pub_key)
    }

    #[inline]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_equal(&other.pub_key, condition)
    }

    #[inline]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        condition: &Boolean<ConstraintF<C>>,
    ) -> Result<(), SynthesisError> {
        self.pub_key
            .conditional_enforce_not_equal(&other.pub_key, condition)
    }
}

impl<C, GC> ToBytesGadget<ConstraintF<C>> for PublicKeyVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn to_bytes(&self) -> Result<Vec<UInt8<ConstraintF<C>>>, SynthesisError> {
        self.pub_key.to_bytes()
    }
}
