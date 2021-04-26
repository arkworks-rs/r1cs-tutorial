use ark_ec::ProjectiveCurve;
use ark_ff::{to_bytes, Field};
use ark_r1cs_std::{bits::uint8::UInt8, prelude::*};
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_std::vec::Vec;

use crate::random_oracle::blake2s::constraints::{ParametersVar as B2SParamsVar, ROGadget};
use crate::random_oracle::RandomOracleGadget;
use crate::signature::SigVerifyGadget;

use derivative::Derivative;

use core::{borrow::Borrow, marker::PhantomData};

use crate::signature::schnorr::{Parameters, PublicKey, Schnorr, Signature};

type ConstraintF<C> = <<C as ProjectiveCurve>::BaseField as Field>::BasePrimeField;

#[derive(Clone)]
pub struct ParametersVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    generator: GC,
    salt: Option<Vec<UInt8<ConstraintF<C>>>>,
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

#[derive(Derivative)]
#[derivative(
    Debug(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>"),
    Clone(bound = "C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>")
)]
pub struct SignatureVar<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    prover_response: Vec<UInt8<ConstraintF<C>>>,
    verifier_challenge: Vec<UInt8<ConstraintF<C>>>,
    #[doc(hidden)]
    _group: PhantomData<GC>,
}

pub struct SchnorrSignatureVerifyGadget<C: ProjectiveCurve, GC: CurveVar<C, ConstraintF<C>>>
where
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    #[doc(hidden)]
    _group: PhantomData<*const C>,
    #[doc(hidden)]
    _group_gadget: PhantomData<*const GC>,
}

impl<C, GC> SigVerifyGadget<Schnorr<C>, ConstraintF<C>> for SchnorrSignatureVerifyGadget<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    type ParametersVar = ParametersVar<C, GC>;
    type PublicKeyVar = PublicKeyVar<C, GC>;
    type SignatureVar = SignatureVar<C, GC>;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        message: &[UInt8<ConstraintF<C>>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF<C>>, SynthesisError> {
        let prover_response = signature.prover_response.clone();
        let verifier_challenge = signature.verifier_challenge.clone();
        let mut claimed_prover_commitment = parameters
            .generator
            .scalar_mul_le(prover_response.to_bits_le()?.iter())?;
        let public_key_times_verifier_challenge = public_key
            .pub_key
            .scalar_mul_le(verifier_challenge.to_bits_le()?.iter())?;
        claimed_prover_commitment += &public_key_times_verifier_challenge;

        let mut hash_input = Vec::new();
        if parameters.salt.is_some() {
            hash_input.extend_from_slice(parameters.salt.as_ref().unwrap());
        }
        hash_input.extend_from_slice(&public_key.pub_key.to_bytes()?);
        hash_input.extend_from_slice(&claimed_prover_commitment.to_bytes()?);
        hash_input.extend_from_slice(message);

        let b2s_params = <B2SParamsVar as AllocVar<_, ConstraintF<C>>>::new_constant(
            ConstraintSystemRef::None,
            (),
        )?;
        let obtained_verifier_challenge = ROGadget::evaluate(&b2s_params, &hash_input)?.0;

        obtained_verifier_challenge.is_eq(&verifier_challenge.to_vec())
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
        f().and_then(|val| {
            let cs = cs.into();
            let generator = GC::new_variable(cs.clone(), || Ok(val.borrow().generator), mode)?;
            let native_salt = val.borrow().salt;
            let mut constraint_salt = Vec::<UInt8<ConstraintF<C>>>::new();
            if native_salt.is_some() {
                for i in 0..32 {
                    constraint_salt.push(UInt8::<ConstraintF<C>>::new_variable(
                        cs.clone(),
                        || Ok(native_salt.unwrap()[i].clone()),
                        mode,
                    )?);
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

impl<C, GC> AllocVar<Signature<C>, ConstraintF<C>> for SignatureVar<C, GC>
where
    C: ProjectiveCurve,
    GC: CurveVar<C, ConstraintF<C>>,
    for<'a> &'a GC: GroupOpsBounds<'a, C, GC>,
{
    fn new_variable<T: Borrow<Signature<C>>>(
        cs: impl Into<Namespace<ConstraintF<C>>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|val| {
            let cs = cs.into();
            let response_bytes = to_bytes![val.borrow().prover_response].unwrap();
            let challenge_bytes = val.borrow().verifier_challenge;
            let mut prover_response = Vec::<UInt8<ConstraintF<C>>>::new();
            let mut verifier_challenge = Vec::<UInt8<ConstraintF<C>>>::new();
            for i in 0..response_bytes.len() {
                prover_response.push(UInt8::<ConstraintF<C>>::new_variable(
                    cs.clone(),
                    || Ok(response_bytes[i].clone()),
                    mode,
                )?);
            }
            for i in 0..32 {
                verifier_challenge.push(UInt8::<ConstraintF<C>>::new_variable(
                    cs.clone(),
                    || Ok(challenge_bytes[i].clone()),
                    mode,
                )?);
            }
            Ok(SignatureVar {
                prover_response,
                verifier_challenge,
                _group: PhantomData,
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
