use ark_ff::Field;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

use crate::signature::SignatureScheme;

pub trait SigVerifyGadget<S: SignatureScheme, ConstraintF: Field> {
    type ParametersVar: AllocVar<S::Parameters, ConstraintF> + Clone;

    type PublicKeyVar: ToBytesGadget<ConstraintF> + AllocVar<S::PublicKey, ConstraintF> + Clone;

    type SignatureVar: AllocVar<S::Signature, ConstraintF> + Clone;

    fn verify(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        // TODO: Should we make this take in bytes or something different?
        message: &[UInt8<ConstraintF>],
        signature: &Self::SignatureVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError>;
}

pub trait SigRandomizePkGadget<S: SignatureScheme, ConstraintF: Field> {
    type ParametersVar: AllocVar<S::Parameters, ConstraintF> + Clone;

    type PublicKeyVar: ToBytesGadget<ConstraintF>
        + EqGadget<ConstraintF>
        + AllocVar<S::PublicKey, ConstraintF>
        + Clone;

    fn randomize(
        parameters: &Self::ParametersVar,
        public_key: &Self::PublicKeyVar,
        randomness: &[UInt8<ConstraintF>],
    ) -> Result<Self::PublicKeyVar, SynthesisError>;
}

#[cfg(test)]
mod test {
    use crate::signature::{schnorr, schnorr::constraints::*, *};
    use ark_ec::ProjectiveCurve;
    use ark_ed_on_bls12_381::constraints::EdwardsVar as JubJubVar;
    use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
    use ark_ff::PrimeField;
    use ark_r1cs_std::prelude::*;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::test_rng;

    fn sign_and_verify<F: PrimeField, S: SignatureScheme, SG: SigVerifyGadget<S, F>>(
        message: &[u8],
    ) {
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, &message, rng).unwrap();
        assert!(S::verify(&parameters, &pk, &message, &sig).unwrap());

        let cs = ConstraintSystem::<F>::new_ref();

        let parameters_var = SG::ParametersVar::new_constant(cs.clone(), parameters).unwrap();
        let signature_var = SG::SignatureVar::new_witness(cs.clone(), || Ok(&sig)).unwrap();
        let pk_var = SG::PublicKeyVar::new_witness(cs.clone(), || Ok(&pk)).unwrap();
        let mut msg_var = Vec::new();
        for i in 0..message.len() {
            msg_var.push(UInt8::new_witness(cs.clone(), || Ok(&message[i])).unwrap())
        }
        let valid_sig_var = SG::verify(&parameters_var, &pk_var, &msg_var, &signature_var).unwrap();

        valid_sig_var.enforce_equal(&Boolean::<F>::TRUE).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    fn failed_verification<S: SignatureScheme>(message: &[u8], bad_message: &[u8]) {
        let rng = &mut test_rng();
        let parameters = S::setup::<_>(rng).unwrap();
        let (pk, sk) = S::keygen(&parameters, rng).unwrap();
        let sig = S::sign(&parameters, &sk, message, rng).unwrap();
        assert!(!S::verify(&parameters, &pk, bad_message, &sig).unwrap());
    }

    #[test]
    fn schnorr_signature_test() {
        type F = <JubJub as ProjectiveCurve>::BaseField;
        let message = "Hi, I am a Schnorr signature!";
        sign_and_verify::<
            F,
            schnorr::Schnorr<JubJub>,
            SchnorrSignatureVerifyGadget<JubJub, JubJubVar>,
        >(message.as_bytes());
        failed_verification::<schnorr::Schnorr<JubJub>>(
            message.as_bytes(),
            "Bad message".as_bytes(),
        );
    }
}
