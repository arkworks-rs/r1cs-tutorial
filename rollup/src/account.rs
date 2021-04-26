use crate::ledger::*;
use crate::ConstraintF;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use ark_r1cs_std::bits::{uint8::UInt8, ToBytesGadget};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{Namespace, SynthesisError};
use ark_simple_payments::account::*;
use ark_simple_payments::signature::schnorr::constraints::*;
use std::borrow::Borrow;

/// Account public key used to verify transaction signatures.
pub type AccountPublicKeyVar = PublicKeyVar<EdwardsProjective, EdwardsVar>;

/// Account identifier. This prototype supports only 256 accounts at a time.
#[derive(Clone, Debug)]
pub struct AccountIdVar(pub UInt8<ConstraintF>);

impl AccountIdVar {
    /// Convert the account identifier to bytes.
    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn to_bytes_le(&self) -> Vec<UInt8<ConstraintF>> {
        vec![self.0.clone()]
    }
}

impl AllocVar<AccountId, ConstraintF> for AccountIdVar {
    #[tracing::instrument(target = "r1cs", skip(cs, f, mode))]
    fn new_variable<T: Borrow<AccountId>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        UInt8::new_variable(cs, || f().map(|u| u.borrow().0), mode).map(Self)
    }
}

/// Information about the account, such as the balance and the associated public key.
#[derive(Clone)]
pub struct AccountInformationVar {
    /// The account public key.
    pub public_key: AccountPublicKeyVar,
    /// The balance associated with this this account.
    pub balance: AmountVar,
}

impl AccountInformationVar {
    /// Convert the account information to bytes.
    #[tracing::instrument(target = "r1cs", skip(self))]
    pub fn to_bytes_le(&self) -> Vec<UInt8<crate::ConstraintF>> {
        self.public_key
            .to_bytes()
            .unwrap()
            .into_iter()
            .chain(self.balance.to_bytes_le())
            .collect()
    }
}

impl AllocVar<AccountInformation, ConstraintF> for AccountInformationVar {
    #[tracing::instrument(target = "r1cs", skip(cs, f, mode))]
    fn new_variable<T: Borrow<AccountInformation>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        f().and_then(|info| {
            let info = info.borrow();
            let cs = cs.into();
            let public_key =
                AccountPublicKeyVar::new_variable(cs.clone(), || Ok(&info.public_key), mode)?;
            let balance = AmountVar::new_variable(cs.clone(), || Ok(&info.balance), mode)?;
            Ok(Self {
                public_key,
                balance,
            })
        })
    }
}
