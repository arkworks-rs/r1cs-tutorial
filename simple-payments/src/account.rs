use crate::ledger::*;
use crate::signature::schnorr;
use ark_ed_on_bls12_381::EdwardsProjective;

/// Account public key used to verify transaction signatures.
pub type AccountPublicKey = schnorr::PublicKey<EdwardsProjective>;
/// Account secret key used to create transaction signatures.
pub type AccountSecretKey = schnorr::SecretKey<EdwardsProjective>;

/// Account identifier. This prototype supports only 256 accounts at a time.
#[derive(Hash, Eq, PartialEq, Copy, Clone, Ord, PartialOrd, Debug)]
pub struct AccountId(pub u8);

impl AccountId {
    /// Convert the account identifier to bytes.
    pub fn to_bytes_le(&self) -> Vec<u8> {
        vec![self.0]
    }
}

impl AccountId {
    /// Increment the identifier in place.
    pub(crate) fn checked_increment(&mut self) -> Option<()> {
        self.0.checked_add(1).map(|result| self.0 = result)
    }
}

/// Information about the account, such as the balance and the associated public key.
#[derive(Hash, Eq, PartialEq, Copy, Clone)]
pub struct AccountInformation {
    /// The account public key.
    pub public_key: AccountPublicKey,
    /// The balance associated with this this account.
    pub balance: Amount,
}

impl AccountInformation {
    /// Convert the account information to bytes.
    pub fn to_bytes_le(&self) -> Vec<u8> {
        ark_ff::to_bytes![self.public_key, self.balance.to_bytes_le()].unwrap()
    }
}