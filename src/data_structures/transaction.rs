use ark_crypto_primitives::signature::schnorr;
use crate::data_structures::ledger::{AccountPublicKey, AccountId, Amount}
use ark_crypto_primitives::merkle_tree::MerkleTree;
use ark_crypto_primitives::crh::CRH;

/// Transaction transferring some amount from one account to another.
pub struct Transaction {
    /// The account information of the sender.
    pub sender: AccountId,
    /// The account information of the recipient.
    pub recipient: AccountId,
    /// The amount being transferred from the sender to the receiver.
    pub amount: Amount,
    /// The spend authorization is a signature over the sender, the recipient,
    /// and the amount.
    pub signature: schnorr::Signature,
}

impl Transaction {
    /// Verify just the signature in the transaction.
    fn verify_signature(&self, pub_key: &AccountPublicKey) -> bool {
        // The authorized message consists of 
        // (SenderAccId || SenderPubKey || RecipientAccId || RecipientPubKey || Amount)
        let mut message = vec![self.sender.0.0, self.recipient.0.0];
        message.extend(&self.amount.0.to_le_bytes()[..]);
        S::verify(pp, &self.sender.1, &message, &self.signature)
    }

    pub fn verify_against_ledger_state(&self, state: &ledger::State) -> bool {
        // Lookup public keys corresponding to sender ID
        // Verify the signature against the sender pubkey.
        // Verify the amount is available in the sender account.
        // Verify that recipient account exists.
    }
}


// IDeas to make exercises more interesting/complex:
// 1. Add fees
// 2. Add recipient confirmation requirement if tx amount is too large.
// 3. Add authority confirmation if tx amount is too large.
// 4. Create account if it doesn't exist.
// 5. Add idea for compressing state transitions with repeated senders and recipients.
