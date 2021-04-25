use blake2::Blake2s;
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_crypto_primitives::signature::{SignatureScheme, schnorr::{self, Schnorr}};
use crate::data_structures::ledger::{self, AccountPublicKey, AccountId, Amount};

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
    pub signature: schnorr::Signature<EdwardsProjective>,
}

impl Transaction {
    /// Verify just the signature in the transaction.
    fn verify_signature(
        &self,
        pp: &schnorr::Parameters<EdwardsProjective, Blake2s>,
        pub_key: &AccountPublicKey
    ) -> bool {
        // The authorized message consists of 
        // (SenderAccId || SenderPubKey || RecipientAccId || RecipientPubKey || Amount)
        let mut message = self.sender.to_bytes_le();
        message.extend(self.recipient.to_bytes_le());
        message.extend(self.amount.to_bytes_le());
        Schnorr::verify(&pp, &pub_key, &message, &self.signature).unwrap()
    }

    pub fn verify_against_ledger_state(
        &self,
        parameters: &ledger::Parameters,
        state: &ledger::State
    ) -> bool {
        // Lookup public key corresponding to sender ID
        if let Some(sender_acc_info) = state.id_to_account_info.get(&self.sender) {
            let mut result = false;
            // Verify the signature against the sender pubkey.
            result |= self.verify_signature(&parameters.sig_params, &sender_acc_info.public_key);
            // Verify the amount is available in the sender account.
            result |= self.amount <= sender_acc_info.balance;
            // Verify that recipient account exists.
            result |= state.id_to_account_info.get(&self.recipient).is_some();
            result
        } else {
            false
        }
    }
}


// IDeas to make exercises more interesting/complex:
// 1. Add fees
// 2. Add recipient confirmation requirement if tx amount is too large.
// 3. Add authority confirmation if tx amount is too large.
// 4. Create account if it doesn't exist.
// 5. Add idea for compressing state transitions with repeated senders and recipients.
