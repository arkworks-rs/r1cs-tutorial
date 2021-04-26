use ark_std::rand::Rng;
use blake2::Blake2s;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use ark_crypto_primitives::signature::{SignatureScheme, schnorr::{self, Schnorr}};
use ark_crypto_primitives::signature::schnorr::constraints::*;
use crate::ledger::{self, AmountVar, AccRootVar, AccPathVar};
use crate::account::{AccountPublicKey, AccountId, AccountSecretKey};

/// Transaction transferring some amount from one account to another.
pub struct TransactionVar {
    /// The account information of the sender.
    pub sender: AccountIdVar,
    /// The account information of the recipient.
    pub recipient: AccountIdVar,
    /// The amount being transferred from the sender to the receiver.
    pub amount: AmountVar,
    /// The spend authorization is a signature over the sender, the recipient,
    /// and the amount.
    pub signature: SignatureVar<EdwardsProjective, EdwardsVar>,
}

impl TransactionVar {
    /// Verify just the signature in the transaction.
    fn verify_signature(
        &self,
        pp: &schnorr::ParametersVar<EdwardsProjective, Blake2s>,
        pub_key: &AccountPublicKeyVar
    ) -> bool {
        // The authorized message consists of
        // (SenderAccId || SenderPubKey || RecipientAccId || RecipientPubKey || Amount)
        let mut message = self.sender.to_bytes();
        message.extend(self.recipient.to_bytes());
        message.extend(self.amount.to_bytes());
        Schnorr::verify(&pp, &pub_key, &message, &self.signature).unwrap()
    }

    /// Check that the transaction is valid for the given ledger state. This checks
    /// the following conditions:
    /// 1. Verify that the signature is valid with respect to the public key
    /// corresponding to `self.sender`.
    /// 2. Verify that the sender's account has sufficient balance to finance
    /// the transaction.
    /// 3. Verify that the recipient's account exists.
    pub fn validate(
        &self,
        parameters: &ledger::ParametersVar,
        pre_sender_acc_info: &AccountInformationVar,
        pre_sender_path: &AccPathVar,
        pre_recipient_acc_info: &AccountInformationVar,
        pre_recipient_path: &AccPathVar,
        pre_root: &AccRootVar,
        post_root: &AccRootVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError> {
        // Verify the signature against the sender pubkey.
        let sig_verifies = self.verify_signature(&parameters.sig_params, &pre_sender_acc_info.public_key);

        // Compute the new sender balance.
        let mut post_sender_acc_info = pre_sender_acc_info.clone();
        post_sender_acc_info.balance = pre_sender_acc_info.balance.checked_sub(&tx.amount);
        // Compute the new receiver balance.
        let mut post_recipient_acc_info = pre_recipient_acc_info.clone();
        post_recipient_acc_info.balance = pre_recipient_acc_info.balance.checked_add(&tx.amount);

        // Check that the pre-tx sender account information is correct with 
        // respect to `pre_tx_root`, and that the post-tx sender account
        // information is correct with respect to `post_tx_root`.
        let sender_exists_and_updated_correctly = pre_sender_path.update_and_check(
            &parameters.leaf_crh_params, 
            &parameters.two_to_one_crh_params, 
            &pre_root,
            &post_root,
            &pre_sender_acc_info.to_bytes_le(),
            &post_sender_acc_info.to_bytes_le(),
        )?;

        // Check that the pre-tx recipient account information is correct with 
        // respect to `pre_tx_root`, and that the post-tx recipient account
        // information is correct with respect to `post_tx_root`.
        let recipient_exists_and_updated_correctly = pre_recipient_path.update_and_check(
            &parameters.leaf_crh_params, 
            &parameters.two_to_one_crh_params, 
            &pre_root,
            &post_root,
            &pre_recipient_acc_info.to_bytes_le(),
            &post_recipient_acc_info.to_bytes_le(),
        )?;

        sender_exists_and_updated_correctly
            .and(&recipient_exists_and_updated_correctly)?
            .and(&sig_verifies)
    }
}
