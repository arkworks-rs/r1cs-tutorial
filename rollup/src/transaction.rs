use ark_std::rand::Rng;
use blake2::Blake2s;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use ark_crypto_primitives::signature::{SignatureScheme, schnorr::{self, Schnorr}};
use ark_crypto_primitives::signature::schnorr::constraints::*;
use ark_crypto_primitives::merkle_tree::constraints::PathVar;
use crate::ledger::{self, Amount};
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
        claimed_sender_acc_info: &AccountInformationVar,
        acc_tree_root: &<TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::OutputVar,
        claimed_sender_acc_info_mem_proof: &PathVar<MerkleConfig, LeafHashGadget, TwoToOneHashGadget, ConstraintF>,
    ) -> Result<Boolean<ConstraintF>, SynthesisError> {
        // Check merkle tree path for 
        let sender_exists = claimed_sender_acc_info_mem_proof.verify_membership(
            parameters.leaf_crh_params,
            parameters.two_to_one_crh_params,
            &acc_tree_root,
            &claimed_sender_acc_info.to_bytes()
        );

        // Verify the signature against the sender pubkey.
        let sig_verifies = self.verify_signature(&parameters.sig_params, &sender_acc_info.public_key);
        // Verify the amount is available in the sender account.
        let balance_is_sufficient = self.amount.less_than_eq(&sender_acc_info.balance);
        // TODO: Verify that recipient account exists.
        sender_exists.and(&sig_verifies)?.and(&balance_is_sufficient)?
    }
}
