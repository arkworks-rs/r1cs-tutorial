use ark_crypto_primitives::signature::schnorr;

    SignatureScheme;
use ark_crypto_primitives::merkle_tree::MerkleTree;
use ark_crypto_primitives::crh::CRH;

/// Account ID.
pub AccountId(u8);

/// Transaction amount.
pub Amount(u64);

/// Transaction transferring some amount from one account to another.
pub struct Transaction {
    /// The account information of the sender.
    pub sender: (AccountId, schnorr::PublicKey),
    /// The account information of the recipient.
    pub recipient: (AccountId, schnorr::PublicKey),
    /// The amount being transferred from the sender to the receiver.
    pub amount: Amount,
    /// The spend authorization is a signature over the sender, the recipient,
    /// and the amount.
    pub spend_authorization: schnorr::Signature,
}

impl<S: SignatureScheme> Transaction<S> {
    /// Verify just the signature in the transaction.
    pub fn verify_signature(&self, pp: &schnorr::PublicParameters) -> bool {
        // The authorized message consists of 
        // (SenderAccId || SenderPubKey || RecipientAccId || RecipientPubKey || Amount)
        let mut message = vec![self.sender.0.0];
        message.extend(ark_ff::to_bytes![self.sender.1]);
        message.extend(&[self.recipient.0.0]);
        message.extend(ark_ff::to_bytes![self.recipient.1]);
        message.extend(&self.amount.0.to_le_bytes()[..]);
        S::verify(pp, &self.sender.1, &message, &self.spend_authorization)
    }

    pub fn verify_against_merkle_tree<H: CRH>(&self, pp: &S::PublicParameters, tree: &MerkleTree) -> bool {

    }
}
