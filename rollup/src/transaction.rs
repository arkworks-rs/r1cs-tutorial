use crate::account::{AccountIdVar, AccountInformationVar, AccountPublicKeyVar};
use crate::ledger::{self, AccPathVar, AccRootVar, AmountVar, ParametersVar};
use crate::ConstraintF;
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Namespace, SynthesisError};
use ark_simple_payments::account::AccountInformation;
use ark_simple_payments::ledger::{AccPath, AccRoot, Parameters, State};
use ark_simple_payments::signature::schnorr::constraints::{
    ParametersVar as SchnorrParamsVar, SchnorrSignatureVerifyGadget, SignatureVar,
};
use ark_simple_payments::signature::SigVerifyGadget;
use ark_simple_payments::transaction::Transaction;
use std::borrow::Borrow;

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
    #[tracing::instrument(target = "r1cs", skip(self, pp, pub_key))]
    fn verify_signature(
        &self,
        pp: &SchnorrParamsVar<EdwardsProjective, EdwardsVar>,
        pub_key: &AccountPublicKeyVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError> {
        // The authorized message consists of
        // (SenderAccId || SenderPubKey || RecipientAccId || RecipientPubKey || Amount)
        let mut message = self.sender.to_bytes_le();
        message.extend(self.recipient.to_bytes_le());
        message.extend(self.amount.to_bytes_le());
        SchnorrSignatureVerifyGadget::verify(pp, pub_key, &message, &self.signature)
    }

    /// Check that the transaction is valid for the given ledger state. This checks
    /// the following conditions:
    /// 1. Verify that the signature is valid with respect to the public key
    /// corresponding to `self.sender`.
    /// 2. Verify that the sender's account has sufficient balance to finance
    /// the transaction.
    /// 3. Verify that the recipient's account exists.
    #[allow(clippy::too_many_arguments)]
    #[tracing::instrument(
        target = "r1cs",
        skip(
            self,
            parameters,
            pre_sender_acc_info,
            pre_sender_path,
            post_sender_path,
            pre_recipient_acc_info,
            pre_recipient_path,
            post_recipient_path,
            pre_root,
            post_root
        )
    )]
    pub fn validate(
        &self,
        parameters: &ledger::ParametersVar,
        pre_sender_acc_info: &AccountInformationVar,
        pre_sender_path: &AccPathVar,
        post_sender_path: &AccPathVar,
        pre_recipient_acc_info: &AccountInformationVar,
        pre_recipient_path: &AccPathVar,
        post_recipient_path: &AccPathVar,
        pre_root: &AccRootVar,
        post_root: &AccRootVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError> {
        // Verify the signature against the sender pubkey.
        // TODO: FILL IN THE BLANK
        // let sig_verifies = ???;

        // Compute the new sender balance.
        let mut post_sender_acc_info = pre_sender_acc_info.clone();
        // TODO: Safely subtract amount sent from the sender's balance
        // post_sender_acc_info.balance = ???;

        // TODO: Compute the new receiver balance, ensure its overflow safe.
        let mut post_recipient_acc_info = pre_recipient_acc_info.clone();
        // post_recipient_acc_info.balance = ???

        // Check that the pre-tx sender account information is correct with
        // respect to `pre_tx_root`, and that the post-tx sender account
        // information is correct with respect to `post_tx_root`.
        // HINT: Use the path structs
        // TODO: FILL IN THE FOLLOWING
        // let sender_exists = ???

        // let sender_updated_correctly = ???

        // Check that the pre-tx recipient account information is correct with
        // respect to `pre_tx_root`, and that the post-tx recipient account
        // information is correct with respect to `post_tx_root`.
        // TODO: FILL IN THE FOLLOWING
        // let recipient_exists = ???

        // let recipient_updated_correctly = ???

        // TODO: Uncomment the following
        // sender_exists
        //     .and(&sender_updated_correctly)?
        //     .and(&recipient_exists)?
        //     .and(&recipient_updated_correctly)?
        //     .and(&sig_verifies)
        Err(SynthesisError::Unsatisfiable)
    }
}

impl AllocVar<Transaction, ConstraintF> for TransactionVar {
    #[tracing::instrument(target = "r1cs", skip(cs, f, mode))]
    fn new_variable<T: Borrow<Transaction>>(
        cs: impl Into<Namespace<ConstraintF>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: AllocationMode,
    ) -> Result<Self, SynthesisError> {
        let cs = cs.into();
        f().and_then(|tx| {
            let tx: &Transaction = tx.borrow();
            let sender = AccountIdVar::new_variable(cs.clone(), || Ok(&tx.sender), mode)?;
            let recipient = AccountIdVar::new_variable(cs.clone(), || Ok(&tx.recipient), mode)?;
            let amount = AmountVar::new_variable(cs.clone(), || Ok(&tx.amount), mode)?;
            let signature = SignatureVar::new_variable(cs.clone(), || Ok(&tx.signature), mode)?;
            Ok(Self {
                sender,
                recipient,
                amount,
                signature,
            })
        })
    }
}

pub struct UnaryRollup {
    /// The ledger parameters.
    pub ledger_params: Parameters,
    /// The Merkle tree root before applying this batch of transactions.
    pub initial_root: AccRoot,
    /// The Merkle tree root after applying this batch of transactions.
    pub final_root: AccRoot,
    /// The current batch of transactions.
    pub transaction: Transaction,
    /// The sender's account information *before* applying the transaction.
    pub sender_acc_info: AccountInformation,
    /// The sender's authentication path, *before* applying the transaction.
    pub sender_pre_path: AccPath,
    /// The authentication path corresponding to the sender's account information *after* applying
    /// the transactions.
    pub sender_post_path: AccPath,
    /// The recipient's account information *before* applying the transaction.
    pub recv_acc_info: AccountInformation,
    /// The recipient's authentication path, *before* applying the transaction.
    pub recv_pre_path: AccPath,
    /// The authentication path corresponding to the recipient's account information *after*
    /// applying the transactions.
    pub recv_post_path: AccPath,
}

impl UnaryRollup {
    pub fn with_state_and_transaction(
        ledger_params: Parameters,
        transaction: Transaction,
        state: &mut State,
        validate: bool,
    ) -> Option<UnaryRollup> {
        if validate && !transaction.validate(&ledger_params, &*state) {
            return None;
        }

        let initial_root = state.root();
        let sender_id = transaction.sender;
        let recipient_id = transaction.recipient;

        let sender_acc_info = *state.id_to_account_info.get(&sender_id)?;
        let sender_pre_path = state
            .account_merkle_tree
            .generate_proof(sender_id.0 as usize)
            .unwrap();

        let recv_acc_info = *state.id_to_account_info.get(&recipient_id)?;
        let recv_pre_path = state
            .account_merkle_tree
            .generate_proof(recipient_id.0 as usize)
            .unwrap();

        if validate {
            state.apply_transaction(&ledger_params, &transaction)?;
        } else {
            let _ = state.apply_transaction(&ledger_params, &transaction);
        }

        let final_root = state.root();
        let sender_post_path = state
            .account_merkle_tree
            .generate_proof(sender_id.0 as usize)
            .unwrap();
        let recv_post_path = state
            .account_merkle_tree
            .generate_proof(recipient_id.0 as usize)
            .unwrap();

        Some(UnaryRollup {
            ledger_params,
            initial_root,
            final_root,
            transaction,
            sender_acc_info,
            sender_pre_path,
            sender_post_path,
            recv_acc_info,
            recv_pre_path,
            recv_post_path,
        })
    }
}

impl ConstraintSynthesizer<ConstraintF> for UnaryRollup {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Declare the parameters as constants.
        let ledger_params = ParametersVar::new_constant(
            ark_relations::ns!(cs, "Ledger parameters"),
            &self.ledger_params,
        )?;
        // Declare the initial root as a public input.
        let initial_root = AccRootVar::new_input(ark_relations::ns!(cs, "Initial root"), || {
            Ok(self.initial_root)
        })?;
        // Declare the final root as a public input.
        let final_root =
            AccRootVar::new_input(ark_relations::ns!(cs, "Final root"), || Ok(self.final_root))?;

        // Declare transaction as a witness.
        let tx = TransactionVar::new_witness(ark_relations::ns!(cs, "Transaction"), || {
            Ok(self.transaction.clone())
        })?;

        // Declare the sender's initial account balance...
        let sender_acc_info = AccountInformationVar::new_witness(
            ark_relations::ns!(cs, "Sender Account Info"),
            || Ok(self.sender_acc_info),
        )?;
        // ..., corresponding authentication path, ...
        let sender_pre_path =
            AccPathVar::new_witness(ark_relations::ns!(cs, "Sender Pre-Path"), || {
                Ok(self.sender_pre_path.clone())
            })?;
        // ... and authentication path after the update.
        let sender_post_path =
            AccPathVar::new_witness(ark_relations::ns!(cs, "Sender Post-Path"), || {
                Ok(self.sender_post_path.clone())
            })?;

        // Declare the recipient's initial account balance...
        let recipient_acc_info = AccountInformationVar::new_witness(
            ark_relations::ns!(cs, "Recipient Account Info"),
            || Ok(self.recv_acc_info),
        )?;
        // ..., corresponding authentication path, ...
        let recipient_pre_path =
            AccPathVar::new_witness(ark_relations::ns!(cs, "Recipient Pre-Path"), || {
                Ok(self.recv_pre_path.clone())
            })?;
        // ... and authentication path after the update.
        let recipient_post_path =
            AccPathVar::new_witness(ark_relations::ns!(cs, "Recipient Post-Path"), || {
                Ok(self.recv_post_path.clone())
            })?;

        // Validate that the transaction signature and amount is correct.
        tx.validate(
            &ledger_params,
            &sender_acc_info,
            &sender_pre_path,
            &sender_post_path,
            &recipient_acc_info,
            &recipient_pre_path,
            &recipient_post_path,
            &initial_root,
            &final_root,
        )?
        .enforce_equal(&Boolean::TRUE)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_relations::r1cs::{
        ConstraintLayer, ConstraintSynthesizer, ConstraintSystem, TracingMode::OnlyConstraints,
    };
    use ark_simple_payments::ledger::{Amount, Parameters, State};
    use ark_simple_payments::transaction::Transaction;
    use tracing_subscriber::layer::SubscriberExt;

    fn test_cs(rollup: UnaryRollup) -> bool {
        let mut layer = ConstraintLayer::default();
        layer.mode = OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);
        let cs = ConstraintSystem::new_ref();
        rollup.generate_constraints(cs.clone()).unwrap();
        let result = cs.is_satisfied().unwrap();
        if !result {
            println!("{:?}", cs.which_is_unsatisfied());
        }
        result
    }

    #[test]
    fn unary_rollup_validity_test() {
        let mut rng = ark_std::test_rng();
        let pp = Parameters::sample(&mut rng);
        let mut state = State::new(32, &pp);
        // Let's make an account for Alice.
        let (alice_id, _alice_pk, alice_sk) =
            state.sample_keys_and_register(&pp, &mut rng).unwrap();
        // Let's give her some initial balance to start with.
        state
            .update_balance(alice_id, Amount(20))
            .expect("Alice's account should exist");
        // Let's make an account for Bob.
        let (bob_id, _bob_pk, bob_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();

        // Alice wants to transfer 5 units to Bob.
        let mut temp_state = state.clone();
        let tx1 = Transaction::create(&pp, alice_id, bob_id, Amount(5), &alice_sk, &mut rng);
        assert!(tx1.validate(&pp, &temp_state));
        let rollup =
            UnaryRollup::with_state_and_transaction(pp.clone(), tx1, &mut temp_state, true)
                .unwrap();
        assert!(test_cs(rollup));

        let mut temp_state = state.clone();
        let bad_tx = Transaction::create(&pp, alice_id, bob_id, Amount(5), &bob_sk, &mut rng);
        assert!(!bad_tx.validate(&pp, &temp_state));
        assert!(matches!(temp_state.apply_transaction(&pp, &bad_tx), None));
        let rollup =
            UnaryRollup::with_state_and_transaction(pp.clone(), bad_tx, &mut temp_state, false)
                .unwrap();
        assert!(!test_cs(rollup));
    }
}
