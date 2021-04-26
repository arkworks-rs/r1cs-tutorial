use ark_simple_payments::{
    ledger::{AccRoot, State, Parameters, AccPath},
    account::AccountInformation,
    transaction::Transaction,
};
use crate::ConstraintF;
use crate::ledger::*;
use crate::account::AccountInformationVar;
use ark_relations::r1cs::{ConstraintSystemRef, ConstraintSynthesizer, SynthesisError};
use ark_r1cs_std::prelude::*;

pub struct Rollup<const NUM_TX: usize> {
    /// The ledger parameters.
    pub ledger_params: Parameters,
    /// The Merkle tree root before applying this batch of transactions.
    pub initial_root: Option<AccRoot>,
    /// The Merkle tree root after applying this batch of transactions.
    pub final_root: Option<AccRoot>,
    /// The current batch of transactions.
    pub transactions: Option<Vec<Transaction>>,
    /// The sender's account information and corresponding authentication path,
    /// *before* applying the transactions.
    pub sender_pre_tx_info_and_path: Option<Vec<(AccountInformation, AccPath)>>,
    /// The receiver's account information and corresponding authentication path,
    /// *before* applying the transactions.
    pub recv_pre_tx_info_and_path: Option<Vec<(AccountInformation, AccPath)>>,
    /// List of state roots, so that the i-th root is the state roots before applying
    /// the i-th transaction. This means that `pre_tx_roots[0] == initial_root`.
    pub pre_tx_roots: Option<Vec<AccRoot>>,
    /// List of state roots, so that the i-th root is the state root after applying
    /// the i-th transaction. This means that `post_tx_roots[NUM_TX - 1] == final_root`.
    pub post_tx_roots: Option<Vec<AccRoot>>,
}

impl<const NUM_TX: usize> Rollup<NUM_TX> {
    pub fn new_empty(ledger_params: Parameters,) -> Self {
        Self {
            ledger_params,
            initial_root: None,
            final_root: None,
            transactions: None,
            sender_pre_tx_info_and_path: None,
            recv_pre_tx_info_and_path: None,
            pre_tx_roots: None,
            post_tx_roots: None,
        }
    }

    pub fn only_initial_and_final_roots(ledger_params: Parameters, initial_root: AccRoot, final_root: AccRoot) -> Self {
        Self {
            ledger_params,
            initial_root: Some(initial_root),
            final_root: Some(final_root),
            transactions: None,
            sender_pre_tx_info_and_path: None,
            recv_pre_tx_info_and_path: None,
            pre_tx_roots: None,
            post_tx_roots: None,

        }
    }

    pub fn with_state_and_transactions(
        ledger_params: Parameters,
        transactions: &[Transaction],
        state: &mut State
    ) -> Option<Self> {
        assert_eq!(transactions.len(), NUM_TX);
        let initial_root = Some(state.root());
        let mut sender_pre_tx_info_and_path = Vec::with_capacity(NUM_TX);
        let mut recipient_pre_tx_info_and_path = Vec::with_capacity(NUM_TX);
        let mut pre_tx_roots = Vec::with_capacity(NUM_TX);
        let mut post_tx_roots = Vec::with_capacity(NUM_TX);
        for tx in transactions {
            let sender_id = tx.sender;
            let recipient_id = tx.recipient;
            let pre_tx_root = state.root();
            let sender_pre_acc_info = state.id_to_account_info.get(&sender_id)?.clone();
            let sender_pre_path = state.account_merkle_tree.generate_proof(sender_id.0 as usize).unwrap();
            let recipient_pre_acc_info = state.id_to_account_info.get(&recipient_id)?.clone();
            let recipient_pre_path = state.account_merkle_tree.generate_proof(recipient_id.0 as usize).unwrap();

            state.apply_transaction(&ledger_params, tx)?;
            let post_tx_root = state.root();

            sender_pre_tx_info_and_path.push((sender_pre_acc_info, sender_pre_path));
            recipient_pre_tx_info_and_path.push((recipient_pre_acc_info, recipient_pre_path));
            pre_tx_roots.push(pre_tx_root);
            post_tx_roots.push(post_tx_root);
        }

        Some(Self {
            ledger_params,
            initial_root,
            final_root: Some(state.root()),
            transactions: Some(transactions.to_vec()),
            sender_pre_tx_info_and_path: Some(sender_pre_tx_info_and_path),
            recv_pre_tx_info_and_path: Some(recipient_pre_tx_info_and_path),
            pre_tx_roots: Some(pre_tx_roots),
            post_tx_roots: Some(post_tx_roots),
        })
    }
}

impl<const NUM_TX: usize> ConstraintSynthesizer<ConstraintF> for Rollup<NUM_TX> {
    fn generate_constraints(self, cs: ConstraintSystemRef<ConstraintF>) -> Result<(), SynthesisError> {
        // Declare the parameters as constants.
        let ledger_params = ParametersVar::new_constant(ark_relations::ns!(cs, "Ledger parameters"), &self.ledger_params)?;
        // Declare the initial root as a public input.
        let initial_root = AccRootVar::new_input(
            ark_relations::ns!(cs, "Initial root"),
            || self.initial_root.ok_or(SynthesisError::AssignmentMissing)
        )?;

        // Declare the final root as a public input.
        let final_root = AccRootVar::new_input(
            ark_relations::ns!(cs, "Final root"),
            || self.final_root.ok_or(SynthesisError::AssignmentMissing)
        )?;
        let mut prev_root = initial_root;

        for i in 0..NUM_TX {
            let tx = self.transactions.and_then(|t| t.get(i));
            let sender_acc_info = self.sender_pre_tx_info_and_path.map(|t| t[i].0);
            let sender_path = self.sender_pre_tx_info_and_path.map(|t| t[i].1);
            let recipient_acc_info = self.recv_pre_tx_info_and_path.map(|t| t[i].0);
            let recipient_path = self.recv_pre_tx_info_and_path.map(|t| t[i].1);
            let pre_tx_root = self.pre_tx_roots.map(|t| t[i]);
            let post_tx_root = self.post_tx_roots.map(|t| t[i]);

            // Let's declare all these things!

            let tx = TransactionVar::new_witness(
                ark_relations::ns!(cs, "Transaction"),
                || tx.ok_or(SynthesisError::AssignmentMissing)
            )?;
            // Declare the sender's initial account balance...
            let mut sender_acc_info = AccountInformationVar::new_witness(
                ark_relations::ns!(cs, "Sender Account Info"),
                || sender_acc_info.ok_or(SynthesisError::AssignmentMissing)
            )?;
            // ... and corresponding authentication path.
            let sender_path = AccPathVar::new_witness(
                ark_relations::ns!(cs, "Sender Path"),
                || sender_path.ok_or(SynthesisError::AssignmentMissing)
            )?;
            // Declare the recipient's initial account balance...
            let mut recipient_acc_info = AccountInformationVar::new_witness(
                ark_relations::ns!(cs, "Recipient Account Info"),
                || recipient_acc_info.ok_or(SynthesisError::AssignmentMissing)
            )?;
            // ... and corresponding authentication path.
            let recipient_path = AccPathVar::new_witness(
                ark_relations::ns!(cs, "Recipient Path"),
                || recipient_path.ok_or(SynthesisError::AssignmentMissing)
            )?;
            // Declare the state root before the transaction...
            let pre_tx_root = AccRootVar::new_witness(
                ark_relations::ns!(cs, "Pre-tx Root"),
                || pre_tx_root.ok_or(SynthesisError::AssignmentMissing)
            )?;
            // ... and after the transaction.
            let post_tx_root = AccRootVar::new_witness(
                ark_relations::ns!(cs, "Post-tx Root"),
                || post_tx_root.ok_or(SynthesisError::AssignmentMissing)
            )?;
            // Enforce that the state root after the previous transaction equals 
            // the starting state root for this transaction
            prev_root.enforce_equal(&pre_tx_root)?;

            // Validate that the transaction signature and amount is correct.
            tx.validate(
                &ledger_params, 
                &sender_acc_info,
                &sender_path,
                &recipient_acc_info,
                &recipient_path,
                &pre_tx_root,
                &post_tx_root,
            )?.enforce_equal(&Boolean::TRUE)?;


            // Set the root for the next transaction.
            prev_root = post_tx_root; 
        }
        // Check that the final root is consistent with the root computed after
        // applying all state transitions
        prev_root.enforce_equal(&final_root)?;
        Ok(())
    }
}
// Optimization ideas: remove `pre_tx_roots` entirely.
