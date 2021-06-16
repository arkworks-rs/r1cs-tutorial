use crate::account::AccountInformationVar;
use crate::ledger::*;
use crate::transaction::TransactionVar;
use crate::ConstraintF;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_simple_payments::{
    account::AccountInformation,
    ledger::{AccPath, AccRoot, Parameters, State},
    transaction::Transaction,
};

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
    pub sender_pre_tx_info_and_paths: Option<Vec<(AccountInformation, AccPath)>>,
    /// The authentication path corresponding to the sender's account information
    /// *after* applying the transactions.
    pub sender_post_paths: Option<Vec<AccPath>>,
    /// The recipient's account information and corresponding authentication path,
    /// *before* applying the transactions.
    pub recv_pre_tx_info_and_paths: Option<Vec<(AccountInformation, AccPath)>>,
    /// The authentication path corresponding to the recipient's account information
    /// *after* applying the transactions.
    pub recv_post_paths: Option<Vec<AccPath>>,
    /// List of state roots, so that the i-th root is the state roots before applying
    /// the i-th transaction. This means that `pre_tx_roots[0] == initial_root`.
    pub pre_tx_roots: Option<Vec<AccRoot>>,
    /// List of state roots, so that the i-th root is the state root after applying
    /// the i-th transaction. This means that `post_tx_roots[NUM_TX - 1] == final_root`.
    pub post_tx_roots: Option<Vec<AccRoot>>,
}

impl<const NUM_TX: usize> Rollup<NUM_TX> {
    pub fn new_empty(ledger_params: Parameters) -> Self {
        Self {
            ledger_params,
            initial_root: None,
            final_root: None,
            transactions: None,
            sender_pre_tx_info_and_paths: None,
            sender_post_paths: None,
            recv_pre_tx_info_and_paths: None,
            recv_post_paths: None,
            pre_tx_roots: None,
            post_tx_roots: None,
        }
    }

    pub fn only_initial_and_final_roots(
        ledger_params: Parameters,
        initial_root: AccRoot,
        final_root: AccRoot,
    ) -> Self {
        Self {
            ledger_params,
            initial_root: Some(initial_root),
            final_root: Some(final_root),
            transactions: None,
            sender_pre_tx_info_and_paths: None,
            sender_post_paths: None,
            recv_pre_tx_info_and_paths: None,
            recv_post_paths: None,
            pre_tx_roots: None,
            post_tx_roots: None,
        }
    }

    pub fn with_state_and_transactions(
        ledger_params: Parameters,
        transactions: &[Transaction],
        state: &mut State,
        validate_transactions: bool,
    ) -> Option<Self> {
        assert_eq!(transactions.len(), NUM_TX);
        let initial_root = Some(state.root());
        let mut sender_pre_tx_info_and_paths = Vec::with_capacity(NUM_TX);
        let mut recipient_pre_tx_info_and_paths = Vec::with_capacity(NUM_TX);
        let mut sender_post_paths = Vec::with_capacity(NUM_TX);
        let mut recipient_post_paths = Vec::with_capacity(NUM_TX);
        let mut pre_tx_roots = Vec::with_capacity(NUM_TX);
        let mut post_tx_roots = Vec::with_capacity(NUM_TX);
        for tx in transactions {
            if !tx.validate(&ledger_params, &*state) && validate_transactions {
                return None;
            }
        }
        for tx in transactions {
            let sender_id = tx.sender;
            let recipient_id = tx.recipient;
            let pre_tx_root = state.root();
            let sender_pre_acc_info = state.id_to_account_info.get(&sender_id)?.clone();
            let sender_pre_path = state
                .account_merkle_tree
                .generate_proof(sender_id.0 as usize)
                .unwrap();
            let recipient_pre_acc_info = state.id_to_account_info.get(&recipient_id)?.clone();
            let recipient_pre_path = state
                .account_merkle_tree
                .generate_proof(recipient_id.0 as usize)
                .unwrap();

            if validate_transactions {
                state.apply_transaction(&ledger_params, tx)?;
            } else {
                let _ = state.apply_transaction(&ledger_params, tx);
            }
            let post_tx_root = state.root();
            let sender_post_path = state
                .account_merkle_tree
                .generate_proof(sender_id.0 as usize)
                .unwrap();
            let recipient_post_path = state
                .account_merkle_tree
                .generate_proof(recipient_id.0 as usize)
                .unwrap();
            sender_pre_tx_info_and_paths.push((sender_pre_acc_info, sender_pre_path));
            recipient_pre_tx_info_and_paths.push((recipient_pre_acc_info, recipient_pre_path));
            sender_post_paths.push(sender_post_path);
            recipient_post_paths.push(recipient_post_path);
            pre_tx_roots.push(pre_tx_root);
            post_tx_roots.push(post_tx_root);
        }

        Some(Self {
            ledger_params,
            initial_root,
            final_root: Some(state.root()),
            transactions: Some(transactions.to_vec()),
            sender_pre_tx_info_and_paths: Some(sender_pre_tx_info_and_paths),
            recv_pre_tx_info_and_paths: Some(recipient_pre_tx_info_and_paths),
            sender_post_paths: Some(sender_post_paths),
            recv_post_paths: Some(recipient_post_paths),
            pre_tx_roots: Some(pre_tx_roots),
            post_tx_roots: Some(post_tx_roots),
        })
    }
}

impl<const NUM_TX: usize> ConstraintSynthesizer<ConstraintF> for Rollup<NUM_TX> {
    #[tracing::instrument(target = "r1cs", skip(self, cs))]
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
            self.initial_root.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Declare the final root as a public input.
        let final_root = AccRootVar::new_input(ark_relations::ns!(cs, "Final root"), || {
            self.final_root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let mut prev_root = initial_root;

        for i in 0..NUM_TX {
            let tx = self.transactions.as_ref().and_then(|t| t.get(i));

            let sender_acc_info = self.sender_pre_tx_info_and_paths.as_ref().map(|t| t[i].0);
            let sender_pre_path = self.sender_pre_tx_info_and_paths.as_ref().map(|t| &t[i].1);

            let recipient_acc_info = self.recv_pre_tx_info_and_paths.as_ref().map(|t| t[i].0);
            let recipient_pre_path = self.recv_pre_tx_info_and_paths.as_ref().map(|t| &t[i].1);

            let sender_post_path = self.sender_post_paths.as_ref().map(|t| &t[i]);
            let recipient_post_path = self.recv_post_paths.as_ref().map(|t| &t[i]);

            let pre_tx_root = self.pre_tx_roots.as_ref().map(|t| t[i]);
            let post_tx_root = self.post_tx_roots.as_ref().map(|t| t[i]);

            // Let's declare all these things!

            let tx = TransactionVar::new_witness(ark_relations::ns!(cs, "Transaction"), || {
                tx.ok_or(SynthesisError::AssignmentMissing)
            })?;
            // Declare the sender's initial account balance...
            let sender_acc_info = AccountInformationVar::new_witness(
                ark_relations::ns!(cs, "Sender Account Info"),
                || sender_acc_info.ok_or(SynthesisError::AssignmentMissing),
            )?;
            // ..., corresponding authentication path, ...
            let sender_pre_path =
                AccPathVar::new_witness(ark_relations::ns!(cs, "Sender Pre-Path"), || {
                    sender_pre_path.ok_or(SynthesisError::AssignmentMissing)
                })?;
            // ... and authentication path after the update.
            // TODO: Fill in the following
            // let sender_post_path = ???

            // Declare the recipient's initial account balance...
            let recipient_acc_info = AccountInformationVar::new_witness(
                ark_relations::ns!(cs, "Recipient Account Info"),
                || recipient_acc_info.ok_or(SynthesisError::AssignmentMissing),
            )?;
            // ..., corresponding authentication path, ...
            let recipient_pre_path =
                AccPathVar::new_witness(ark_relations::ns!(cs, "Recipient Pre-Path"), || {
                    recipient_pre_path.ok_or(SynthesisError::AssignmentMissing)
                })?;

            // ... and authentication path after the update.
            // TODO: Fill in the following
            // let recipient_post_path = ???

            // Declare the state root before the transaction...
            let pre_tx_root =
                AccRootVar::new_witness(ark_relations::ns!(cs, "Pre-tx Root"), || {
                    pre_tx_root.ok_or(SynthesisError::AssignmentMissing)
                })?;
            // ... and after the transaction.
            let post_tx_root =
                AccRootVar::new_witness(ark_relations::ns!(cs, "Post-tx Root"), || {
                    post_tx_root.ok_or(SynthesisError::AssignmentMissing)
                })?;

            // Enforce that the state root after the previous transaction equals
            // the starting state root for this transaction
            // TODO: Write this

            // Validate that the transaction signature and amount is correct.
            // TODO: Uncomment this
            // tx.validate(
            //     &ledger_params,
            //     &sender_acc_info,
            //     &sender_pre_path,
            //     &sender_post_path,
            //     &recipient_acc_info,
            //     &recipient_pre_path,
            //     &recipient_post_path,
            //     &pre_tx_root,
            //     &post_tx_root,
            // )?
            // .enforce_equal(&Boolean::TRUE)?;

            // Set the root for the next transaction.
            prev_root = post_tx_root;
        }
        // Check that the final root is consistent with the root computed after
        // applying all state transitions
        // TODO: implement this
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_relations::r1cs::{
        ConstraintLayer, ConstraintSynthesizer, ConstraintSystem, TracingMode::OnlyConstraints,
    };
    use ark_simple_payments::account::AccountId;
    use ark_simple_payments::ledger::{Amount, Parameters, State};
    use ark_simple_payments::transaction::Transaction;
    use tracing_subscriber::layer::SubscriberExt;

    fn test_cs<const NUM_TX: usize>(rollup: Rollup<NUM_TX>) -> bool {
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
    fn single_tx_validity_test() {
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
        let rollup = Rollup::<1>::with_state_and_transactions(
            pp.clone(),
            &[tx1.clone()],
            &mut temp_state,
            true,
        )
        .unwrap();
        assert!(test_cs(rollup));

        let bad_tx = Transaction::create(&pp, alice_id, bob_id, Amount(5), &bob_sk, &mut rng);
        assert!(!bad_tx.validate(&pp, &temp_state));
        assert!(matches!(temp_state.apply_transaction(&pp, &bad_tx), None));
        let rollup = Rollup::<1>::with_state_and_transactions(
            pp.clone(),
            &[bad_tx.clone()],
            &mut temp_state,
            false,
        )
        .unwrap();
        assert!(!test_cs(rollup));
    }

    #[test]
    fn end_to_end() {
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
        let rollup = Rollup::<1>::with_state_and_transactions(
            pp.clone(),
            &[tx1.clone()],
            &mut temp_state,
            true,
        )
        .unwrap();
        assert!(test_cs(rollup));

        let mut temp_state = state.clone();
        let rollup = Rollup::<2>::with_state_and_transactions(
            pp.clone(),
            &[tx1.clone(), tx1.clone()],
            &mut temp_state,
            true,
        )
        .unwrap();
        assert!(test_cs(rollup));
        assert_eq!(
            temp_state
                .id_to_account_info
                .get(&alice_id)
                .unwrap()
                .balance,
            Amount(10)
        );
        assert_eq!(
            temp_state.id_to_account_info.get(&bob_id).unwrap().balance,
            Amount(10)
        );

        // Let's try creating invalid transactions:
        // First, let's try a transaction where the amount is larger than Alice's balance.
        let mut temp_state = state.clone();
        let bad_tx = Transaction::create(&pp, alice_id, bob_id, Amount(21), &alice_sk, &mut rng);
        assert!(!bad_tx.validate(&pp, &temp_state));
        assert!(matches!(temp_state.apply_transaction(&pp, &bad_tx), None));
        let rollup = Rollup::<1>::with_state_and_transactions(
            pp.clone(),
            &[bad_tx.clone()],
            &mut temp_state,
            false,
        )
        .unwrap();
        assert!(!test_cs(rollup));

        // Next, let's try a transaction where the signature is incorrect:
        let mut temp_state = state.clone();
        let bad_tx = Transaction::create(&pp, alice_id, bob_id, Amount(5), &bob_sk, &mut rng);
        assert!(!bad_tx.validate(&pp, &temp_state));
        assert!(matches!(temp_state.apply_transaction(&pp, &bad_tx), None));
        let rollup = Rollup::<1>::with_state_and_transactions(
            pp.clone(),
            &[bad_tx.clone()],
            &mut temp_state,
            false,
        )
        .unwrap();
        assert!(!test_cs(rollup));

        // Finally, let's try a transaction to an non-existant account:
        let bad_tx =
            Transaction::create(&pp, alice_id, AccountId(10), Amount(5), &alice_sk, &mut rng);
        assert!(!bad_tx.validate(&pp, &state));
        assert!(matches!(temp_state.apply_transaction(&pp, &bad_tx), None));
    }

    // Builds a circuit with two txs, using different pubkeys & amounts every time.
    // It returns this circuit
    fn build_two_tx_circuit() -> Rollup<2> {
        use ark_std::rand::Rng;
        let mut rng = ark_std::test_rng();
        let pp = Parameters::sample(&mut rng);
        let mut state = State::new(32, &pp);
        // Let's make an account for Alice.
        let (alice_id, _alice_pk, alice_sk) =
            state.sample_keys_and_register(&pp, &mut rng).unwrap();
        // Let's give her some initial balance to start with.
        state
            .update_balance(alice_id, Amount(1000))
            .expect("Alice's account should exist");
        // Let's make an account for Bob.
        let (bob_id, _bob_pk, bob_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();

        let amount_to_send = rng.gen_range(0..200);

        // Alice wants to transfer amount_to_send units to Bob, and does this twice
        let mut temp_state = state.clone();
        let tx1 = Transaction::create(
            &pp,
            alice_id,
            bob_id,
            Amount(amount_to_send),
            &alice_sk,
            &mut rng,
        );
        let rollup = Rollup::<2>::with_state_and_transactions(
            pp.clone(),
            &[tx1.clone(), tx1.clone()],
            &mut temp_state,
            true,
        )
        .unwrap();
        rollup
    }

    #[test]
    fn snark_verification() {
        use ark_bls12_381::Bls12_381;
        use ark_groth16::Groth16;
        use ark_snark::SNARK;
        // Use a circuit just to generate the circuit
        let circuit_defining_cs = build_two_tx_circuit();

        let mut rng = ark_std::test_rng();
        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(circuit_defining_cs, &mut rng).unwrap();

        // Use the same circuit but with different inputs to verify against
        // This test checks that the SNARK passes on the provided input
        let circuit_to_verify_against = build_two_tx_circuit();
        let public_input = [
            circuit_to_verify_against.initial_root.unwrap(),
            circuit_to_verify_against.final_root.unwrap(),
        ];

        let proof = Groth16::prove(&pk, circuit_to_verify_against, &mut rng).unwrap();
        let valid_proof = Groth16::verify(&vk, &public_input, &proof).unwrap();
        assert!(valid_proof);

        // Use the same circuit but with different inputs to verify against
        // This test checks that the SNARK fails on the wrong input
        let circuit_to_verify_against = build_two_tx_circuit();
        // Error introduced, used the final root twice!
        let public_input = [
            circuit_to_verify_against.final_root.unwrap(),
            circuit_to_verify_against.final_root.unwrap(),
        ];

        let proof = Groth16::prove(&pk, circuit_to_verify_against, &mut rng).unwrap();
        let valid_proof = Groth16::verify(&vk, &public_input, &proof).unwrap();
        assert!(!valid_proof);
    }
}
// Optimization ideas: remove `pre_tx_roots` entirely.
