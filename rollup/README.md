# SNARK-based batch verification of transactions

SNARK proofs of validity of a batch of transactions are one way increasingly popular to increase the throughput of blockchains while also reducing the size of the blockchain. For example, they are being deployed in the Ethereum community under then name of "rollups". In this crate, we will design a constraint system for proving the validity of a batch of payments in the payment system in `simple-payments`. The high-level specification of this constraint system is defined next.

## Batch verification

At a high level, the constraint system for batch verification works as follows:

* Public input: initial state root (i.e., before applying current batch of transactions) and final state root (i.e., after applying current batch)
* Private inputs: current batch of transactions
* Checks:

  For each transaction in the batch, check the validity of applying that transaction:
  (1) Check a Merkle Tree path wrt initial root that demonstrates the existence of the sender's account.
  (2) Check a Merkle Tree path wrt initial root that demonstrates the existence of the receiver's account.
  (3) Verify the signature in the transaction with respect to the sender's public key.
  (4) Verify that sender.balance >= tx.amount (i.e., sender has sufficient funds).
  (5) Compute new balances for both the sender and the receiver.
  (6) Check a Merkle Tree path wrt final root for the new sender balance.
  (7) Check a Merkle Tree path wrt final root for the new receiver balance.

To make it easier to write out this constraint system, we've provided gadget equivalents of the key data structures from `simple-payments`. Find these via `cargo doc --open --no-deps`.

## Verifying a single transaction

Our first task will be to verify the state transitions involved when applying a single transaction. Go to [`transaction.rs`](./src/transaction.rs) and fill in the blanks in the `validate` method, following the hints there. Use the pseudocode [above](#batch-verification) and the logic in `simple_payments::transaction::Transaction::validate` as guides. To check if your code works, run `cargo test single_tx_validity_test`.


## Verifying a batch of transactions

Use the foregoing validation logic to verify a batch of transactions in the `generate_constraints` method in [`rollup.rs#148], and verify that your circuit works via `cargo test end_to_end`, and then test that you can generate a valid proof via `cargo test snark_verification`.