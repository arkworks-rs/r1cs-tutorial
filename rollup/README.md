# Rollup example

In this crate, we build a circuit for proving the validity of a batch of payments in a simple account-based blockchain. This proof of validity is also called a SNARK-based Rollup in the Ethereum community.

## Accounts and state tree

In this chain, an "Account" is a (ID, PubKey, Balance) triple. Upon registration, (PubKey, Balance) is stored in a Merkle tree, at the index specified by the identifier. For simplicity and efficiency, in this tutorial we support only a fixed number of accounts (say, 256).

## Tx processing

To transfer currency from one account to another, users create transactions, which contain the sender's ID, the receiver's ID, the transaction amount, and a signature on the foregoing with respect to the sender's secret key. A transaction is valid if:
* The sender's account exists
* The recipient's account exists.
* The sender's account contains sufficient balance to fund the transaction.
* The signature is valid with respect to the sender's public key.
To check these conditions, a transaction verifier performs the following steps:
* Looks up the (PubKey, Balance) tuple in the Merkle tree that corresponds to the sender's ID.
* Verifies the transaction signature with respect to PubKey.
* Checks that the tx.amount <= Balance.
* Checks that the Merkle tree contains a path corresponding to the current recipient's ID. 

If the foregoing checks pass, the transaction can be applied by updating the respective balances, and recomputing the Merkle tree.

## Batch verification

SNARK proofs of validity of a batch of transactions are one way to increase the throughput of blockchains while also reducing the size of the blockchain. At a high level, the circuit for batch verification works as follows:
* Public input: initial and final state roots
* Private inputs: transactions
* For each transaction:
  * Check a Merkle Tree path wrt initial root that demonstrates the existence of the sender's account.
  * Check a Merkle Tree path wrt initial root that demonstrates the existence of the receiver's account.
  * Verify the signature in the transaction with respect to the sender's public key.
  * Verify that the sender has sufficient funds.
  * Compute new balances for both the sender and the receiver.
  * Check a Merkle Tree path wrt final root for the new sender balance.
  * Check a Merkle Tree path wrt final root for the new receiver balance.

A block is a list of transactions.
It is processed by running the circuit for each transaction in order, applying all state updates within the transaction.
This means that the Merkle tree root for state will update after executing each tx in the block.
