# Rollup example

In this folder, we build a circuit for a very simple rollup.
This rollup handles payments in a restricted account-based blockchain.

## Accounts & State Tree

In this chain, an Account is a (ID, Pubkey, Balance) tuple.
You can only pay to accounts that already exist (meaning they have an ID associated with them)

State is a single merkle tree, where the leaves are accounts indexed by ID.

## Tx processing

So a transaction is a (sender ID, recipient ID, Amount, Signature) tuple.
It is processed as follows:

* Looks up the leaf from the sender, and gets the public key.
* Checks the signature for the tx.
* Checks that the sender has a sufficient Balance to spend Amount.
* Checks that recipient exists
* If the above 3 are true, it updates the leaves for the sender and recipient balances,
and computes the new MT state root.

## Block processing

A block is a list of transactions.
It is processed by running the circuit for each transaction in order, applying all state updates within the transaction.
This means that the Merkle tree root for state will update after executing each tx in the block.



In this chain, there is a fixed set of addresses that can transact.
Each address has an associated account ID.