# Applying simple transactions inside SNARKs

In this part of the tutorial, we will look into how a simple account-based payment system can be designed on top of `arkworks` APIs in Rust. At the end of this step, you should be familiar with APIs for cryptographic primitives in  `arkworks`.

## High-level architecture

Our payment system maintains a ledger consisting of accounts with corresponding balances. In more detail, an "account" is a `(AccountID, SigPubKey, Balance)` triple. The ledger maintains a Merkle tree atop this list of accounts, so that the i-th leaf corresponds to the i-th AccountID. For simplicity and efficiency, in this tutorial we fix the number of accounts to be a small number (say, 256).

To register an account via `ledger::State::register`, a user provides their signature public key to the ledger, and receives a unique AccountID in return. The ledger stores the public key and an initial balance of 0 for this identifier. 
`AccountID`s are generated sequentially. That is, if `n` accounts have been registered so far, then the next registration will return `AccountID = n+1`.

To transfer value from their account to another account, the user first creates a `Transaction` consisting of the following pieces of information:
* Sender's account identifier
* Recipient's account identifier
* Transaction amount
* Signature on the previous three parts, using the signature public key associated with the sender's account.

The user then publishes this to the ledger, which applies the transaction via `ledger::State::apply_transaction`.

The latter method updates the ledger's information if the following conditions are satisfied:
* The sender's account exists
* The recipient's account exists
* The sender's account contains a balance greater than or equal to the transaction amount
* The signature is valid with respect to the public key stored in the sender's account

To enforce this logic, `Transaction::verify` performs the following steps on input a transaction `tx` and existing ledger state `State`.
* Look up the `(SigPubKey, Balance)` tuple corresponding to the sender's ID in the Merkle tree in `State`.
* Verify the transaction signature with respect to `SigPubKey`.
* Check that the `tx.amount <= Balance`.
* Check that the Merkle tree in `State` contains a path corresponding to the current recipient's ID. 

If these checks pass, the ledger decrements the sender's account balance by `tx.amount`, increments the recipient's balance by `tx.amount`, and updates the appropriate paths in the Merkle tree.

## Cryptographic primitives

### Signature scheme

We use a simple custom implementation of Schnorr signatures over the prime order subgroup of the [Jubjub](https://z.cash/technology/jubjub/) curve. This curve is implemented in the [ark-ed-on-bls12-381](https://docs.rs/ark-ed-on-bls12-381/0.3.0/ark_ed_on_bls12_381/) crate. Our Schnorr signature implementation can be found in [`src/signature/schnorr/mod.rs`](./src/signature/schnorr/mod.rs).

### Merkle tree

Our implementation uses the Merkle tree of [`ark-crypto-primitives`](https://docs.rs/ark-crypto-primitives/0.3.0/ark_crypto_primitives/merkle_tree/index.html). This is the same tree that we saw in the `merkle-tree-example` step. In our system, the concrete underlying hash function is the Pedersen hash function, as implemented in the [`ark-crypto-primitives` crate](https://docs.rs/ark-crypto-primitives/0.3.0/ark_crypto_primitives/crh/pedersen/index.html). This hash is implemented over the prime-order subgroup of the Jubjub curve.


## Code walk-through

To get an overview of important data structures as well as their associated methods, run `cargo doc --open --no-deps`.
