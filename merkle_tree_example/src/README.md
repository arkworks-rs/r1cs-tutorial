# Checking Merkle tree paths

In this example, our goal is to familiarize ourselves with the workflow of
writing constraints in `arkworks`. We do this by writing a simple circuit
 that just verifies a single Merkle tree authentication path, using the APIs in
https://github.com/arkworks-rs/crypto-primitives/tree/main/src/merkle_tree.

We will learn how to:

* Allocate public and private variables in a circuit
* Invoke gadgets
* Invoke SNARKs on the final circuit

## Getting started

To get started, let's take a look at a "native" version of the computation we want to perform.
Let's go to [`src/lib.rs`](src/lib.rs) and take a look at the example there.
