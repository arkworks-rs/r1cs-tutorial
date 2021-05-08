<h1 align="center">Introduction to SNARK Development with arkworks</h1>

In this tutorial, we will learn how to write applications for use with state-of-the-art zkSNARKs using the [`arkworks`](https://arkworks.rs) ecosystem of SNARK libraries.

## Prerequisites

Because the `arkworks` ecosystem uses the Rust programming language, this tutorial assumes some familiarity with the basics of Rust. We also assume basic familiarity with zkSNARK concepts, and in particular with the following terminology:

* Public input/instance: a publicly known object that the verifier can check a zkSNARK proof against. For example, in a proof of membership in a Merkle tree, the Merkle tree root would be a public input.
* Private input/witness: an object that is known only to the prover, for either efficiency or privacy reasons. In the Merkle tree example, the Merkle tree authentication path would be a private input.
* Circuit: an encoding of a computation in a way that can be proven using a zkSNARK.
* Gadget: subcircuits corresponding to useful computations that can be used to build up the full circuit. In the Merkle tree example, a hash function gadget would be used repeatedly.

## Instructions

1. Ensure that you have the latest version of Rust installed (1.51 at the time of writing).  If you do not already have Rust installed, you can do so via [`rustup`](https://rustup.rs/). Linux users, please note that `arkworks` relies on Rust 1.49, which might be more recent than the Rust version provided by your distribution's package repositories; hence, even if you have installed Rust via your package manager, please install the latest Rust via `rustup`.

2. Clone this repository via `git clone https://github.com/arkworks-rs/r1cs-tutorial.git`

3. (Optional) While Rust works out of the box with your text editor of choice, using [Visual Studio Code](https://code.visualstudio.com/) along with the [`rust-analyzer`](https://marketplace.visualstudio.com/items?itemName=matklad.rust-analyzer) plugin makes Rust development easier.  

4. Proceed to the exercises below.

## Exercises

In this tutorial, we will construct a SNARK-based rollup for a simple payments system. In the course of doing so, you will learn how to use `arkworks` libraries for writing circuits, how to debug these circuits for both correctness and performance, and finally how to plug these circuits into zkSNARKs.

First, checkout the `main` branch in the repository.

### Exercise 1: Merkle Tree Example
Open [`merkle_tree_example/src/README.md`](./merkle_tree_example/src/README.md).

### Exercise 2: Validating a single transaction

We'll design a simple circuit for validating a single transaction.

### Exercise 3: Writing a rollup circuit

We'll design a simple circuit for rollups.
