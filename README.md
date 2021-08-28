<h1 align="center">Introduction to SNARK Development with `arkworks`</h1>

In this tutorial, we will learn how to write applications for use with state-of-the-art zkSNARKs using the [`arkworks`](https://arkworks.rs) ecosystem of SNARK libraries.

## Prerequisites

Because the `arkworks` ecosystem uses the Rust programming language, this tutorial assumes some familiarity with the basics of Rust. We also assume basic familiarity with zkSNARK concepts, and in particular with the following terminology:

* Public input/instance: a publicly known object that the verifier can check a zkSNARK proof against. For example, in a proof of membership in a Merkle tree, the Merkle tree root would be a public input.
* Private input/witness: an object that is known only to the prover, for either efficiency or privacy reasons. In the Merkle tree example, the Merkle tree authentication path would be a private input.
* Circuit: an encoding of a computation in a way that can be proven using a zkSNARK.
* Gadget: subcircuits corresponding to useful computations that can be used to build up the full circuit. In the Merkle tree example, a hash function gadget would be used repeatedly.

## Instructions

1. Ensure that you have the latest version of Rust installed (1.51 at the time of writing).  If you do not already have Rust installed, you can do so via [`rustup`](https://rustup.rs/). Linux users, please note that `arkworks` relies on Rust 1.51, which might be more recent than the Rust version provided by your distribution's package repositories; hence, even if you have installed Rust via your package manager, please install the latest Rust via `rustup`.

2. Clone this repository via `git clone https://github.com/arkworks-rs/r1cs-tutorial.git`

3. (Optional) While Rust works out of the box with your text editor of choice, using [Visual Studio Code](https://code.visualstudio.com/) along with the [`rust-analyzer`](https://marketplace.visualstudio.com/items?itemName=matklad.rust-analyzer) plugin makes Rust development easier.  

4. (Optional) Join the Telegram channel for [this tutorial](https://t.me/joinchat/4HzYWAYHVfpiODZh) and for the [`arkworks` ecosystem](https://t.me/joinchat/QaIYxIqLScnonTJ4) to ask questions interactively.

5. Proceed to the exercises below.

## Exercises

In this tutorial, we will construct a SNARK-based rollup for a simple payments system. In the course of doing so, you will learn how to use `arkworks` libraries for writing constraint systems, how to debug these circuits for both correctness and performance, and finally how to plug these circuits into zkSNARKs.

First, checkout the `main` branch in the repository.

### Exercise 1: Merkle Tree Example

We'll design a simple circuit for checking a Merkle tree membership path for a given leaf.
Open [`merkle-tree-example/README.md`](./merkle-tree-example/README.md).

### Exercise 2: Validating a single transaction

We'll design a circuit for validating a single transaction in a simple account-based payment system.
Open [`simple-payments/README.md`](./simple-payments/README.md) to first learn more about the payment system, and then open [`rollup/README.md`](./rollup/README.md) for the instructions for this exercise.

### Exercise 3: Writing a rollup circuit

We'll design a circuit for a rollup for batch verification of transactions in the foregoing payment system.
Open [`rollup/README.md`](./rollup/README.md) for the instructions for this exercise.

## Solutions

If you get stuck on one of the above exercises, or if you wish to compare your solution with ours, check out the [`solutions`](https://github.com/arkworks-rs/r1cs-tutorial/tree/solutions) branch on this repository.
