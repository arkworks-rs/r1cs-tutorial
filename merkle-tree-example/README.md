# Checking Merkle tree paths

In this example, our goal is to familiarize ourselves with the workflow of
writing constraints in `arkworks`. We do this by writing a simple constraint system
 that just verifies a single Merkle tree authentication path, using the APIs in
https://github.com/arkworks-rs/crypto-primitives/tree/main/src/merkle_tree.

We will learn how to:

* Allocate public and private variables in a circuit
* Invoke gadgets
* Invoke SNARKs on the final circuit

## Getting started

Let's start by taking a look at a "native" version of the computation we want to perform.
Let's go to [`src/lib.rs`](src/lib.rs) and look at the code example in `test_merkle_tree`.

In this example we create a Merkle tree using the Pedersen hash function, and then we check that a claimed path for some leaf corresponds to a given root.

Our goal is to replicate this check with constraints.

## Writing constraints to check Merkle tree paths

We'll be adding our constraints in [`src/constraints.rs`](src/constraints.rs), inside the function `generate_constraints`. Recall that our task is to check that the prover knows a valid membership path for a given leaf inside a Merkle tree with a given root.

We start by allocating the Merkle tree root `root` as a public input variable:
```rust
let root = RootVar::new_input(ark_relations::ns!(cs, "root_var"), || Ok(&self.root))?;
```
Let's go over this incantation part-by-part.
* `RootVar` is a [type alias](https://doc.rust-lang.org/book/ch19-04-advanced-types.html#creating-type-synonyms-with-type-aliases) for the output of the hash function used in the Merkle tree.
* `new_input` is a method on the [`AllocVar`](https://docs.rs/ark-r1cs-std/0.3.0/ark_r1cs_std/alloc/trait.AllocVar.html) trait that reserves variables corresponding to the root. The reserved variables are of the public input type, as the root is a public input against which we'll check the private path.
    * The [`ns!`](https://docs.rs/ark-relations/0.3.0/ark_relations/macro.ns.html) macro enters a new namespace in the constraint system, with the aim of making it easier to identify failing constraints when debugging.
    * The closure `|| Ok(self.root)` provides an (optional) assignment to the variables reserved by `new_input`. The closure is invoked only if we need the assignment. For example, it is not invoked during SNARK setup.

We similarly allocate the leaf as a public input variable, and allocate the parameters of the hash as "constants" in the constraint system. This means that these parameters are "baked" into the constraint system when it is created, and changing these parameters would result in a different constraint system. Finally, we allocate the membership path as a private witness variable.

Now, we must  fill in the blanks by adding constraints to check the membership path. Go ahead and follow the hint in `constraints.rs` to complete this task.

## Testing our constraints

Once we've written our path-checking constraints, we have to check that the resulting constraint system satisfies two properties: that it accepts a valid membership path, and that it rejects an invalid path. We perform these checks via two tests: `merkle_tree_constraints_correctness` and `merkle_tree_constraints_soundness`. Go ahead and look at those for an example of how to test constraint systems in practice.

This wraps up this part of the tutorial. Go to the `simple_payments` folder for the next step!