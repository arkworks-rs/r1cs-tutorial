use ark_crypto_primitives::crh::TwoToOneCRH;
use ark_crypto_primitives::merkle_tree::{Config, MerkleTree, Path};

pub mod common;
use common::*;

mod constraints;
// mod constraints_test;

#[derive(Clone)]
pub struct MerkleConfig;
impl Config for MerkleConfig {
    // Our Merkle tree relies on two hashes: one to hash leaves, and one to hash pairs
    // of internal nodes.
    type LeafHash = LeafHash;
    type TwoToOneHash = TwoToOneHash;
}

/// A Merkle tree containing account information.
pub type SimpleMerkleTree = MerkleTree<MerkleConfig>;
/// The root of the account Merkle tree.
pub type Root = <TwoToOneHash as TwoToOneCRH>::Output;
/// A membership proof for a given account.
pub type SimplePath = Path<MerkleConfig>;

// Run this test via `cargo test --release test_merkle_tree`.
#[test]
fn test_merkle_tree() {
    use ark_crypto_primitives::crh::CRH;
    // Let's set up an RNG for use within tests. Note that this is *not* safe
    // for any production use.
    let mut rng = ark_std::test_rng();

    // First, let's sample the public parameters for the hash functions:
    let leaf_crh_params = <LeafHash as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <TwoToOneHash as TwoToOneCRH>::setup(&mut rng).unwrap();

    // Next, let's construct our tree.
    // This follows the API in https://github.com/arkworks-rs/crypto-primitives/blob/6be606259eab0aec010015e2cfd45e4f134cd9bf/src/merkle_tree/mod.rs#L156
    let tree = SimpleMerkleTree::new(
        &leaf_crh_params,
        &two_to_one_crh_params,
        &[1u8, 2u8, 3u8, 10u8, 9u8, 17u8, 70u8, 45u8], // the i-th entry is the i-th leaf.
    )
    .unwrap();

    // Now, let's try to generate a membership proof for the 5th item.
    let proof = tree.generate_proof(4).unwrap(); // we're 0-indexing!
                                                 // This should be a proof for the membership of a leaf with value 9. Let's check that!

    // First, let's get the root we want to verify against:
    let root = tree.root();
    // Next, let's verify the proof!
    let result = proof
        .verify(
            &leaf_crh_params,
            &two_to_one_crh_params,
            &root,
            &[9u8], // The claimed leaf
        )
        .unwrap();
    assert!(result);
}
