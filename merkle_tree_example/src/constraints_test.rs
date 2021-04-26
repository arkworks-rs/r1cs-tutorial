use crate::merkle_tree_example::constraints::MerkleTreeVerification;
use ark_crypto_primitives::crh::{pedersen, TwoToOneCRHGadget};
use ark_crypto_primitives::merkle_tree::Config;
use ark_crypto_primitives::{CRHGadget, MerkleTree, CRH};
use ark_ed_on_bls12_381::constraints::EdwardsVar;
use ark_ed_on_bls12_381::EdwardsProjective as JubJub;
use ark_r1cs_std::alloc::AllocVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_std::marker::PhantomData;

#[derive(Clone)]
pub(super) struct Window4x256;
impl pedersen::Window for Window4x256 {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

type H = pedersen::CRH<JubJub, Window4x256>;
type HG = pedersen::constraints::CRHGadget<JubJub, EdwardsVar, Window4x256>;

struct JubJubMerkleTreeParams;

impl Config for JubJubMerkleTreeParams {
    type LeafHash = H;
    type TwoToOneHash = H;
}
type JubJubMerkleTree = MerkleTree<JubJubMerkleTreeParams>;

#[test]
fn constraints_test() {
    let mut rng = ark_std::test_rng();
    // instantiate native tree
    let leaf_hash_params = H::setup(&mut rng).unwrap();
    let two_to_one_hash_params = H::setup(&mut rng).unwrap();
    let leaves: Vec<_> = (0..64).map(|v| [v, v + 1, v + 2]).collect();
    let native_mt =
        JubJubMerkleTree::new(&leaf_hash_params, &two_to_one_hash_params, &leaves).unwrap();

    let native_path = native_mt.generate_proof(5).unwrap();

    let cs = ConstraintSystem::new_ref();

    // generate constraints
    let leaf_hash_params_var = <HG as CRHGadget<H, _>>::ParametersVar::new_constant(
        ark_relations::ns!(cs, "leaf_crh_parameter"),
        &leaf_hash_params,
    )
    .unwrap();

    let two_to_one_crh_params_var = <HG as TwoToOneCRHGadget<H, _>>::ParametersVar::new_constant(
        ark_relations::ns!(cs, "two_to_one_crh_parameter"),
        &two_to_one_hash_params,
    )
    .unwrap();

    let mt_verification = MerkleTreeVerification::<JubJubMerkleTreeParams, HG, HG, _> {
        leaf_hash_params: leaf_hash_params_var,
        two_to_one_hash_params: two_to_one_crh_params_var,
        leaf: leaves[5].clone(),
        root: native_mt.root(),
        _f: PhantomData,
        authentication_path: native_path,
    };

    mt_verification.generate_constraints(cs.clone()).unwrap();

    println!("Number of constraints: {}", cs.num_constraints());
    assert!(cs.is_satisfied().unwrap())
}
