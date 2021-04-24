use blake2::Blake2s;
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_crypto_primitives::signature::schnorr;
use ark_crypto_primitives::crh::{CRH, pedersen, injective_map::{PedersenCRHCompressor, TECompressor}};
use ark_crypto_primitives::merkle_tree::{self, MerkleTree};


pub struct Parameters {
    pub sig_params: schnorr::Parameters<EdwardsProjective, Blake2s>,
    pub leaf_crh_params: <MerkleTreeCRH as CRH>::Parameters,
    pub two_to_one_crh_params: <MerkleTreeCRH as CRH>::Parameters,
}

pub type MerkleTreeCRH = PedersenCRHCompressor<EdwardsProjective, TECompressor, TwoToOneWindow>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;
// `WINDOW_SIZE * NUM_WINDOWS` = 2 * 256 bits
impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 128;
    const NUM_WINDOWS: usize = 4;
}

pub struct MerkleConfig;
impl merkle_tree::Config for MerkleConfig {
    type LeafHash = MerkleTreeCRH;
    type TwoToOneHash = MerkleTreeCRH;
}

pub struct State {
    account_tree: MerkleTree<MerkleConfig>
}
