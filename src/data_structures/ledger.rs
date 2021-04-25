use std::collections::HashMap;
use blake2::Blake2s;
use ark_ed_on_bls12_381::EdwardsProjective;
use ark_crypto_primitives::signature::schnorr;
use ark_crypto_primitives::crh::{CRH, pedersen, injective_map::{PedersenCRHCompressor, TECompressor}};
use ark_crypto_primitives::merkle_tree::{self, MerkleTree};
use crate::data_structures::transaction::Transaction;


/// Account public key used to verify transaction signatures.
pub type AccountPublicKey = schnorr::PublicKey<EdwardsProjective>;

/// Account ID.
#[derive(Hash, Eq, PartialEq, Copy, Clone, Ord, PartialOrd)]
pub struct AccountId(u8);

impl AccountId {
    pub fn to_bytes_le(&self) -> Vec<u8> {
        vec![self.0]
    }
}

/// Transaction amount.
#[derive(Hash, Eq, PartialEq, Copy, Clone, PartialOrd, Ord)]
pub struct Amount(u64);

impl Amount {
    pub fn to_bytes_le(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.0.checked_add(other.0).map(Self)

    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.0.checked_sub(other.0).map(Self)
    }
}

#[derive(Hash, Eq, PartialEq, Copy, Clone)]
pub struct AccountInformation {
    pub public_key: AccountPublicKey,
    pub balance: Amount
}

impl AccountInformation {
    pub fn to_bytes_le(&self) -> Vec<u8> {
        ark_ff::to_bytes![self.public_key, self.balance.to_bytes_le()].unwrap()
    }
}

pub struct Parameters {
    pub sig_params: schnorr::Parameters<EdwardsProjective, Blake2s>,
    pub leaf_crh_params: <MerkleTreeCRH as CRH>::Parameters,
    pub two_to_one_crh_params: <MerkleTreeCRH as CRH>::Parameters,
}

pub type MerkleTreeCRH = PedersenCRHCompressor<EdwardsProjective, TECompressor, TwoToOneWindow>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;

// `WINDOW_SIZE * NUM_WINDOWS` = 2 * 256 bits = enough for hashing two outputs.
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
    pub account_merkle_tree: MerkleTree<MerkleConfig>,
    pub id_to_account_info: HashMap<AccountId, AccountInformation>,
    pub pub_key_to_id: HashMap<schnorr::PublicKey<EdwardsProjective>, AccountId>,
}

impl State {
    /// Create an empty ledger that supports `num_accounts` accounts.
    pub fn new(num_accounts: usize, parameters: &Parameters) -> Self {
        let height = ark_std::log2(num_accounts);
        let account_merkle_tree = MerkleTree::blank(
            &parameters.leaf_crh_params,
            &parameters.two_to_one_crh_params,
            height as usize,
        ).unwrap();
        let pub_key_to_id = HashMap::with_capacity(num_accounts);
        let id_to_account_info = HashMap::with_capacity(num_accounts);
        Self {
            account_merkle_tree,
            id_to_account_info,
            pub_key_to_id,
        }
    }

    /// Create a new account with account identifier `id` and public key `pub_key`.
    /// The initial balance is 0.
    pub fn new_account(&mut self, id: AccountId, public_key: AccountPublicKey) {
        let account_info = AccountInformation {
            public_key,
            balance: Amount(0),
        };
        self.pub_key_to_id.insert(public_key, id);
        self.account_merkle_tree.update(id.0 as usize, &account_info.to_bytes_le()).expect("should exist");
        self.id_to_account_info.insert(id, account_info);
    }


    /// Update the balance of `id` to `new_amount`.
    /// Returns `Some(())` if an account with identifier `id` exists already, and `None`
    /// otherwise.
    pub fn update_balance(&mut self, id: AccountId, new_amount: Amount) -> Option<()> {
        let tree = &mut self.account_merkle_tree;
        self.id_to_account_info.get_mut(&id).map(|account_info| {
            account_info.balance = new_amount;
            tree.update(id.0 as usize, &account_info.to_bytes_le()).expect("should exist");
        })
    }

    /// Update the state by applying the transaction `tx`, if `tx` is valid.
    pub fn apply_transaction(&mut self, pp: &Parameters, tx: &Transaction) -> Option<()> {
        if tx.verify_against_ledger_state(pp, self) {
            let old_sender_bal = self.id_to_account_info.get(&tx.sender)?.balance;
            let old_receiver_bal = self.id_to_account_info.get(&tx.recipient)?.balance;
            let new_sender_bal = old_sender_bal.checked_sub(tx.amount)?;
            let new_receiver_bal = old_receiver_bal.checked_add(tx.amount)?;
            self.update_balance(tx.sender, new_sender_bal);
            self.update_balance(tx.recipient, new_receiver_bal);
            Some(())
        } else {
            None
        }
    }
}
