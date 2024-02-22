use curve_trees::{
    tests::membership,
    ed25519_api::{
        init as ed25519_init, GeneratorsAndTree as CurveTreesGeneratorsAndTree, Proof,
        prove as ed25519_prove, verify as ed25519_verify, add_leaves,
        make_blind as ed25519_make_blind
    }
};

use ciphersuite::{Ciphersuite, Ed25519, group::Group};

#[cxx::bridge]
mod ffi {
    // Rust types and signatures exposed to C++.
    #[namespace = "monero_rust::curve_trees"]
    extern "Rust" {
        type GeneratorsAndTree;
        // TODO: don't pass blinded point back
        type BlindedPointAndProof;

        fn init() -> Box<GeneratorsAndTree>;
        fn add_squashed_enote_to_tree(state: &mut Box<GeneratorsAndTree>, squashed_enote: &[u8]);
        fn make_blind(generators_and_tree: &mut Box<GeneratorsAndTree>) -> [u8; 32];
        // TODO: pass blinded point in to prove
        fn prove(generators_and_tree: &Box<GeneratorsAndTree>, blind: &[u8], squashed_enote: &[u8]) -> Box<BlindedPointAndProof>;
        fn verify(generators_and_tree: &Box<GeneratorsAndTree>, proof_res: &Box<BlindedPointAndProof>) -> bool;
    }
}

pub struct GeneratorsAndTree(CurveTreesGeneratorsAndTree);

pub struct BlindedPointAndProof {
    blinded_point: <Ed25519 as Ciphersuite>::G,
    proof: Proof,
}

pub fn init() -> Box<GeneratorsAndTree> {
    // TODO: share C1 H generator with Seraphis (required)
    // TODO: use constant generators, don't randomly generate each init (required)
    // TODO: share bulletproof generators with Seraphis (perf optimization)
    // TODO: share C1 G generator with Seraphis (cleanliness)
    Box::new(GeneratorsAndTree(ed25519_init()))
}

pub fn add_squashed_enote_to_tree(generators_and_tree: &mut Box<GeneratorsAndTree>, mut squashed_enote: &[u8]) {
    let leaf = <Ed25519 as Ciphersuite>::read_G(&mut squashed_enote).unwrap();
    let leaves: Vec<<Ed25519 as Ciphersuite>::G> = vec![leaf];
    add_leaves(&mut generators_and_tree.0, &leaves);
}

pub fn make_blind(generators_and_tree: &mut Box<GeneratorsAndTree>) -> [u8; 32] {
    let blind = ed25519_make_blind(&generators_and_tree.0);
    blind.to_bytes()
}

pub fn prove(generators_and_tree: &Box<GeneratorsAndTree>, mut blind: &[u8], mut squashed_enote: &[u8]) -> Box<BlindedPointAndProof> {
    let blind = <Ed25519 as Ciphersuite>::read_F(&mut blind).unwrap();
    let point_in_tree = <Ed25519 as Ciphersuite>::read_G(&mut squashed_enote).unwrap();
    let proof_res = ed25519_prove(&generators_and_tree.0, blind, point_in_tree);
    Box::new(BlindedPointAndProof { blinded_point: proof_res.0, proof: proof_res.1 })
}

pub fn verify(generators_and_tree: &Box<GeneratorsAndTree>, proof_res: &Box<BlindedPointAndProof>) -> bool {
    ed25519_verify(&generators_and_tree.0, proof_res.blinded_point, &proof_res.proof)
}