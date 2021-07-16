#![allow(dead_code)]

use blake2b_rs::Blake2bBuilder;
use ckb_error::assert_error_eq;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types;
use ckb_types::core::{Capacity, DepType, ScriptHashType, TransactionBuilder};
use ckb_types::packed::{
    BytesOptBuilder, CellDep, CellInput, CellOutput, Script, WitnessArgsBuilder,
};
use ckb_types::prelude::{Builder, Entity, Pack};
use rand::prelude::thread_rng;
use sparse_merkle_tree::H256;

use misc::*;
use xudt_test::xudt_rce_mol::{
    RCCellVecBuilder, RCDataBuilder, RCDataUnion, SmtProofBuilder, SmtUpdateActionBuilder,
    SmtUpdateItemBuilder, SmtUpdateItemVecBuilder,
};

mod misc;

#[test]
fn test_rce_validator_bl_append_key() {
    let old_smt_keys = vec![(H256::from(K1.clone()), SMT_EXISTING.clone())];
    let new_smt_keys = vec![
        (H256::from(K1.clone()), SMT_EXISTING.clone()),
        (H256::from(K2.clone()), SMT_EXISTING.clone()),
    ];
    let mod_keys = vec![(H256::from(K2.clone()), SMT_NOT_EXISTING.clone())];
    let packed_values = 0b0000_0001;
    let flag = 0;

    let old_smt = new_smt(old_smt_keys);
    let new_smt = new_smt(new_smt_keys);
    let old_smt_root = old_smt.root().clone();
    let new_smt_root = new_smt.root().clone();

    let merkle_proof = old_smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _)| k).collect())
        .unwrap();
    let merkle_proof_compiled = merkle_proof.clone().compile(mod_keys.clone()).unwrap();
    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.into();

    let smt_update_item = SmtUpdateItemBuilder::default()
        .key(ckb_types::packed::Byte32::from_slice(&K2.clone()).unwrap())
        .packed_values(packed_values.into())
        .build();
    let smt_update_item_vec = SmtUpdateItemVecBuilder::default()
        .push(smt_update_item)
        .build();
    let smt_proof = SmtProofBuilder::default()
        .set(
            merkle_proof_bytes
                .into_iter()
                .map(|v| ckb_types::molecule::prelude::Byte::new(v))
                .collect(),
        )
        .build();
    let smt_update_action = SmtUpdateActionBuilder::default()
        .updates(smt_update_item_vec)
        .proof(smt_proof)
        .build();
    let smt_update_action_bytes = smt_update_action.as_slice();

    let witness_args = WitnessArgsBuilder::default()
        .input_type(
            BytesOptBuilder::default()
                .set(Some(Pack::pack(&ckb_types::bytes::Bytes::copy_from_slice(
                    smt_update_action_bytes,
                ))))
                .build(),
        )
        .build();
    let witness_args_bytes = witness_args.as_slice();

    let mut data_loader = DummyDataLoader::new();
    let mut rng = thread_rng();

    let always_success_cell_data: ckb_types::bytes::Bytes = ALWAYS_SUCCESS_BIN.clone();
    let always_success_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(always_success_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let always_success_out_point = gen_random_out_point(&mut rng);
    let always_success_code_hash = CellOutput::calc_data_hash(&always_success_cell_data);
    let always_success_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(always_success_code_hash.clone())
        .build();

    let rce_validator_cell_data: ckb_types::bytes::Bytes = RCE_VALIDATOR_BIN.clone();
    let rce_validator_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(rce_validator_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let rce_validator_out_point = gen_random_out_point(&mut rng);
    let mut rce_validator_args_bytes: [u8; 33] = [0; 33];
    rce_validator_args_bytes[0..32].copy_from_slice(&TYPE_ID_CODE_HASH[..]);
    rce_validator_args_bytes[32] = flag;
    let rce_validator_args =
        ckb_types::bytes::Bytes::copy_from_slice(rce_validator_args_bytes.as_ref());

    let rce_validator_code_hash = CellOutput::calc_data_hash(&rce_validator_cell_data);
    let rce_validator_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(rce_validator_code_hash.clone())
        .args(rce_validator_args.pack())
        .build();

    let old_rce_out_point = gen_random_out_point(&mut rng);
    let old_rce_cell_data = build_rc_rule(&old_smt_root.into(), true, false);
    let old_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(21000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();

    let new_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(20000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();
    let new_rce_cell_data = build_rc_rule(&new_smt_root.into(), true, false);

    data_loader.cells.insert(
        always_success_out_point.clone(),
        (always_success_cell, always_success_cell_data.clone()),
    );
    data_loader.cells.insert(
        rce_validator_out_point.clone(),
        (rce_validator_cell, rce_validator_cell_data.clone()),
    );
    data_loader
        .cells
        .insert(old_rce_out_point.clone(), (old_rce_cell, old_rce_cell_data));

    let tx = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(always_success_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(rce_validator_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .input(CellInput::new(old_rce_out_point, 0))
        .output(new_rce_cell)
        .output_data(new_rce_cell_data.pack())
        .witness(ckb_types::bytes::Bytes::copy_from_slice(witness_args_bytes).pack())
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let r = verifier.verify(MAX_CYCLES);
    assert!(r.is_ok())
}

#[test]
fn test_rce_validator_bl_append_key_with_freeze_type() {
    let old_smt_keys = vec![(H256::from(K1.clone()), SMT_EXISTING.clone())];
    let new_smt_keys = vec![
        (H256::from(K1.clone()), SMT_EXISTING.clone()),
        (H256::from(K2.clone()), SMT_EXISTING.clone()),
    ];
    let mod_keys = vec![(H256::from(K2.clone()), SMT_NOT_EXISTING.clone())];
    let packed_values = 0b0000_0001;
    let flag = 2;

    let old_smt = new_smt(old_smt_keys);
    let new_smt = new_smt(new_smt_keys);
    let old_smt_root = old_smt.root().clone();
    let new_smt_root = new_smt.root().clone();

    let merkle_proof = old_smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _)| k).collect())
        .unwrap();
    let merkle_proof_compiled = merkle_proof.clone().compile(mod_keys.clone()).unwrap();
    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.into();

    let smt_update_item = SmtUpdateItemBuilder::default()
        .key(ckb_types::packed::Byte32::from_slice(&K2.clone()).unwrap())
        .packed_values(packed_values.into())
        .build();
    let smt_update_item_vec = SmtUpdateItemVecBuilder::default()
        .push(smt_update_item)
        .build();
    let smt_proof = SmtProofBuilder::default()
        .set(
            merkle_proof_bytes
                .into_iter()
                .map(|v| ckb_types::molecule::prelude::Byte::new(v))
                .collect(),
        )
        .build();
    let smt_update_action = SmtUpdateActionBuilder::default()
        .updates(smt_update_item_vec)
        .proof(smt_proof)
        .build();
    let smt_update_action_bytes = smt_update_action.as_slice();

    let witness_args = WitnessArgsBuilder::default()
        .input_type(
            BytesOptBuilder::default()
                .set(Some(Pack::pack(&ckb_types::bytes::Bytes::copy_from_slice(
                    smt_update_action_bytes,
                ))))
                .build(),
        )
        .build();
    let witness_args_bytes = witness_args.as_slice();

    let mut data_loader = DummyDataLoader::new();
    let mut rng = thread_rng();

    let always_success_cell_data: ckb_types::bytes::Bytes = ALWAYS_SUCCESS_BIN.clone();
    let always_success_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(always_success_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let always_success_out_point = gen_random_out_point(&mut rng);
    let always_success_code_hash = CellOutput::calc_data_hash(&always_success_cell_data);
    let always_success_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(always_success_code_hash.clone())
        .build();

    let rce_validator_cell_data: ckb_types::bytes::Bytes = RCE_VALIDATOR_BIN.clone();
    let rce_validator_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(rce_validator_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let rce_validator_out_point = gen_random_out_point(&mut rng);
    let mut rce_validator_args_bytes: [u8; 33] = [0; 33];
    rce_validator_args_bytes[0..32].copy_from_slice(&TYPE_ID_CODE_HASH[..]);
    rce_validator_args_bytes[32] = flag;
    let rce_validator_args =
        ckb_types::bytes::Bytes::copy_from_slice(rce_validator_args_bytes.as_ref());

    let rce_validator_code_hash = CellOutput::calc_data_hash(&rce_validator_cell_data);
    let rce_validator_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(rce_validator_code_hash.clone())
        .args(rce_validator_args.pack())
        .build();

    let old_rce_out_point = gen_random_out_point(&mut rng);
    let old_rce_cell_data = build_rc_rule(&old_smt_root.into(), true, false);
    let old_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(21000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();

    let new_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(20000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();
    let new_rce_cell_data = build_rc_rule(&new_smt_root.into(), true, false);

    data_loader.cells.insert(
        always_success_out_point.clone(),
        (always_success_cell, always_success_cell_data.clone()),
    );
    data_loader.cells.insert(
        rce_validator_out_point.clone(),
        (rce_validator_cell, rce_validator_cell_data.clone()),
    );
    data_loader
        .cells
        .insert(old_rce_out_point.clone(), (old_rce_cell, old_rce_cell_data));

    let tx = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(always_success_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(rce_validator_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .input(CellInput::new(old_rce_out_point, 0))
        .output(new_rce_cell)
        .output_data(new_rce_cell_data.pack())
        .witness(ckb_types::bytes::Bytes::copy_from_slice(witness_args_bytes).pack())
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let r = verifier.verify(MAX_CYCLES);
    assert!(r.is_ok())
}

#[test]
fn test_rce_validator_bl_remove_key() {
    let old_smt_keys = vec![
        (H256::from(K1.clone()), SMT_EXISTING.clone()),
        (H256::from(K2.clone()), SMT_EXISTING.clone()),
    ];
    let new_smt_keys = vec![(H256::from(K1.clone()), SMT_EXISTING.clone())];
    let mod_keys = vec![(H256::from(K2.clone()), SMT_EXISTING.clone())];
    let packed_values = 0b0001_0000;
    let flag = 0;

    let old_smt = new_smt(old_smt_keys);
    let new_smt = new_smt(new_smt_keys);
    let old_smt_root = old_smt.root().clone();
    let new_smt_root = new_smt.root().clone();

    let merkle_proof = old_smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _)| k).collect())
        .unwrap();
    let merkle_proof_compiled = merkle_proof.clone().compile(mod_keys.clone()).unwrap();
    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.into();

    let smt_update_item = SmtUpdateItemBuilder::default()
        .key(ckb_types::packed::Byte32::from_slice(&K2.clone()).unwrap())
        .packed_values(packed_values.into())
        .build();
    let smt_update_item_vec = SmtUpdateItemVecBuilder::default()
        .push(smt_update_item)
        .build();
    let smt_proof = SmtProofBuilder::default()
        .set(
            merkle_proof_bytes
                .into_iter()
                .map(|v| ckb_types::molecule::prelude::Byte::new(v))
                .collect(),
        )
        .build();
    let smt_update_action = SmtUpdateActionBuilder::default()
        .updates(smt_update_item_vec)
        .proof(smt_proof)
        .build();
    let smt_update_action_bytes = smt_update_action.as_slice();

    let witness_args = WitnessArgsBuilder::default()
        .input_type(
            BytesOptBuilder::default()
                .set(Some(Pack::pack(&ckb_types::bytes::Bytes::copy_from_slice(
                    smt_update_action_bytes,
                ))))
                .build(),
        )
        .build();
    let witness_args_bytes = witness_args.as_slice();

    let mut data_loader = DummyDataLoader::new();
    let mut rng = thread_rng();

    let always_success_cell_data: ckb_types::bytes::Bytes = ALWAYS_SUCCESS_BIN.clone();
    let always_success_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(always_success_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let always_success_out_point = gen_random_out_point(&mut rng);
    let always_success_code_hash = CellOutput::calc_data_hash(&always_success_cell_data);
    let always_success_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(always_success_code_hash.clone())
        .build();

    let rce_validator_cell_data: ckb_types::bytes::Bytes = RCE_VALIDATOR_BIN.clone();
    let rce_validator_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(rce_validator_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let rce_validator_out_point = gen_random_out_point(&mut rng);
    let mut rce_validator_args_bytes: [u8; 33] = [0; 33];
    rce_validator_args_bytes[0..32].copy_from_slice(&TYPE_ID_CODE_HASH[..]);
    rce_validator_args_bytes[32] = flag;
    let rce_validator_args =
        ckb_types::bytes::Bytes::copy_from_slice(rce_validator_args_bytes.as_ref());

    let rce_validator_code_hash = CellOutput::calc_data_hash(&rce_validator_cell_data);
    let rce_validator_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(rce_validator_code_hash.clone())
        .args(rce_validator_args.pack())
        .build();

    let old_rce_out_point = gen_random_out_point(&mut rng);
    let old_rce_cell_data = build_rc_rule(&old_smt_root.into(), true, false);
    let old_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(21000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();

    let new_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(20000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();
    let new_rce_cell_data = build_rc_rule(&new_smt_root.into(), true, false);

    data_loader.cells.insert(
        always_success_out_point.clone(),
        (always_success_cell, always_success_cell_data.clone()),
    );
    data_loader.cells.insert(
        rce_validator_out_point.clone(),
        (rce_validator_cell, rce_validator_cell_data.clone()),
    );
    data_loader
        .cells
        .insert(old_rce_out_point.clone(), (old_rce_cell, old_rce_cell_data));

    let tx = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(always_success_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(rce_validator_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .input(CellInput::new(old_rce_out_point, 0))
        .output(new_rce_cell)
        .output_data(new_rce_cell_data.pack())
        .witness(ckb_types::bytes::Bytes::copy_from_slice(witness_args_bytes).pack())
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let r = verifier.verify(MAX_CYCLES);
    assert!(r.is_ok())
}

#[test]
fn test_rce_validator_bl_remove_key_but_append_only() {
    let old_smt_keys = vec![
        (H256::from(K1.clone()), SMT_EXISTING.clone()),
        (H256::from(K2.clone()), SMT_EXISTING.clone()),
    ];
    let new_smt_keys = vec![(H256::from(K1.clone()), SMT_EXISTING.clone())];
    let mod_keys = vec![(H256::from(K2.clone()), SMT_EXISTING.clone())];
    let packed_values = 0b0001_0000;
    let flag = 1;

    let old_smt = new_smt(old_smt_keys);
    let new_smt = new_smt(new_smt_keys);
    let old_smt_root = old_smt.root().clone();
    let new_smt_root = new_smt.root().clone();

    let merkle_proof = old_smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _)| k).collect())
        .unwrap();
    let merkle_proof_compiled = merkle_proof.clone().compile(mod_keys.clone()).unwrap();
    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.into();

    let smt_update_item = SmtUpdateItemBuilder::default()
        .key(ckb_types::packed::Byte32::from_slice(&K2.clone()).unwrap())
        .packed_values(packed_values.into())
        .build();
    let smt_update_item_vec = SmtUpdateItemVecBuilder::default()
        .push(smt_update_item)
        .build();
    let smt_proof = SmtProofBuilder::default()
        .set(
            merkle_proof_bytes
                .into_iter()
                .map(|v| ckb_types::molecule::prelude::Byte::new(v))
                .collect(),
        )
        .build();
    let smt_update_action = SmtUpdateActionBuilder::default()
        .updates(smt_update_item_vec)
        .proof(smt_proof)
        .build();
    let smt_update_action_bytes = smt_update_action.as_slice();

    let witness_args = WitnessArgsBuilder::default()
        .input_type(
            BytesOptBuilder::default()
                .set(Some(Pack::pack(&ckb_types::bytes::Bytes::copy_from_slice(
                    smt_update_action_bytes,
                ))))
                .build(),
        )
        .build();
    let witness_args_bytes = witness_args.as_slice();

    let mut data_loader = DummyDataLoader::new();
    let mut rng = thread_rng();

    let always_success_cell_data: ckb_types::bytes::Bytes = ALWAYS_SUCCESS_BIN.clone();
    let always_success_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(always_success_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let always_success_out_point = gen_random_out_point(&mut rng);
    let always_success_code_hash = CellOutput::calc_data_hash(&always_success_cell_data);
    let always_success_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(always_success_code_hash.clone())
        .build();

    let rce_validator_cell_data: ckb_types::bytes::Bytes = RCE_VALIDATOR_BIN.clone();
    let rce_validator_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(rce_validator_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let rce_validator_out_point = gen_random_out_point(&mut rng);
    let mut rce_validator_args_bytes: [u8; 33] = [0; 33];
    rce_validator_args_bytes[0..32].copy_from_slice(&TYPE_ID_CODE_HASH[..]);
    rce_validator_args_bytes[32] = flag;
    let rce_validator_args =
        ckb_types::bytes::Bytes::copy_from_slice(rce_validator_args_bytes.as_ref());

    let rce_validator_code_hash = CellOutput::calc_data_hash(&rce_validator_cell_data);
    let rce_validator_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(rce_validator_code_hash.clone())
        .args(rce_validator_args.pack())
        .build();

    let old_rce_out_point = gen_random_out_point(&mut rng);
    let old_rce_cell_data = build_rc_rule(&old_smt_root.into(), true, false);
    let old_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(21000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();

    let new_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(20000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();
    let new_rce_cell_data = build_rc_rule(&new_smt_root.into(), true, false);

    data_loader.cells.insert(
        always_success_out_point.clone(),
        (always_success_cell, always_success_cell_data.clone()),
    );
    data_loader.cells.insert(
        rce_validator_out_point.clone(),
        (rce_validator_cell, rce_validator_cell_data.clone()),
    );
    data_loader
        .cells
        .insert(old_rce_out_point.clone(), (old_rce_cell, old_rce_cell_data));

    let tx = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(always_success_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(rce_validator_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .input(CellInput::new(old_rce_out_point, 0))
        .output(new_rce_cell)
        .output_data(new_rce_cell_data.pack())
        .witness(ckb_types::bytes::Bytes::copy_from_slice(witness_args_bytes).pack())
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let r = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        r.unwrap_err(),
        ScriptError::ValidationFailure(61).input_type_script(0),
    );
}

#[test]
fn test_rce_validator_no_input() {
    let old_smt_keys = vec![];
    let new_smt_keys = vec![(H256::from(K1.clone()), SMT_EXISTING.clone())];
    let mod_keys = vec![(H256::from(K1.clone()), SMT_NOT_EXISTING.clone())];
    let packed_values = 0b0000_0001;
    let flag = 0;

    let old_smt = new_smt(old_smt_keys);
    let new_smt = new_smt(new_smt_keys);
    let old_smt_root = old_smt.root().clone();
    let new_smt_root = new_smt.root().clone();

    let merkle_proof = old_smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _)| k).collect())
        .unwrap();
    let merkle_proof_compiled = merkle_proof.clone().compile(mod_keys.clone()).unwrap();
    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.into();

    let smt_update_item = SmtUpdateItemBuilder::default()
        .key(ckb_types::packed::Byte32::from_slice(&K1.clone()).unwrap())
        .packed_values(packed_values.into())
        .build();
    let smt_update_item_vec = SmtUpdateItemVecBuilder::default()
        .push(smt_update_item)
        .build();
    let smt_proof = SmtProofBuilder::default()
        .set(
            merkle_proof_bytes
                .into_iter()
                .map(|v| ckb_types::molecule::prelude::Byte::new(v))
                .collect(),
        )
        .build();
    let smt_update_action = SmtUpdateActionBuilder::default()
        .updates(smt_update_item_vec)
        .proof(smt_proof)
        .build();
    let smt_update_action_bytes = smt_update_action.as_slice();

    let witness_args = WitnessArgsBuilder::default()
        .output_type(
            BytesOptBuilder::default()
                .set(Some(Pack::pack(&ckb_types::bytes::Bytes::copy_from_slice(
                    smt_update_action_bytes,
                ))))
                .build(),
        )
        .build();
    let witness_args_bytes = witness_args.as_slice();

    let mut data_loader = DummyDataLoader::new();
    let mut rng = thread_rng();

    let always_success_cell_data: ckb_types::bytes::Bytes =
        ckb_types::bytes::Bytes::from(ALWAYS_SUCCESS_BIN.clone());
    let always_success_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(always_success_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let always_success_out_point = gen_random_out_point(&mut rng);
    let always_success_code_hash = CellOutput::calc_data_hash(&always_success_cell_data);
    let always_success_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(always_success_code_hash.clone())
        .build();

    let old_rce_out_point = gen_random_out_point(&mut rng);
    let old_rce_cell_data = ckb_types::bytes::Bytes::copy_from_slice(
        build_rc_rule(&old_smt_root.into(), true, false).as_ref(),
    );
    let old_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(21000).pack())
        .lock(always_success_script.clone())
        .build();

    let old_rce_cell_hash = {
        let mut blake2b = Blake2bBuilder::new(BLAKE2B_LEN)
            .personal(PERSONALIZATION)
            .key(BLAKE2B_KEY)
            .build();
        blake2b.update(CellInput::new(old_rce_out_point.clone(), 0).as_slice());
        blake2b.update(&0u64.to_le_bytes());
        let mut ret = [0; 32];
        blake2b.finalize(&mut ret);
        ckb_types::bytes::Bytes::from(ret.to_vec())
    };

    let rce_validator_cell_data: ckb_types::bytes::Bytes =
        ckb_types::bytes::Bytes::from(include_bytes!("../../../build/rce_validator").as_ref());
    let rce_validator_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(rce_validator_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let rce_validator_out_point = gen_random_out_point(&mut rng);
    let mut rce_validator_args_bytes: [u8; 33] = [0; 33];
    rce_validator_args_bytes[0..32].copy_from_slice(&old_rce_cell_hash[..]);
    rce_validator_args_bytes[32] = flag;
    let rce_validator_args =
        ckb_types::bytes::Bytes::copy_from_slice(rce_validator_args_bytes.as_ref());

    let rce_validator_code_hash = CellOutput::calc_data_hash(&rce_validator_cell_data);
    let rce_validator_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(rce_validator_code_hash.clone())
        .args(rce_validator_args.pack())
        .build();

    let new_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(20000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();
    let new_rce_cell_data = ckb_types::bytes::Bytes::copy_from_slice(
        build_rc_rule(&new_smt_root.into(), true, false).as_ref(),
    );

    data_loader.cells.insert(
        always_success_out_point.clone(),
        (always_success_cell, always_success_cell_data.clone()),
    );
    data_loader.cells.insert(
        rce_validator_out_point.clone(),
        (rce_validator_cell, rce_validator_cell_data.clone()),
    );
    data_loader
        .cells
        .insert(old_rce_out_point.clone(), (old_rce_cell, old_rce_cell_data));

    let tx = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(always_success_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(rce_validator_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .input(CellInput::new(old_rce_out_point, 0))
        .output(new_rce_cell)
        .output_data(new_rce_cell_data.pack())
        .witness(ckb_types::bytes::Bytes::copy_from_slice(witness_args_bytes.clone()).pack())
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let r = verifier.verify(MAX_CYCLES);
    assert!(r.is_ok())
}

#[test]
fn test_rce_validator_rccellvec_to_rccell() {
    let old_smt_keys = vec![];
    let new_smt_keys = vec![(H256::from(K1.clone()), SMT_EXISTING.clone())];
    let mod_keys = vec![(H256::from(K1.clone()), SMT_NOT_EXISTING.clone())];
    let packed_values = 0b0000_0001;
    let flag = 0;

    let old_smt = new_smt(old_smt_keys);
    let new_smt = new_smt(new_smt_keys);
    let new_smt_root = new_smt.root().clone();

    let merkle_proof = old_smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _)| k).collect())
        .unwrap();
    let merkle_proof_compiled = merkle_proof.clone().compile(mod_keys.clone()).unwrap();
    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.into();

    let smt_update_item = SmtUpdateItemBuilder::default()
        .key(ckb_types::packed::Byte32::from_slice(&K1.clone()).unwrap())
        .packed_values(packed_values.into())
        .build();
    let smt_update_item_vec = SmtUpdateItemVecBuilder::default()
        .push(smt_update_item)
        .build();
    let smt_proof = SmtProofBuilder::default()
        .set(
            merkle_proof_bytes
                .into_iter()
                .map(|v| ckb_types::molecule::prelude::Byte::new(v))
                .collect(),
        )
        .build();
    let smt_update_action = SmtUpdateActionBuilder::default()
        .updates(smt_update_item_vec)
        .proof(smt_proof)
        .build();
    let smt_update_action_bytes = smt_update_action.as_slice();

    let witness_args = WitnessArgsBuilder::default()
        .input_type(
            BytesOptBuilder::default()
                .set(Some(Pack::pack(&ckb_types::bytes::Bytes::copy_from_slice(
                    smt_update_action_bytes,
                ))))
                .build(),
        )
        .build();
    let witness_args_bytes = witness_args.as_slice();

    let mut data_loader = DummyDataLoader::new();
    let mut rng = thread_rng();

    let always_success_cell_data: ckb_types::bytes::Bytes = ALWAYS_SUCCESS_BIN.clone();
    let always_success_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(always_success_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let always_success_out_point = gen_random_out_point(&mut rng);
    let always_success_code_hash = CellOutput::calc_data_hash(&always_success_cell_data);
    let always_success_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(always_success_code_hash.clone())
        .build();

    let rce_validator_cell_data: ckb_types::bytes::Bytes = RCE_VALIDATOR_BIN.clone();
    let rce_validator_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(rce_validator_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let rce_validator_out_point = gen_random_out_point(&mut rng);
    let mut rce_validator_args_bytes: [u8; 33] = [0; 33];
    rce_validator_args_bytes[0..32].copy_from_slice(&TYPE_ID_CODE_HASH[..]);
    rce_validator_args_bytes[32] = flag;
    let rce_validator_args =
        ckb_types::bytes::Bytes::copy_from_slice(rce_validator_args_bytes.as_ref());

    let rce_validator_code_hash = CellOutput::calc_data_hash(&rce_validator_cell_data);
    let rce_validator_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(rce_validator_code_hash.clone())
        .args(rce_validator_args.pack())
        .build();

    let old_rce_out_point = gen_random_out_point(&mut rng);
    let old_rce_cell_data = RCDataBuilder::default()
        .set(RCDataUnion::from(RCCellVecBuilder::default().build()))
        .build()
        .as_bytes();
    let old_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(21000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();

    let new_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(20000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();
    let new_rce_cell_data = build_rc_rule(&new_smt_root.into(), true, false);

    data_loader.cells.insert(
        always_success_out_point.clone(),
        (always_success_cell, always_success_cell_data.clone()),
    );
    data_loader.cells.insert(
        rce_validator_out_point.clone(),
        (rce_validator_cell, rce_validator_cell_data.clone()),
    );
    data_loader
        .cells
        .insert(old_rce_out_point.clone(), (old_rce_cell, old_rce_cell_data));

    let tx = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(always_success_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(rce_validator_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .input(CellInput::new(old_rce_out_point, 0))
        .output(new_rce_cell)
        .output_data(new_rce_cell_data.pack())
        .witness(ckb_types::bytes::Bytes::copy_from_slice(witness_args_bytes).pack())
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let r = verifier.verify(MAX_CYCLES);
    assert!(r.is_ok())
}

#[test]
fn test_rce_validator_rccellvec_to_rccell_with_freeze_type() {
    let old_smt_keys = vec![];
    let new_smt_keys = vec![(H256::from(K1.clone()), SMT_EXISTING.clone())];
    let mod_keys = vec![(H256::from(K1.clone()), SMT_NOT_EXISTING.clone())];
    let packed_values = 0b0000_0001;
    let flag = 2;

    let old_smt = new_smt(old_smt_keys);
    let new_smt = new_smt(new_smt_keys);
    let new_smt_root = new_smt.root().clone();

    let merkle_proof = old_smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _)| k).collect())
        .unwrap();
    let merkle_proof_compiled = merkle_proof.clone().compile(mod_keys.clone()).unwrap();
    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.into();

    let smt_update_item = SmtUpdateItemBuilder::default()
        .key(ckb_types::packed::Byte32::from_slice(&K1.clone()).unwrap())
        .packed_values(packed_values.into())
        .build();
    let smt_update_item_vec = SmtUpdateItemVecBuilder::default()
        .push(smt_update_item)
        .build();
    let smt_proof = SmtProofBuilder::default()
        .set(
            merkle_proof_bytes
                .into_iter()
                .map(|v| ckb_types::molecule::prelude::Byte::new(v))
                .collect(),
        )
        .build();
    let smt_update_action = SmtUpdateActionBuilder::default()
        .updates(smt_update_item_vec)
        .proof(smt_proof)
        .build();
    let smt_update_action_bytes = smt_update_action.as_slice();

    let witness_args = WitnessArgsBuilder::default()
        .input_type(
            BytesOptBuilder::default()
                .set(Some(Pack::pack(&ckb_types::bytes::Bytes::copy_from_slice(
                    smt_update_action_bytes,
                ))))
                .build(),
        )
        .build();
    let witness_args_bytes = witness_args.as_slice();

    let mut data_loader = DummyDataLoader::new();
    let mut rng = thread_rng();

    let always_success_cell_data: ckb_types::bytes::Bytes = ALWAYS_SUCCESS_BIN.clone();
    let always_success_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(always_success_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let always_success_out_point = gen_random_out_point(&mut rng);
    let always_success_code_hash = CellOutput::calc_data_hash(&always_success_cell_data);
    let always_success_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(always_success_code_hash.clone())
        .build();

    let rce_validator_cell_data: ckb_types::bytes::Bytes = RCE_VALIDATOR_BIN.clone();
    let rce_validator_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(rce_validator_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let rce_validator_out_point = gen_random_out_point(&mut rng);
    let mut rce_validator_args_bytes: [u8; 33] = [0; 33];
    rce_validator_args_bytes[0..32].copy_from_slice(&TYPE_ID_CODE_HASH[..]);
    rce_validator_args_bytes[32] = flag;
    let rce_validator_args =
        ckb_types::bytes::Bytes::copy_from_slice(rce_validator_args_bytes.as_ref());

    let rce_validator_code_hash = CellOutput::calc_data_hash(&rce_validator_cell_data);
    let rce_validator_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(rce_validator_code_hash.clone())
        .args(rce_validator_args.pack())
        .build();

    let old_rce_out_point = gen_random_out_point(&mut rng);
    let old_rce_cell_data = RCDataBuilder::default()
        .set(RCDataUnion::from(RCCellVecBuilder::default().build()))
        .build()
        .as_bytes();
    let old_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(21000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();

    let new_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(20000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();
    let new_rce_cell_data = build_rc_rule(&new_smt_root.into(), true, false);

    data_loader.cells.insert(
        always_success_out_point.clone(),
        (always_success_cell, always_success_cell_data.clone()),
    );
    data_loader.cells.insert(
        rce_validator_out_point.clone(),
        (rce_validator_cell, rce_validator_cell_data.clone()),
    );
    data_loader
        .cells
        .insert(old_rce_out_point.clone(), (old_rce_cell, old_rce_cell_data));

    let tx = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(always_success_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(rce_validator_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .input(CellInput::new(old_rce_out_point, 0))
        .output(new_rce_cell)
        .output_data(new_rce_cell_data.pack())
        .witness(ckb_types::bytes::Bytes::copy_from_slice(witness_args_bytes).pack())
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let r = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        r.unwrap_err(),
        ScriptError::ValidationFailure(60).input_type_script(0),
    );
}

#[test]
fn test_rce_validator_rccell_to_rccellvec_with_freeze_type() {
    let old_smt_keys = vec![(H256::from(K1.clone()), SMT_EXISTING.clone())];
    let flag = 2;

    let old_smt = new_smt(old_smt_keys);
    let old_smt_root = old_smt.root().clone();

    let mut data_loader = DummyDataLoader::new();
    let mut rng = thread_rng();

    let always_success_cell_data: ckb_types::bytes::Bytes = ALWAYS_SUCCESS_BIN.clone();
    let always_success_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(always_success_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let always_success_out_point = gen_random_out_point(&mut rng);
    let always_success_code_hash = CellOutput::calc_data_hash(&always_success_cell_data);
    let always_success_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(always_success_code_hash.clone())
        .build();

    let rce_validator_cell_data: ckb_types::bytes::Bytes = RCE_VALIDATOR_BIN.clone();
    let rce_validator_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(rce_validator_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let rce_validator_out_point = gen_random_out_point(&mut rng);
    let mut rce_validator_args_bytes: [u8; 33] = [0; 33];
    rce_validator_args_bytes[0..32].copy_from_slice(&TYPE_ID_CODE_HASH[..]);
    rce_validator_args_bytes[32] = flag;
    let rce_validator_args =
        ckb_types::bytes::Bytes::copy_from_slice(rce_validator_args_bytes.as_ref());

    let rce_validator_code_hash = CellOutput::calc_data_hash(&rce_validator_cell_data);
    let rce_validator_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(rce_validator_code_hash.clone())
        .args(rce_validator_args.pack())
        .build();

    let old_rce_out_point = gen_random_out_point(&mut rng);
    let old_rce_cell_data = build_rc_rule(&old_smt_root.into(), true, false);
    let old_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(21000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();

    let new_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(20000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();
    let new_rce_cell_data = RCDataBuilder::default()
        .set(RCDataUnion::from(RCCellVecBuilder::default().build()))
        .build()
        .as_bytes();

    data_loader.cells.insert(
        always_success_out_point.clone(),
        (always_success_cell, always_success_cell_data.clone()),
    );
    data_loader.cells.insert(
        rce_validator_out_point.clone(),
        (rce_validator_cell, rce_validator_cell_data.clone()),
    );
    data_loader
        .cells
        .insert(old_rce_out_point.clone(), (old_rce_cell, old_rce_cell_data));

    let tx = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(always_success_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(rce_validator_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .input(CellInput::new(old_rce_out_point, 0))
        .output(new_rce_cell)
        .output_data(new_rce_cell_data.pack())
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let r = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        r.unwrap_err(),
        ScriptError::ValidationFailure(60).input_type_script(0),
    );
}

#[test]
fn test_rce_validator_bl_update_to_wl() {
    let old_smt_keys = vec![(H256::from(K1.clone()), SMT_EXISTING.clone())];
    let new_smt_keys = vec![
        (H256::from(K1.clone()), SMT_EXISTING.clone()),
        (H256::from(K2.clone()), SMT_EXISTING.clone()),
    ];
    let mod_keys = vec![(H256::from(K2.clone()), SMT_NOT_EXISTING.clone())];
    let packed_values = 0b0000_0001;
    let flag = 0;

    let old_smt = new_smt(old_smt_keys);
    let new_smt = new_smt(new_smt_keys);
    let old_smt_root = old_smt.root().clone();
    let new_smt_root = new_smt.root().clone();

    let merkle_proof = old_smt
        .merkle_proof(mod_keys.clone().into_iter().map(|(k, _)| k).collect())
        .unwrap();
    let merkle_proof_compiled = merkle_proof.clone().compile(mod_keys.clone()).unwrap();
    let merkle_proof_bytes: Vec<u8> = merkle_proof_compiled.into();

    let smt_update_item = SmtUpdateItemBuilder::default()
        .key(ckb_types::packed::Byte32::from_slice(&K2.clone()).unwrap())
        .packed_values(packed_values.into())
        .build();
    let smt_update_item_vec = SmtUpdateItemVecBuilder::default()
        .push(smt_update_item)
        .build();
    let smt_proof = SmtProofBuilder::default()
        .set(
            merkle_proof_bytes
                .into_iter()
                .map(|v| ckb_types::molecule::prelude::Byte::new(v))
                .collect(),
        )
        .build();
    let smt_update_action = SmtUpdateActionBuilder::default()
        .updates(smt_update_item_vec)
        .proof(smt_proof)
        .build();
    let smt_update_action_bytes = smt_update_action.as_slice();

    let witness_args = WitnessArgsBuilder::default()
        .input_type(
            BytesOptBuilder::default()
                .set(Some(Pack::pack(&ckb_types::bytes::Bytes::copy_from_slice(
                    smt_update_action_bytes,
                ))))
                .build(),
        )
        .build();
    let witness_args_bytes = witness_args.as_slice();

    let mut data_loader = DummyDataLoader::new();
    let mut rng = thread_rng();

    let always_success_cell_data: ckb_types::bytes::Bytes = ALWAYS_SUCCESS_BIN.clone();
    let always_success_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(always_success_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let always_success_out_point = gen_random_out_point(&mut rng);
    let always_success_code_hash = CellOutput::calc_data_hash(&always_success_cell_data);
    let always_success_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(always_success_code_hash.clone())
        .build();

    let rce_validator_cell_data: ckb_types::bytes::Bytes = RCE_VALIDATOR_BIN.clone();
    let rce_validator_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(rce_validator_cell_data.len())
                .unwrap()
                .pack(),
        )
        .build();
    let rce_validator_out_point = gen_random_out_point(&mut rng);
    let mut rce_validator_args_bytes: [u8; 33] = [0; 33];
    rce_validator_args_bytes[0..32].copy_from_slice(&TYPE_ID_CODE_HASH[..]);
    rce_validator_args_bytes[32] = flag;
    let rce_validator_args =
        ckb_types::bytes::Bytes::copy_from_slice(rce_validator_args_bytes.as_ref());

    let rce_validator_code_hash = CellOutput::calc_data_hash(&rce_validator_cell_data);
    let rce_validator_script = Script::new_builder()
        .hash_type(ScriptHashType::Data.into())
        .code_hash(rce_validator_code_hash.clone())
        .args(rce_validator_args.pack())
        .build();

    let old_rce_out_point = gen_random_out_point(&mut rng);
    let old_rce_cell_data = build_rc_rule(&old_smt_root.into(), true, false);
    let old_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(21000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();

    let new_rce_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(20000).pack())
        .lock(always_success_script.clone())
        .type_(Some(rce_validator_script.clone()).pack())
        .build();
    let new_rce_cell_data = build_rc_rule(&new_smt_root.into(), false, false);

    data_loader.cells.insert(
        always_success_out_point.clone(),
        (always_success_cell, always_success_cell_data.clone()),
    );
    data_loader.cells.insert(
        rce_validator_out_point.clone(),
        (rce_validator_cell, rce_validator_cell_data.clone()),
    );
    data_loader
        .cells
        .insert(old_rce_out_point.clone(), (old_rce_cell, old_rce_cell_data));

    let tx = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(always_success_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(rce_validator_out_point.clone())
                .dep_type(DepType::Code.into())
                .build(),
        )
        .input(CellInput::new(old_rce_out_point, 0))
        .output(new_rce_cell)
        .output_data(new_rce_cell_data.pack())
        .witness(ckb_types::bytes::Bytes::copy_from_slice(witness_args_bytes).pack())
        .build();

    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let r = verifier.verify(MAX_CYCLES);
    assert!(r.is_ok())
}
