#![allow(unused_imports)]

// stdlib or 3rd part lib
use lazy_static::lazy_static;
use std::collections::HashMap;

// ckb lib
use blake2b_rs::{Blake2b, Blake2bBuilder};
use ckb_crypto::secp::Privkey;
use ckb_error::assert_error_eq;
use ckb_hash::blake2b_256;
use ckb_script::DataLoader;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types::packed::{Byte, Byte32};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellMetaBuilder, ResolvedTransaction},
        BlockExt, Capacity, DepType, EpochExt, HeaderView, ScriptHashType, TransactionBuilder,
        TransactionView,
    },
    packed::{
        self, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs, WitnessArgsBuilder,
    },
    prelude::*,
};
use rand::rngs::ThreadRng;
use rand::{thread_rng, Rng};
use sparse_merkle_tree::{
    blake2b::Blake2bHasher, default_store::DefaultStore, error::Error, traits::Hasher, MerkleProof,
    SparseMerkleTree, H256,
};

// internal lib
use super::{
    blockchain::Script as ExtensionScript,
    build_resolved_tx,
    xudt_rce_mol::RCCellVecBuilder,
    xudt_rce_mol::ScriptVec as ExtensionScriptVec,
    xudt_rce_mol::ScriptVecBuilder as ExtensionScriptVecBuilder,
    xudt_rce_mol::{RCData, RCDataBuilder, RCRuleBuilder},
    DummyDataLoader, MAX_CYCLES,
};

const BLAKE2B_KEY: &[u8] = &[];
const BLAKE2B_LEN: usize = 32;
const PERSONALIZATION: &[u8] = b"ckb-default-hash";

pub struct CKBBlake2bHasher(Blake2b);

impl Default for CKBBlake2bHasher {
    fn default() -> Self {
        let blake2b = Blake2bBuilder::new(BLAKE2B_LEN)
            .personal(PERSONALIZATION)
            .key(BLAKE2B_KEY)
            .build();
        CKBBlake2bHasher(blake2b)
    }
}

impl Hasher for CKBBlake2bHasher {
    fn write_h256(&mut self, h: &H256) {
        self.0.update(h.as_slice());
    }
    fn finish(self) -> H256 {
        let mut hash = [0u8; 32];
        self.0.finalize(&mut hash);
        hash.into()
    }
}

lazy_static! {
    pub static ref RCE_HASH: [u8; 32] = [
        1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
    ];
    pub static ref XUDT_RCE_BIN: Bytes =
        Bytes::from(include_bytes!("../../build/xudt_rce").as_ref());
    pub static ref ALWAYS_SUCCESS_BIN: Bytes =
        Bytes::from(include_bytes!("../../build/always_success").as_ref());
    pub static ref EXTENSION_SCRIPT_0: Bytes =
        Bytes::from(include_bytes!("../../build/extension_script_0").as_ref());
    pub static ref EXTENSION_SCRIPT_1: Bytes =
        Bytes::from(include_bytes!("../../build/extension_script_1").as_ref());
    pub static ref EXTENSION_SCRIPT_RCE: Bytes = Bytes::from(RCE_HASH.as_ref());
    pub static ref SMT_EXISTING: H256 = [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
    ]
    .into();
    pub static ref SMT_NOT_EXISTING: H256 = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
    ]
    .into();
}

// on(1): white list
// off(0): black list
const WHITE_BLACK_LIST_MASK: u8 = 0x2;
// on(1): emergency halt mode
// off(0): not int emergency halt mode
const EMERGENCY_HALT_MODE_MASK: u8 = 0x1;

pub fn gen_random_out_point(rng: &mut ThreadRng) -> OutPoint {
    let hash = {
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf.pack()
    };
    OutPoint::new(hash, 0)
}

//
// deploy "bin" to cell, then build a script to point it.
//
// it can:
// * build lock script, set is_type to false
// * build type script, set is_type to true
// * build type script without upgrading, set is_type to false
// * build extension script, set is_type to true
// * build extension script without upgrading, set is_type to false
// * build RCE cell, is_type = true. Only the Script.code_hash is kept for further use.
//   when in this case, to make "args" passed in unique
fn build_script(
    dummy: &mut DummyDataLoader,
    tx_builder: TransactionBuilder,
    is_type: bool,
    bin: &Bytes,
    args: Bytes,
) -> (TransactionBuilder, Script) {
    // this hash to make type script in code unique
    // then make "type script hash" unique, which will be code_hash in "type script"
    let hash = ckb_hash::blake2b_256(bin);

    let type_script_in_code = {
        // this args can be anything
        let args = vec![0u8; 32];
        Script::new_builder()
            .args(args.pack())
            .code_hash(hash.pack())
            .hash_type(ScriptHashType::Type.into())
            .build()
    };

    // it not needed to set "type script" when is_type is false
    let cell = CellOutput::new_builder()
        .capacity(Capacity::bytes(bin.len()).expect("script capacity").pack())
        .type_(Some(type_script_in_code.clone()).pack())
        .build();

    // use "code" hash as out point, which is unique
    let out_point = &OutPoint::new(hash.pack(), 0);

    dummy.cells.insert(out_point.clone(), (cell, bin.clone()));

    let tx_builder = tx_builder.cell_dep(
        CellDep::new_builder()
            .out_point(out_point.clone())
            .dep_type(DepType::Code.into())
            .build(),
    );
    let code_hash = if is_type {
        ckb_hash::blake2b_256(type_script_in_code.as_slice())
    } else {
        ckb_hash::blake2b_256(bin)
    };
    let hash_type = if is_type {
        ScriptHashType::Type
    } else {
        ScriptHashType::Data
    };

    let script = Script::new_builder()
        .args(args.pack())
        .code_hash(code_hash.pack())
        .hash_type(hash_type.into())
        .build();

    (tx_builder, script)
}

fn build_rce_script(args: &Bytes) -> Script {
    Script::new_builder()
        .args(args.pack())
        .hash_type(ScriptHashType::Type.into())
        .code_hash(Byte32::new(RCE_HASH.clone()))
        .build()
}

fn build_xudt_args(flags: u32, scripts: &Vec<Script>) -> Bytes {
    // note, the types listed here are different than outside
    use molecule::bytes::Bytes;
    use molecule::prelude::Builder;
    use molecule::prelude::Entity;

    let mut result = vec![];
    result.extend(flags.to_le_bytes().as_ref());

    let mut builder = ExtensionScriptVecBuilder::default();

    for s in scripts {
        builder = builder.push(ExtensionScript::new_unchecked(s.as_slice().into()));
    }

    let s = builder.build();
    result.extend(s.as_slice());

    result.into()
}

fn build_args(lock: &[u8], xudt_args: &Bytes) -> Bytes {
    let mut res = Bytes::from(lock);
    res.extend(xudt_args.clone());
    res
}

type SMT = SparseMerkleTree<CKBBlake2bHasher, H256, DefaultStore<H256>>;

fn new_smt(pairs: Vec<(H256, H256)>) -> SMT {
    let mut smt = SMT::default();
    for (key, value) in pairs {
        smt.update(key, value).unwrap();
    }
    smt
}

// return smt root and proof
fn build_smt_on_bl(hashes: &Vec<[u8; 32]>, on: bool) -> (H256, Vec<u8>) {
    let test_pairs: Vec<(H256, H256)> = hashes
        .clone()
        .into_iter()
        .map(|hash| (hash.into(), SMT_NOT_EXISTING.clone()))
        .collect();
    // this is the hash on black list, but "hashes" are not on that.
    let key_on_bl1: H256 = [
        111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let key_on_bl2: H256 = [
        222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let pairs = vec![
        (key_on_bl1, SMT_EXISTING.clone()),
        (key_on_bl2, SMT_EXISTING.clone()),
    ];
    let smt = new_smt(pairs.clone());
    let root = smt.root();

    let proof = smt
        .merkle_proof(test_pairs.clone().into_iter().map(|(k, _)| k).collect())
        .expect("gen proof");
    let compiled_proof = proof
        .clone()
        .compile(test_pairs.clone())
        .expect("compile proof");
    let test_on = compiled_proof
        .verify::<CKBBlake2bHasher>(smt.root(), test_pairs.clone())
        .expect("verify compiled proof");
    assert!(test_on);
    if on {
        let mut new_root = root.clone();
        let one = new_root.get_bit(0);
        if one {
            new_root.clear_bit(0);
        } else {
            new_root.set_bit(0);
        }
        (new_root.clone(), compiled_proof.into())
    } else {
        (root.clone(), compiled_proof.into())
    }
}

// return smt root and proof
fn build_smt_on_wl(hashes: &Vec<[u8; 32]>, on: bool) -> (H256, Vec<u8>) {
    let existing_pairs: Vec<(H256, H256)> = hashes
        .clone()
        .into_iter()
        .map(|hash| (hash.into(), SMT_EXISTING.clone()))
        .collect();

    // this is the hash on white list, and "hashes" are on that.
    let key_on_wl1: H256 = [
        111, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let key_on_wl2: H256 = [
        222, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]
    .into();
    let mut pairs = vec![
        (key_on_wl1, SMT_EXISTING.clone()),
        (key_on_wl2, SMT_EXISTING.clone()),
    ];
    if on {
        pairs.extend(existing_pairs.clone());
    }

    let smt = new_smt(pairs);
    let root = smt.root();

    let proof = smt
        .merkle_proof(existing_pairs.clone().into_iter().map(|(k, _)| k).collect())
        .expect("gen proof");
    let compiled_proof = proof
        .clone()
        .compile(existing_pairs.clone())
        .expect("compile proof");
    let test_on = compiled_proof
        .verify::<CKBBlake2bHasher>(root, existing_pairs.clone())
        .expect("verify compiled proof");
    if on {
        assert!(test_on);
    } else {
        assert!(!test_on);
    }
    return (root.clone(), compiled_proof.into());
}

fn build_rc_rule(
    smt_root: &[u8; 32],
    is_black: bool,
    is_emergency: bool,
) -> ckb_types::bytes::Bytes {
    use super::blockchain::*;
    use super::xudt_rce_mol::*;
    use molecule::prelude::*;

    let mut flags: u8 = 0;

    if !is_black {
        flags ^= WHITE_BLACK_LIST_MASK;
    }
    if is_emergency {
        flags ^= EMERGENCY_HALT_MODE_MASK;
    }
    let smt_root = molecule::bytes::Bytes::from(smt_root.as_ref());
    let sr = Byte32::new_unchecked(smt_root);
    let rcrule = RCRuleBuilder::default()
        .flags(Byte::new(flags))
        .smt_root(sr)
        .build();
    let res = RCDataBuilder::default()
        .set(RCDataUnion::RCRule(rcrule))
        .build();
    res.as_slice().into()
}

fn make_new_bytes(input: &[u8]) -> super::blockchain::Bytes {
    use molecule::prelude::*;
    super::blockchain::BytesBuilder::default()
        .set(input.into_iter().map(|v| Byte::new(v.clone())).collect())
        .build()
}

fn make_old_bytes(input: &[u8]) -> ckb_types::packed::Bytes {
    ckb_types::packed::BytesBuilder::default()
        .set(input.into_iter().map(|v| Byte::new(v.clone())).collect())
        .build()
}

fn build_extension_data(
    count: u32,
    rce_index: u32,
    proofs: Vec<Vec<u8>>,
) -> ckb_types::bytes::Bytes {
    use super::blockchain::*;
    use super::xudt_rce_mol::*;
    use molecule::bytes::Bytes;
    use molecule::prelude::*;

    let mut builder = SmtProofVecBuilder::default();
    for p in proofs {
        let temp = SmtProofBuilder::default().set(p.into_iter().map(|v| Byte::new(v)).collect());
        builder = builder.push(temp.build());
    }
    let proofs: SmtProofVec = builder.build();

    let mut bytes_vec_builder = BytesVecBuilder::default();

    for i in 0..count {
        if i == rce_index {
            bytes_vec_builder = bytes_vec_builder.push(make_new_bytes(proofs.as_slice()));
        } else {
            bytes_vec_builder = bytes_vec_builder.push(super::blockchain::Bytes::default());
        }
    }
    let mut wi_builder = XudtWitnessInputBuilder::default();
    wi_builder = wi_builder.extension_data(bytes_vec_builder.build());

    wi_builder.build().as_slice().into()
}

pub enum TestScheme {
    None,
    OnWhiteList,
    NotOnWhiteList,
    OnBlackList,
    NotOnBlackList,
    BothOn,
    EmergencyHaltMode,
}

pub enum XudtFlags {
    Plain = 0,
    InArgs = 1,
    InWitness = 2,
}

pub fn gen_tx(
    dummy: &mut DummyDataLoader,
    _args: Bytes,
    input_count: usize,
    output_count: usize,
    input_amount: Vec<u128>,
    output_amount: Vec<u128>,
    extension_scripts_bin: Vec<&Bytes>,
    scheme: TestScheme,
    rng: &mut ThreadRng,
) -> TransactionView {
    assert_eq!(input_amount.len(), input_count);
    assert_eq!(output_amount.len(), output_count);

    // setup default tx builder
    let dummy_capacity = Capacity::shannons(50000);
    let mut tx_builder = TransactionBuilder::default();

    let (tx0, always_success_script) = build_script(
        dummy,
        tx_builder,
        false,
        &ALWAYS_SUCCESS_BIN,
        vec![0u8; 32].into(),
    );
    tx_builder = tx0;
    let always_success_script_hash = blake2b_256(always_success_script.as_slice());

    let (proofs, rc_datas) = generate_proofs(scheme, &vec![always_success_script_hash]);

    let (rce_cell_root_hash, b0) = generate_rce_cell(dummy, tx_builder, rc_datas, rng);
    tx_builder = b0;

    let mut total_count = 0;
    let mut rce_index = 0;
    // this is the default args, without XUDT extension: Simple UDT
    let mut args = Bytes::from([0u8; 32].as_ref());
    if !extension_scripts_bin.is_empty() {
        let mut extension_scripts: Vec<Script> = vec![];
        for e_script in extension_scripts_bin {
            if e_script == EXTENSION_SCRIPT_RCE.as_ref() {
                // then create a script with args pointed to that RCE cell
                let e_script = build_rce_script(&rce_cell_root_hash.as_bytes());
                extension_scripts.push(e_script);
                rce_index = total_count;
            } else {
                let (b0, e_script) =
                    build_script(dummy, tx_builder, true, e_script, vec![0u8; 32].into());
                tx_builder = b0;
                extension_scripts.push(e_script);
            }
            total_count += 1;
        }
        // xUDT args on "args" field
        let xudt_args = build_xudt_args(XudtFlags::InArgs as u32, &extension_scripts);
        args = build_args(&[0u8; 32][..], &xudt_args);
    }

    let (mut tx_builder, xudt_rce_script) =
        build_script(dummy, tx_builder, true, &XUDT_RCE_BIN, args);

    for i in 0..output_count {
        let amount = output_amount[i];
        tx_builder = tx_builder
            .output(
                CellOutput::new_builder()
                    .lock(always_success_script.clone())
                    .type_(Some(xudt_rce_script.clone()).pack())
                    .capacity(dummy_capacity.pack())
                    .build(),
            )
            .output_data(amount.to_le_bytes().pack());
    }

    // setup input type script
    for i in 0..input_count {
        let previous_out_point = gen_random_out_point(rng);

        let previous_output_cell = CellOutput::new_builder()
            .capacity(dummy_capacity.pack())
            // give an "always success" lock script for testing
            .lock(always_success_script.clone())
            .type_(Some(xudt_rce_script.clone()).pack())
            .build();
        dummy.cells.insert(
            previous_out_point.clone(),
            (
                previous_output_cell.clone(),
                Bytes::from(&input_amount[i].to_le_bytes()[..]),
            ),
        );

        // fill witness
        let witness_input_type = build_extension_data(total_count, rce_index, proofs.clone());
        let witness_args = WitnessArgsBuilder::default()
            .type_(witness_input_type.pack())
            .build();

        tx_builder = tx_builder
            .input(CellInput::new(previous_out_point, 0))
            .witness(witness_args.as_bytes().pack());
    }

    tx_builder.build()
}
//
// fn build_rce_cell_vec(hash_set: Vec<Byte32>) {
// }

// first generate N RCE cells with each contained one RCRule
// then collect all these RCE cell hash and create the final RCE cell.
fn generate_rce_cell(
    dummy: &mut DummyDataLoader,
    mut tx_builder: TransactionBuilder,
    rc_data: Vec<Bytes>,
    rng: &mut ThreadRng,
) -> (Byte32, TransactionBuilder) {
    use super::blockchain::Byte32;
    use super::xudt_rce_mol::RCDataUnion;
    use molecule::prelude::*;

    let mut cell_vec_builder = RCCellVecBuilder::default();

    for rc_rule in rc_data {
        let mut random_args: [u8; 32] = Default::default();
        rng.fill(&mut random_args[..]);
        // let's first build the RCE cell which contains the RCData(RCRule/RCCellVec).
        let (b0, rce_script) = build_script(
            dummy,
            tx_builder,
            true,
            &rc_rule,
            ckb_types::bytes::Bytes::from(random_args.as_ref()),
        );
        tx_builder = b0;
        // rce_script is in "old" blockchain types
        let hash = rce_script.code_hash();

        cell_vec_builder =
            cell_vec_builder.push(Byte32::from_slice(hash.as_slice()).expect("Byte32::from_slice"));
    }

    let cell_vec = cell_vec_builder.build();

    let rce_cell_content = RCDataBuilder::default()
        .set(RCDataUnion::RCCellVec(cell_vec))
        .build();

    let mut random_args: [u8; 32] = Default::default();
    rng.fill(&mut random_args[..]);

    let bin = rce_cell_content.as_slice();

    // let's first build the RCE cell which contains the RCData(RCRule/RCCellVec).
    let (b0, rce_script) = build_script(
        dummy,
        tx_builder,
        true,
        &ckb_types::bytes::Bytes::from(bin),
        ckb_types::bytes::Bytes::from(random_args.as_ref()),
    );
    tx_builder = b0;

    (rce_script.code_hash(), tx_builder)
}

fn generate_proofs(scheme: TestScheme, script_hash: &Vec<[u8; 32]>) -> (Vec<Vec<u8>>, Vec<Bytes>) {
    let mut proofs = Vec::<Vec<u8>>::default();
    let mut rc_data = Vec::<Bytes>::default();

    match scheme {
        TestScheme::BothOn => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::OnWhiteList, script_hash);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::OnBlackList, script_hash);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proofs.push(proof2);
            rc_data.push(rc_data2);
        }
        _ => {
            let (proof1, rc_data1) = generate_single_proof(scheme, script_hash);
            proofs.push(proof1);
            rc_data.push(rc_data1);
        }
    }

    (proofs, rc_data)
}

fn generate_single_proof(scheme: TestScheme, script_hash: &Vec<[u8; 32]>) -> (Vec<u8>, Bytes) {
    let hash = script_hash.clone();
    let mut is_black_list = false;
    let mut is_emergency_halt = false;
    let (smt_root, proof) = match scheme {
        TestScheme::OnWhiteList => {
            is_black_list = false;
            build_smt_on_wl(&hash, true)
        }
        TestScheme::NotOnWhiteList => {
            is_black_list = false;
            build_smt_on_wl(&hash, false)
        }
        TestScheme::OnBlackList => {
            is_black_list = true;
            build_smt_on_bl(&hash, true)
        }
        TestScheme::NotOnBlackList => {
            is_black_list = true;
            build_smt_on_bl(&hash, false)
        }
        TestScheme::EmergencyHaltMode => {
            is_emergency_halt = true;
            (H256::default(), Vec::<u8>::default())
        }
        _ => (H256::default(), Vec::<u8>::default()),
    };

    let rc_data = build_rc_rule(&smt_root.into(), is_black_list, is_emergency_halt);
    (proof, rc_data)
}

fn debug_printer(script: &Byte32, msg: &str) {
    let slice = script.as_slice();
    let str = format!(
        "Script({:x}{:x}{:x}{:x}{:x})",
        slice[0], slice[1], slice[2], slice[3], slice[4]
    );
    println!("{:?}: {}", str, msg);
}

#[test]
fn test_simple_udt() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        vec![],
        TestScheme::None,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_simple_udt_failed() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![200],
        vec![],
        TestScheme::None,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(-52),
    );
}

#[test]
fn test_xudt_extension_returns_success() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        vec![&EXTENSION_SCRIPT_0],
        TestScheme::None,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_xudt_extension_multi_return_success() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let bin_vec: Vec<&Bytes> = vec![
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_0,
    ];
    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        bin_vec,
        TestScheme::None,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_xudt_extension_returns_failed() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        vec![&EXTENSION_SCRIPT_1],
        TestScheme::None,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(1),
    );
}

#[test]
fn test_xudt_extension_multi_return_failed() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let bin_vec: Vec<&Bytes> = vec![
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_0,
        &EXTENSION_SCRIPT_1,
    ];
    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        bin_vec,
        TestScheme::None,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(1),
    );
}

#[test]
fn test_rce_on_wl() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let special_rce_hash = Bytes::from(RCE_HASH.as_ref());
    let bin_vec: Vec<&Bytes> = vec![&special_rce_hash];

    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        bin_vec,
        TestScheme::OnWhiteList,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_rce_not_on_wl() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let special_rce_hash = Bytes::from(RCE_HASH.as_ref());
    let bin_vec: Vec<&Bytes> = vec![&special_rce_hash];

    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        bin_vec,
        TestScheme::NotOnWhiteList,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_rce_not_on_bl() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let special_rce_hash = Bytes::from(RCE_HASH.as_ref());
    let bin_vec: Vec<&Bytes> = vec![&special_rce_hash];

    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        bin_vec,
        TestScheme::NotOnBlackList,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_rce_on_bl() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let special_rce_hash = Bytes::from(RCE_HASH.as_ref());
    let bin_vec: Vec<&Bytes> = vec![&special_rce_hash];

    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        bin_vec,
        TestScheme::OnBlackList,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(57), // ERROR_ON_BLACK_LIST
    );
}

#[test]
fn test_rce_emergency_halt_mode() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let special_rce_hash = Bytes::from(RCE_HASH.as_ref());
    let bin_vec: Vec<&Bytes> = vec![&special_rce_hash];

    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        bin_vec,
        TestScheme::EmergencyHaltMode,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(54), // ERROR_RCE_EMERGENCY_HATL
    );
}

#[test]
fn test_rce_both_on_wl_bl() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let special_rce_hash = Bytes::from(RCE_HASH.as_ref());
    let bin_vec: Vec<&Bytes> = vec![&special_rce_hash];

    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![100],
        bin_vec,
        TestScheme::BothOn,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}
