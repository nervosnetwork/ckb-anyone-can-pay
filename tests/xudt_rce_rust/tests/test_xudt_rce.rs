#![allow(dead_code)]

use ckb_error;
use ckb_error::assert_error_eq;
use ckb_hash::blake2b_256;
use ckb_script::{ScriptError, TransactionScriptsVerifier};
use ckb_types;
use ckb_types::bytes::BufMut;
use ckb_types::core::{Capacity, DepType, ScriptHashType, TransactionBuilder, TransactionView};
use ckb_types::molecule;
// We use this Bytes!
use ckb_types::molecule::bytes::Bytes;
use ckb_types::molecule::bytes::BytesMut;
use ckb_types::packed::{
    Byte32, BytesVecBuilder, CellDep, CellInput, CellOutput, Script, WitnessArgsBuilder,
};
use ckb_types::prelude::{Builder, Entity, Pack};
use lazy_static::lazy_static;
use rand::prelude::{thread_rng, ThreadRng};
use rand::Rng;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::{SparseMerkleTree, H256};

use misc::*;
use xudt_test::xudt_rce_mol::{
    RCCellVecBuilder, RCDataBuilder, RCDataUnion, RCRuleBuilder, ScriptVec, ScriptVecBuilder,
    ScriptVecOptBuilder, SmtProofBuilder, SmtProofEntryBuilder, SmtProofEntryVec,
    SmtProofEntryVecBuilder, XudtWitnessInputBuilder,
};

mod misc;

lazy_static! {
    pub static ref RCE_HASH: [u8; 32] = [
        1u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
        0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8,
    ];
    pub static ref XUDT_RCE_BIN: Bytes =
        Bytes::from(include_bytes!("../../../build/xudt_rce").as_ref());
    pub static ref ALWAYS_SUCCESS_BIN: Bytes =
        Bytes::from(include_bytes!("../../../build/always_success").as_ref());
    pub static ref EXTENSION_SCRIPT_0: Bytes =
        Bytes::from(include_bytes!("../../../build/extension_script_0").as_ref());
    pub static ref EXTENSION_SCRIPT_1: Bytes =
        Bytes::from(include_bytes!("../../../build/extension_script_1").as_ref());
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
    args_for_type: Option<Vec<u8>>,
) -> (TransactionBuilder, Script) {
    let type_script_in_code = {
        let hash = ckb_hash::blake2b_256(bin);
        let args = if let Some(a) = args_for_type {
            a
        } else {
            vec![0u8; 32]
        };
        Script::new_builder()
            .args(args.pack())
            .code_hash(hash.pack())
            .hash_type(ScriptHashType::Type.into())
            .build()
    };

    // it not needed to set "type script" when is_type is false
    let capacity = bin.len() as u64;
    let cell = CellOutput::new_builder()
        .capacity(capacity.pack())
        .type_(Some(type_script_in_code.clone()).pack())
        .build();

    // use "code" hash as out point, which is unique
    let mut rng = thread_rng();
    let out_point = gen_random_out_point(&mut rng);

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
        .code_hash(RCE_HASH.clone().pack())
        .build()
}

fn build_xudt_args(
    flags: XudtFlags,
    scripts: &Vec<Script>,
    scheme: TestScheme,
) -> (Bytes, ScriptVec) {
    let mut result = vec![];
    let mut flags_num = flags as u32;
    if scheme == TestScheme::OwnerModeForInputType {
        flags_num |= 0x80000000;
    }
    if scheme == TestScheme::OwnerModeForOutputType {
        flags_num |= 0x40000000;
    }
    result.extend(flags_num.to_le_bytes().as_ref());

    let mut builder = ScriptVecBuilder::default();

    for s in scripts {
        builder = builder.push(s.clone());
    }
    let s = builder.build();

    match flags {
        XudtFlags::Plain => {}
        XudtFlags::InArgs => {
            result.extend(s.as_slice());
        }
        XudtFlags::InWitness => {
            let hash = blake2b_256(s.as_bytes());
            result.extend(&hash[0..20]); // blake160
        }
    }

    (result.into(), s)
}

fn build_args(lock: &[u8], xudt_args: &Bytes) -> Bytes {
    let mut bytes = BytesMut::with_capacity(128);
    bytes.put(lock);
    bytes.put(xudt_args.as_ref());
    bytes.freeze()
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

fn build_rc_rule(smt_root: &[u8; 32], is_black: bool, is_emergency: bool) -> Bytes {
    let mut flags: u8 = 0;

    if !is_black {
        flags ^= WHITE_BLACK_LIST_MASK;
    }
    if is_emergency {
        flags ^= EMERGENCY_HALT_MODE_MASK;
    }
    let rcrule = RCRuleBuilder::default()
        .flags(flags.into())
        .smt_root(smt_root.pack())
        .build();
    let res = RCDataBuilder::default()
        .set(RCDataUnion::RCRule(rcrule))
        .build();
    res.as_bytes()
}

fn build_extension_data(
    count: u32,
    rce_index: u32,
    proofs: Vec<Vec<u8>>,
    proof_masks: Vec<u8>,
    extension_script_vec: ScriptVec,
) -> Bytes {
    assert_eq!(proofs.len(), proof_masks.len());

    let mut builder = SmtProofEntryVecBuilder::default();
    let iter = proofs.iter().zip(proof_masks.iter());
    for (p, m) in iter {
        let proof_builder = SmtProofBuilder::default().set(
            p.into_iter()
                .map(|v| molecule::prelude::Byte::new(*v))
                .collect(),
        );

        let temp = SmtProofEntryBuilder::default()
            .proof(proof_builder.build())
            .mask((*m).into());
        builder = builder.push(temp.build());
    }
    let proofs: SmtProofEntryVec = builder.build();

    let mut bytes_vec_builder = BytesVecBuilder::default();

    for i in 0..count {
        if i == rce_index {
            bytes_vec_builder = bytes_vec_builder.push(proofs.as_slice().pack());
        } else {
            bytes_vec_builder = bytes_vec_builder.push(ckb_types::packed::Bytes::default());
        }
    }
    let mut wi_builder = XudtWitnessInputBuilder::default();
    let b = ScriptVecOptBuilder::default()
        .set(Some(extension_script_vec))
        .build();
    wi_builder = wi_builder.raw_extension_data(b);
    wi_builder = wi_builder.extension_data(bytes_vec_builder.build());

    wi_builder.build().as_bytes()
}

#[derive(Copy, Clone, PartialEq)]
pub enum TestScheme {
    None,
    OnWhiteList,
    NotOnWhiteList,
    OnlyInputOnWhiteList,
    OnlyOutputOnWhiteList,
    BothOnWhiteList,
    OnBlackList,
    NotOnBlackList,
    BothOn,
    EmergencyHaltMode,
    OwnerModeForInputType,
    OwnerModeForOutputType,
}

#[derive(Copy, Clone)]
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
    no_input_witness: bool,
    xudt_flags: XudtFlags,
    rng: &mut ThreadRng,
) -> TransactionView {
    assert_eq!(input_amount.len(), input_count);
    assert_eq!(output_amount.len(), output_count);

    // setup default tx builder
    let dummy_capacity = Capacity::shannons(50000);
    let mut tx_builder = TransactionBuilder::default();
    let mut extension_script_vec = ScriptVec::default();

    let (tx0, always_success_script) = build_script(
        dummy,
        tx_builder,
        false,
        &ALWAYS_SUCCESS_BIN,
        vec![0u8; 32].into(),
        None,
    );
    tx_builder = tx0;
    let always_success_script_hash = blake2b_256(always_success_script.as_slice());

    let (tx0, always_type_script) = build_script(
        dummy,
        tx_builder,
        true,
        &ALWAYS_SUCCESS_BIN,
        vec![0u8; 32].into(),
        Some(vec![
            1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]),
    );
    tx_builder = tx0;

    let (proofs, rc_datas, proof_masks) =
        generate_proofs(scheme, &vec![always_success_script_hash]);

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
                let (b0, e_script) = build_script(
                    dummy,
                    tx_builder,
                    true,
                    e_script,
                    vec![0u8; 32].into(),
                    None,
                );
                tx_builder = b0;
                extension_scripts.push(e_script);
            }
            total_count += 1;
        }
        // xUDT args on "args" field
        let (xudt_args, es) = build_xudt_args(xudt_flags, &extension_scripts, scheme);
        extension_script_vec = es;
        args = build_args(&[0u8; 32][..], &xudt_args);
    }

    let (mut tx_builder, xudt_rce_script) =
        build_script(dummy, tx_builder, true, &XUDT_RCE_BIN, args, None);

    // use owner mode
    let xudt_rce_script = if no_input_witness
        || scheme == TestScheme::OwnerModeForInputType
        || scheme == TestScheme::OwnerModeForOutputType
    {
        let hash = if no_input_witness {
            blake2b_256(always_success_script.as_slice())
        } else {
            blake2b_256(always_type_script.as_slice())
        };
        let hash_slice = &hash[..];

        let args0 = xudt_rce_script.args().raw_data();

        let mut result: Vec<u8> = vec![];
        result.extend_from_slice(hash_slice);
        result.extend_from_slice(&args0[32..]);

        xudt_rce_script.as_builder().args(result.pack()).build()
    } else {
        xudt_rce_script
    };

    let witness = build_extension_data(
        total_count,
        rce_index,
        proofs.clone(),
        proof_masks.clone(),
        extension_script_vec,
    );

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
    // extra output type script
    tx_builder = tx_builder
        .output(
            CellOutput::new_builder()
                .lock(always_success_script.clone())
                .type_(Some(always_type_script.clone()).pack())
                .capacity(dummy_capacity.pack())
                .build(),
        )
        .output_data(Default::default());

    // setup input type script
    for i in 0..input_count {
        let previous_out_point = gen_random_out_point(rng);

        let type_script = if no_input_witness {
            None.pack()
        } else {
            Some(xudt_rce_script.clone()).pack()
        };

        let previous_output_cell = CellOutput::new_builder()
            .capacity(dummy_capacity.pack())
            // give an "always success" lock script for testing
            .lock(always_success_script.clone())
            .type_(type_script)
            .build();
        dummy.cells.insert(
            previous_out_point.clone(),
            (
                previous_output_cell.clone(),
                Bytes::copy_from_slice(&input_amount[i].to_le_bytes()[..]),
            ),
        );

        tx_builder = tx_builder.input(CellInput::new(previous_out_point, 0));

        if !no_input_witness {
            let witness_args = WitnessArgsBuilder::default()
                .input_type(Some(witness.clone()).pack())
                .build();
            tx_builder = tx_builder.witness(witness_args.as_bytes().pack());
        } else {
            let witness_args = WitnessArgsBuilder::default()
                .output_type(Some(witness.clone()).pack())
                .build();
            tx_builder = tx_builder.witness(witness_args.as_bytes().pack());
        }
    }
    // extra input type script
    let previous_out_point = gen_random_out_point(rng);
    let previous_output_cell = CellOutput::new_builder()
        .capacity(dummy_capacity.pack())
        .lock(always_success_script.clone())
        .type_(Some(always_type_script.clone()).pack())
        .build();
    dummy.cells.insert(
        previous_out_point.clone(),
        (previous_output_cell.clone(), Bytes::default()),
    );
    tx_builder = tx_builder.input(CellInput::new(previous_out_point, 0));

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
            Bytes::copy_from_slice(random_args.as_ref()),
            None,
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
        &Bytes::copy_from_slice(bin),
        Bytes::copy_from_slice(random_args.as_ref()),
        None,
    );
    tx_builder = b0;

    (rce_script.code_hash(), tx_builder)
}

fn generate_proofs(
    scheme: TestScheme,
    script_hash: &Vec<[u8; 32]>,
) -> (Vec<Vec<u8>>, Vec<Bytes>, Vec<u8>) {
    let mut proofs = Vec::<Vec<u8>>::default();
    let mut rc_data = Vec::<Bytes>::default();
    let mut proof_masks = Vec::<u8>::default();

    match scheme {
        TestScheme::BothOn => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::OnWhiteList, script_hash);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::OnBlackList, script_hash);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(3);
            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(3);
        }
        TestScheme::OnlyInputOnWhiteList => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::OnWhiteList, script_hash);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::NotOnWhiteList, script_hash);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(1); // input

            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(2); // output
        }
        TestScheme::OnlyOutputOnWhiteList => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::NotOnWhiteList, script_hash);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::OnWhiteList, script_hash);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(1); // input

            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(2); // output
        }
        TestScheme::BothOnWhiteList => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::OnWhiteList, script_hash);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::OnWhiteList, script_hash);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(1); // input

            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(2); // output
        }
        _ => {
            let (proof1, rc_data1) = generate_single_proof(scheme, script_hash);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(3);
        }
    }

    (proofs, rc_data, proof_masks)
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
        false,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_simple_udt_owner_mode() {
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
        true,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_simple_udt_owner_mode_for_input_type() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![200],
        vec![&EXTENSION_SCRIPT_0],
        TestScheme::OwnerModeForInputType,
        false,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_simple_udt_owner_mode_for_output_type() {
    let mut rng = thread_rng();
    let mut data_loader = DummyDataLoader::new();
    let tx = gen_tx(
        &mut data_loader,
        Bytes::from(vec![0u8; 32]),
        1,
        1,
        vec![100],
        vec![200],
        vec![&EXTENSION_SCRIPT_0],
        TestScheme::OwnerModeForOutputType,
        false,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
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
        false,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let verify_result =
        TransactionScriptsVerifier::new(&resolved_tx, &data_loader).verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(-52).input_type_script(0),
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
        false,
        XudtFlags::InArgs,
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
        false,
        XudtFlags::InArgs,
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
        false,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(1).input_type_script(0)
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
        false,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(1).input_type_script(0)
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
        false,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_rce_no_input_witness() {
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
        true,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_rce_no_input_witness_extension_script_in_witness() {
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
        true,
        XudtFlags::InWitness,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_rce_only_input_on_wl() {
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
        TestScheme::OnlyInputOnWhiteList,
        false,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(59).input_type_script(0)
    );
}

#[test]
fn test_rce_only_output_on_wl() {
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
        TestScheme::OnlyOutputOnWhiteList,
        false,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(59).input_type_script(0), // ERROR_NOT_ON_WHITE_LIST
    );
}

#[test]
fn test_rce_both_on_wl() {
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
        TestScheme::BothOnWhiteList,
        false,
        XudtFlags::InArgs,
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
        false,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(59).input_type_script(0), // ERROR_NOT_ON_WHITE_LIST
    );
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
        false,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    verify_result.expect("pass verification");
}

#[test]
fn test_rce_not_on_bl_extension_script_in_witness() {
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
        true,
        XudtFlags::InArgs,
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
        false,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(57).input_type_script(0), // ERROR_ON_BLACK_LIST
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
        false,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(54).input_type_script(0), // ERROR_RCE_EMERGENCY_HATL
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
        false,
        XudtFlags::InArgs,
        &mut rng,
    );
    let resolved_tx = build_resolved_tx(&data_loader, &tx);
    let mut verifier = TransactionScriptsVerifier::new(&resolved_tx, &data_loader);
    verifier.set_debug_printer(debug_printer);
    let verify_result = verifier.verify(MAX_CYCLES);
    assert_error_eq!(
        verify_result.unwrap_err(),
        ScriptError::ValidationFailure(57).input_type_script(0), // ERROR_ON_BLACK_LIST
    );
}
