use std::collections::HashMap;

use ckb_crypto::secp::{Generator, Privkey, Pubkey};
use ckb_hash::{Blake2b, Blake2bBuilder};
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::bytes::{BufMut, BytesMut};
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellMetaBuilder, ResolvedTransaction},
        Capacity, DepType, HeaderView, ScriptHashType, TransactionBuilder, TransactionView,
    },
    molecule,
    packed::{
        self, Byte32, CellDep, CellInput, CellOutput, OutPoint, Script, WitnessArgs,
        WitnessArgsBuilder,
    },
    prelude::*,
    H256 as CkbH256,
};
use lazy_static::lazy_static;
use rand::prelude::{thread_rng, ThreadRng};
use rand::Rng;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::traits::Hasher;
use sparse_merkle_tree::{SparseMerkleTree, H256};

use rc_lock_test::rc_lock;
use rc_lock_test::rc_lock::RcLockWitnessLock;
use rc_lock_test::xudt_rce_mol::{
    RCCellVecBuilder, RCDataBuilder, RCDataUnion, RCRuleBuilder, SmtProofBuilder,
    SmtProofEntryBuilder, SmtProofEntryVec, SmtProofEntryVecBuilder,
};

// on(1): white list
// off(0): black list
pub const WHITE_BLACK_LIST_MASK: u8 = 0x2;
// on(1): emergency halt mode
// off(0): not int emergency halt mode
pub const EMERGENCY_HALT_MODE_MASK: u8 = 0x1;

pub const BLAKE2B_KEY: &[u8] = &[];
pub const BLAKE2B_LEN: usize = 32;
pub const PERSONALIZATION: &[u8] = b"ckb-default-hash";

pub const MAX_CYCLES: u64 = std::u64::MAX;
pub const SIGNATURE_SIZE: usize = 65;

// errors
pub const ERROR_ENCODING: i8 = -2;
pub const ERROR_WITNESS_SIZE: i8 = -22;
pub const ERROR_PUBKEY_BLAKE160_HASH: i8 = -31;
pub const ERROR_OUTPUT_AMOUNT_NOT_ENOUGH: i8 = -42;
pub const ERROR_NO_PAIR: i8 = -44;
pub const ERROR_DUPLICATED_INPUTS: i8 = -45;
pub const ERROR_DUPLICATED_OUTPUTS: i8 = -46;
pub const ERROR_LOCK_SCRIPT_HASH_NOT_FOUND: i8 = 70;
pub const ERROR_NOT_ON_WHITE_LIST: i8 = 59;
pub const ERROR_NO_WHITE_LIST: i8 = 83;
pub const ERROR_ON_BLACK_LIST: i8 = 57;
pub const ERROR_RCE_EMERGENCY_HALT: i8 = 54;

lazy_static! {
    pub static ref RC_LOCK: Bytes = Bytes::from(&include_bytes!("../../../build/rc_lock")[..]);
    pub static ref SECP256K1_DATA_BIN: Bytes =
        Bytes::from(&include_bytes!("../../../build/secp256k1_data")[..]);
    pub static ref ALWAYS_SUCCESS: Bytes =
        Bytes::from(&include_bytes!("../../../build/always_success")[..]);
    pub static ref SMT_EXISTING: H256 = H256::from([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
    ]);
    pub static ref SMT_NOT_EXISTING: H256 = H256::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
    ]);
}
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

pub type SMT = SparseMerkleTree<CKBBlake2bHasher, H256, DefaultStore<H256>>;

pub fn new_smt(pairs: Vec<(H256, H256)>) -> SMT {
    let mut smt = SMT::default();
    for (key, value) in pairs {
        smt.update(key, value).unwrap();
    }
    smt
}

pub fn gen_random_out_point(rng: &mut ThreadRng) -> OutPoint {
    let hash = {
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        Pack::pack(&buf)
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
    let capacity = bin.len() as u64;
    let cell = CellOutput::new_builder()
        .capacity(capacity.pack())
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

#[derive(Default)]
pub struct DummyDataLoader {
    pub cells: HashMap<OutPoint, (CellOutput, ckb_types::bytes::Bytes)>,
}

impl DummyDataLoader {
    pub fn new() -> Self {
        Self::default()
    }
}

impl CellDataProvider for DummyDataLoader {
    // load Cell Data
    fn load_cell_data(&self, cell: &CellMeta) -> Option<ckb_types::bytes::Bytes> {
        cell.mem_cell_data.clone().or_else(|| {
            self.cells
                .get(&cell.out_point)
                .map(|(_, data)| data.clone())
        })
    }

    fn load_cell_data_hash(&self, cell: &CellMeta) -> Option<Byte32> {
        self.load_cell_data(cell)
            .map(|e| CellOutput::calc_data_hash(&e))
    }

    fn get_cell_data(&self, _out_point: &OutPoint) -> Option<ckb_types::bytes::Bytes> {
        None
    }

    fn get_cell_data_hash(&self, _out_point: &OutPoint) -> Option<Byte32> {
        None
    }
}

impl HeaderProvider for DummyDataLoader {
    fn get_header(&self, _hash: &Byte32) -> Option<HeaderView> {
        None
    }
}

pub fn blake160(message: &[u8]) -> Bytes {
    let r = ckb_hash::blake2b_256(message);
    Bytes::copy_from_slice(&r[..20])
}

pub fn sign_tx(
    _dummy: &mut DummyDataLoader,
    tx: TransactionView,
    config: &mut TestConfig,
) -> TransactionView {
    // for owner lock, the first input is an "always success" script: used as owner lock
    let (begin_index, witnesses_len) = if config.is_owner_lock() {
        (1, tx.witnesses().len() - 1)
    } else {
        (0, tx.witnesses().len())
    };
    sign_tx_by_input_group(tx, begin_index, witnesses_len, config)
}

fn build_proofs(proofs: Vec<Vec<u8>>, proof_masks: Vec<u8>) -> SmtProofEntryVec {
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
    builder.build()
}

pub fn append_rc(
    dummy: &mut DummyDataLoader,
    tx_builder: TransactionBuilder,
    config: &mut TestConfig,
) -> TransactionBuilder {
    let smt_key = config.id.to_smt_key();
    let (proofs, rc_datas, proof_masks) = generate_proofs(config.scheme, &vec![smt_key]);
    let (rc_root, b0) = generate_rce_cell(dummy, tx_builder, rc_datas);

    config.proofs = proofs;
    config.proof_masks = proof_masks;
    config.rc_root = rc_root.as_bytes();

    b0
}

// when adding the input lock script as first one,
// it will affect witness offset and length.
pub fn append_input_lock_script_hash(
    dummy: &mut DummyDataLoader,
    tx_builder: TransactionBuilder,
) -> (TransactionBuilder, Bytes) {
    let mut rng = thread_rng();
    let previous_tx_hash = {
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        buf.pack()
    };
    let previous_out_point = OutPoint::new(previous_tx_hash, 0);

    let hash = CellOutput::calc_data_hash(&ALWAYS_SUCCESS);
    let script = Script::new_builder()
        .args(Default::default())
        .code_hash(hash.clone())
        .hash_type(ScriptHashType::Data.into())
        .build();
    let blake160 = {
        let hash = script.calc_script_hash();
        let mut res = BytesMut::new();
        res.put(&hash.as_slice()[0..20]);
        res.freeze()
    };

    let previous_output_cell = CellOutput::new_builder()
        .capacity(Capacity::shannons(42).pack())
        .lock(script)
        .build();
    dummy.cells.insert(
        previous_out_point.clone(),
        (previous_output_cell.clone(), Bytes::new()),
    );
    let tx_builder = tx_builder
        .input(CellInput::new(previous_out_point, 0))
        .witness(Default::default());

    (tx_builder, blake160)
}

pub fn sign_tx_by_input_group(
    tx: TransactionView,
    begin_index: usize,
    len: usize,
    config: &TestConfig,
) -> TransactionView {
    let proof_vec = build_proofs(config.proofs.clone(), config.proof_masks.clone());
    let identity = config.id.to_identity();
    let tx_hash = tx.hash();
    let mut signed_witnesses: Vec<packed::Bytes> = tx
        .inputs()
        .into_iter()
        .enumerate()
        .map(|(i, _)| {
            if i == begin_index {
                let mut blake2b = ckb_hash::new_blake2b();
                let mut message = [0u8; 32];
                blake2b.update(&tx_hash.raw_data());
                // digest the first witness
                let witness = WitnessArgs::new_unchecked(tx.witnesses().get(i).unwrap().unpack());
                let zero_lock = gen_zero_witness_lock(config.use_rc, &proof_vec, &identity);

                let witness_for_digest = witness
                    .clone()
                    .as_builder()
                    .lock(Some(zero_lock).pack())
                    .build();
                let witness_len = witness_for_digest.as_bytes().len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_for_digest.as_bytes());
                ((i + 1)..(i + len)).for_each(|n| {
                    let witness = tx.witnesses().get(n).unwrap();
                    let witness_len = witness.raw_data().len() as u64;
                    blake2b.update(&witness_len.to_le_bytes());
                    blake2b.update(&witness.raw_data());
                });
                blake2b.finalize(&mut message);
                let message = CkbH256::from(message);
                let sig = config.private_key.sign_recoverable(&message).expect("sign");
                let sig_bytes = Bytes::from(sig.serialize());
                let witness_lock =
                    gen_witness_lock(sig_bytes, config.use_rc, &proof_vec, &identity);
                witness
                    .as_builder()
                    .lock(Some(witness_lock).pack())
                    .build()
                    .as_bytes()
                    .pack()
            } else {
                tx.witnesses().get(i).unwrap_or_default()
            }
        })
        .collect();
    for i in signed_witnesses.len()..tx.witnesses().len() {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    if config.scheme2 == TestScheme2::NoWitness {
        signed_witnesses.clear();
    }
    // calculate message
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

pub fn gen_tx(dummy: &mut DummyDataLoader, config: &mut TestConfig) -> TransactionView {
    let lock_args = config.gen_args();
    gen_tx_with_grouped_args(dummy, vec![(lock_args, 1)], config)
}

pub fn gen_tx_with_grouped_args(
    dummy: &mut DummyDataLoader,
    grouped_args: Vec<(Bytes, usize)>,
    config: &mut TestConfig,
) -> TransactionView {
    let mut rng = thread_rng();
    // setup sighash_all dep
    let sighash_all_out_point = {
        let contract_tx_hash = {
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            buf.pack()
        };
        OutPoint::new(contract_tx_hash.clone(), 0)
    };
    // dep contract code
    let sighash_all_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(RC_LOCK.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    let sighash_all_cell_data_hash = CellOutput::calc_data_hash(&RC_LOCK);
    dummy.cells.insert(
        sighash_all_out_point.clone(),
        (sighash_all_cell, RC_LOCK.clone()),
    );
    // always success
    let always_success_out_point = {
        let contract_tx_hash = {
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            buf.pack()
        };
        OutPoint::new(contract_tx_hash.clone(), 0)
    };
    let always_success_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(ALWAYS_SUCCESS.len())
                .expect("script capacity")
                .pack(),
        )
        .build();
    dummy.cells.insert(
        always_success_out_point.clone(),
        (always_success_cell, ALWAYS_SUCCESS.clone()),
    );
    // setup secp256k1_data dep
    let secp256k1_data_out_point = {
        let tx_hash = {
            let mut buf = [0u8; 32];
            rng.fill(&mut buf);
            buf.pack()
        };
        OutPoint::new(tx_hash, 0)
    };
    let secp256k1_data_cell = CellOutput::new_builder()
        .capacity(
            Capacity::bytes(SECP256K1_DATA_BIN.len())
                .expect("data capacity")
                .pack(),
        )
        .build();
    dummy.cells.insert(
        secp256k1_data_out_point.clone(),
        (secp256k1_data_cell, SECP256K1_DATA_BIN.clone()),
    );
    // setup default tx builder
    let dummy_capacity = Capacity::shannons(42);
    let mut tx_builder = TransactionBuilder::default()
        .cell_dep(
            CellDep::new_builder()
                .out_point(sighash_all_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(always_success_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .cell_dep(
            CellDep::new_builder()
                .out_point(secp256k1_data_out_point)
                .dep_type(DepType::Code.into())
                .build(),
        )
        .output(
            CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .build(),
        )
        .output_data(Bytes::new().pack());

    if config.is_owner_lock() {
        // insert an "always success" script as first input script.
        let (b0, blake160) = append_input_lock_script_hash(dummy, tx_builder);
        tx_builder = b0;
        config.id.blake160 = blake160;
    }
    if config.is_rc() {
        tx_builder = append_rc(dummy, tx_builder, config);
    }

    for (mut args, inputs_size) in grouped_args {
        // setup dummy input unlock script
        for _ in 0..inputs_size {
            let previous_tx_hash = {
                let mut buf = [0u8; 32];
                rng.fill(&mut buf);
                buf.pack()
            };
            args = if config.is_owner_lock() {
                if config.scheme == TestScheme::OwnerLockMismatched {
                    config.id.blake160 = {
                        let mut buf = BytesMut::new();
                        buf.resize(20, 0);
                        buf.freeze()
                    };
                    config.gen_args()
                } else {
                    config.gen_args()
                }
            } else {
                if config.is_rc() {
                    config.gen_args()
                } else {
                    args
                }
            };
            let previous_out_point = OutPoint::new(previous_tx_hash, 0);
            let script = Script::new_builder()
                .args(args.pack())
                .code_hash(sighash_all_cell_data_hash.clone())
                .hash_type(ScriptHashType::Data.into())
                .build();
            let previous_output_cell = CellOutput::new_builder()
                .capacity(dummy_capacity.pack())
                .lock(script)
                .build();
            dummy.cells.insert(
                previous_out_point.clone(),
                (previous_output_cell.clone(), Bytes::new()),
            );
            let mut random_extra_witness = Vec::<u8>::new();
            let witness_len = if config.scheme == TestScheme::LongWitness {
                40000
            } else {
                32
            };
            random_extra_witness.resize(witness_len, 0);
            rng.fill(&mut random_extra_witness[..]);

            let witness_args = WitnessArgsBuilder::default()
                .input_type(Some(Bytes::copy_from_slice(&random_extra_witness[..])).pack())
                .build();
            tx_builder = tx_builder
                .input(CellInput::new(previous_out_point, 0))
                .witness(witness_args.as_bytes().pack());
        }
    }

    tx_builder.build()
}

pub fn sign_tx_hash(tx: TransactionView, tx_hash: &[u8], config: &TestConfig) -> TransactionView {
    let identity = config.id.to_identity();
    // calculate message
    let mut blake2b = ckb_hash::new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(tx_hash);
    blake2b.finalize(&mut message);
    let message = CkbH256::from(message);
    let sig = config.private_key.sign_recoverable(&message).expect("sign");
    let proofs = SmtProofEntryVecBuilder::default().build();
    let witness_lock = gen_witness_lock(sig.serialize().into(), config.use_rc, &proofs, &identity);
    let witness_args = WitnessArgsBuilder::default()
        .lock(Some(witness_lock).pack())
        .build();
    tx.as_advanced_builder()
        .set_witnesses(vec![witness_args.as_bytes().pack()])
        .build()
}

pub fn build_resolved_tx(
    data_loader: &DummyDataLoader,
    tx: &TransactionView,
) -> ResolvedTransaction {
    let resolved_cell_deps = tx
        .cell_deps()
        .into_iter()
        .map(|dep| {
            let deps_out_point = dep.clone();
            let (dep_output, dep_data) =
                data_loader.cells.get(&deps_out_point.out_point()).unwrap();
            CellMetaBuilder::from_cell_output(dep_output.to_owned(), dep_data.to_owned())
                .out_point(deps_out_point.out_point().clone())
                .build()
        })
        .collect();

    let mut resolved_inputs = Vec::new();
    for i in 0..tx.inputs().len() {
        let previous_out_point = tx.inputs().get(i).unwrap().previous_output();
        let (input_output, input_data) = data_loader.cells.get(&previous_out_point).unwrap();
        resolved_inputs.push(
            CellMetaBuilder::from_cell_output(input_output.to_owned(), input_data.to_owned())
                .out_point(previous_out_point)
                .build(),
        );
    }

    ResolvedTransaction {
        transaction: tx.clone(),
        resolved_cell_deps,
        resolved_inputs,
        resolved_dep_groups: vec![],
    }
}

pub fn debug_printer(script: &Byte32, msg: &str) {
    let slice = script.as_slice();
    let str = format!(
        "Script({:x}{:x}{:x}{:x}{:x})",
        slice[0], slice[1], slice[2], slice[3], slice[4]
    );
    println!("{:?}: {}", str, msg);
}

pub const IDENTITY_FLAGS_PUBKEY_HASH: u8 = 0;
pub const IDENTITY_FLAGS_OWNER_LOCK: u8 = 1;

pub struct Identity {
    pub flags: u8,
    pub blake160: Bytes,
}

impl Identity {
    pub fn to_smt_key(&self) -> [u8; 32] {
        let mut ret: [u8; 32] = Default::default();
        ret[0] = self.flags;
        (&mut ret[1..21]).copy_from_slice(self.blake160.as_ref());
        ret
    }
    pub fn to_identity(&self) -> rc_lock::Identity {
        let mut ret: [u8; 21] = Default::default();
        ret[0] = self.flags;
        (&mut ret[1..21]).copy_from_slice(self.blake160.as_ref());
        rc_lock::Identity::from_slice(&ret[..]).unwrap()
    }
}

pub struct TestConfig {
    pub id: Identity,
    pub use_rc: bool,
    pub scheme: TestScheme,
    pub scheme2: TestScheme2,
    pub rc_root: Bytes,
    pub proofs: Vec<Vec<u8>>,
    pub proof_masks: Vec<u8>,
    pub private_key: Privkey,
    pub pubkey: Pubkey,
}

#[derive(Copy, Clone, PartialEq)]
pub enum TestScheme {
    None,
    LongWitness,

    OnWhiteList,
    NotOnWhiteList,
    OnlyInputOnWhiteList,
    OnlyOutputOnWhiteList,
    BothOnWhiteList,
    OnBlackList,
    NotOnBlackList,
    BothOn,
    EmergencyHaltMode,

    OwnerLockMismatched,
    OwnerLockWithoutWitness,
}

#[derive(Copy, Clone, PartialEq)]
pub enum TestScheme2 {
    None,
    NoWitness,
}

impl TestConfig {
    pub fn new(flags: u8, use_rc: bool) -> TestConfig {
        let private_key = Generator::random_privkey();
        let pubkey = private_key.pubkey().expect("pubkey");
        let pubkey_hash = blake160(&pubkey.serialize());

        let blake160 = {
            if flags == IDENTITY_FLAGS_PUBKEY_HASH {
                pubkey_hash
            } else {
                Default::default()
            }
        };
        let rc_root: Bytes = {
            let mut buf = BytesMut::new();
            buf.resize(32, 0);
            buf.freeze()
        };

        TestConfig {
            id: Identity { flags, blake160 },
            use_rc,
            rc_root,
            scheme: TestScheme::None,
            scheme2: TestScheme2::None,
            proofs: Default::default(),
            proof_masks: Default::default(),
            private_key,
            pubkey,
        }
    }

    pub fn set_scheme(&mut self, scheme: TestScheme) {
        self.scheme = scheme;
    }

    pub fn gen_args(&self) -> Bytes {
        let mut bytes = BytesMut::with_capacity(128);
        if self.use_rc {
            bytes.resize(21, 0);
            bytes.put(self.rc_root.as_ref());
        } else {
            bytes.put_u8(self.id.flags);
            bytes.put(self.id.blake160.as_ref());
        }
        bytes.freeze()
    }

    pub fn is_owner_lock(&self) -> bool {
        self.id.flags == IDENTITY_FLAGS_OWNER_LOCK
    }
    pub fn is_pubkey_hash(&self) -> bool {
        self.id.flags == IDENTITY_FLAGS_PUBKEY_HASH
    }
    pub fn is_rc(&self) -> bool {
        self.use_rc
    }
}

pub fn gen_witness_lock(
    sig: Bytes,
    use_rc: bool,
    proofs: &SmtProofEntryVec,
    identity: &rc_lock::Identity,
) -> Bytes {
    let builder = RcLockWitnessLock::new_builder();
    let rc_identity = rc_lock::RcIdentityBuilder::default()
        .identity(identity.clone())
        .proofs(proofs.clone())
        .build();

    let mut builder = builder.signature(Some(sig).pack());
    if use_rc {
        let opt = rc_lock::RcIdentityOpt::new_unchecked(rc_identity.as_bytes());
        builder = builder.rc_identity(opt);
    }
    builder.build().as_bytes()
}

pub fn gen_zero_witness_lock(
    use_rc: bool,
    proofs: &SmtProofEntryVec,
    identity: &rc_lock::Identity,
) -> Bytes {
    let mut zero = BytesMut::new();
    zero.resize(65, 0);
    let witness_lock = gen_witness_lock(zero.freeze(), use_rc, proofs, identity);

    let mut res = BytesMut::new();
    res.resize(witness_lock.len(), 0);
    res.freeze()
}

// first generate N RCE cells with each contained one RCRule
// then collect all these RCE cell hash and create the final RCE cell.
pub fn generate_rce_cell(
    dummy: &mut DummyDataLoader,
    mut tx_builder: TransactionBuilder,
    rc_data: Vec<Bytes>,
) -> (Byte32, TransactionBuilder) {
    let mut rng = thread_rng();
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
    );
    tx_builder = b0;

    (rce_script.code_hash(), tx_builder)
}

pub fn generate_proofs(
    scheme: TestScheme,
    smt_key: &Vec<[u8; 32]>,
) -> (Vec<Vec<u8>>, Vec<Bytes>, Vec<u8>) {
    let mut proofs = Vec::<Vec<u8>>::default();
    let mut rc_data = Vec::<Bytes>::default();
    let mut proof_masks = Vec::<u8>::default();

    match scheme {
        TestScheme::BothOn => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::OnBlackList, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(3);
            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(3);
        }
        TestScheme::OnlyInputOnWhiteList => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::NotOnWhiteList, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(1); // input

            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(2); // output
        }
        TestScheme::OnlyOutputOnWhiteList => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::NotOnWhiteList, smt_key);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(1); // input

            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(2); // output
        }
        TestScheme::BothOnWhiteList => {
            let (proof1, rc_data1) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            let (proof2, rc_data2) = generate_single_proof(TestScheme::OnWhiteList, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(1); // input

            proofs.push(proof2);
            rc_data.push(rc_data2);
            proof_masks.push(2); // output
        }
        _ => {
            let (proof1, rc_data1) = generate_single_proof(scheme, smt_key);
            proofs.push(proof1);
            rc_data.push(rc_data1);
            proof_masks.push(3);
        }
    }

    (proofs, rc_data, proof_masks)
}

pub fn generate_single_proof(scheme: TestScheme, smt_key: &Vec<[u8; 32]>) -> (Vec<u8>, Bytes) {
    let hash = smt_key.clone();
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
