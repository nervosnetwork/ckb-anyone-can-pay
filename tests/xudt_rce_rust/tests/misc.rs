// tools, functions, utilities, etc

use std::collections::HashMap;

use ckb_hash::{Blake2b, Blake2bBuilder};
use ckb_traits::{CellDataProvider, HeaderProvider};
use ckb_types::core::cell::{CellMeta, CellMetaBuilder, ResolvedTransaction};
use ckb_types::core::{HeaderView, TransactionView};
use ckb_types::molecule::prelude::{Builder, Entity};
use ckb_types::packed::{Byte32, CellOutput, OutPoint};
use ckb_types::prelude::Pack;
use lazy_static::lazy_static;
use rand::prelude::ThreadRng;
use rand::Rng;
use sparse_merkle_tree::default_store::DefaultStore;
use sparse_merkle_tree::traits::Hasher;
use sparse_merkle_tree::{SparseMerkleTree, H256};

use xudt_test::xudt_rce_mol::{RCDataBuilder, RCDataUnion, RCRuleBuilder};

pub const MAX_CYCLES: u64 = std::u64::MAX;
// on(1): white list
// off(0): black list
pub const WHITE_BLACK_LIST_MASK: u8 = 0x2;
// on(1): emergency halt mode
// off(0): not int emergency halt mode
pub const EMERGENCY_HALT_MODE_MASK: u8 = 0x1;

pub const BLAKE2B_KEY: &[u8] = &[];
pub const BLAKE2B_LEN: usize = 32;
pub const PERSONALIZATION: &[u8] = b"ckb-default-hash";

lazy_static! {
    pub static ref RCE_VALIDATOR_BIN: ckb_types::bytes::Bytes =
        ckb_types::bytes::Bytes::from(include_bytes!("../../../build/rce_validator").as_ref());
    pub static ref ALWAYS_SUCCESS_BIN: ckb_types::bytes::Bytes =
        ckb_types::bytes::Bytes::from(include_bytes!("../../../build/always_success").as_ref());
    pub static ref SMT_EXISTING: H256 = H256::from([
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
    ]);
    pub static ref SMT_NOT_EXISTING: H256 = H256::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0
    ]);
    pub static ref TYPE_ID_CODE_HASH: [u8; 32] = [
        0x54, 0x59, 0x50, 0x45, 0x5f, 0x49, 0x44, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];
    pub static ref K1: [u8; 32] = [
        111, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];
    pub static ref K2: [u8; 32] = [
        222, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    ];
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
    fn write_byte(&mut self, b: u8) {
        self.0.update(&[b][..]);
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

pub fn build_rc_rule(
    smt_root: &[u8; 32],
    is_black: bool,
    is_emergency: bool,
) -> ckb_types::bytes::Bytes {
    let mut flags: u8 = 0;

    if !is_black {
        flags ^= WHITE_BLACK_LIST_MASK;
    }
    if is_emergency {
        flags ^= EMERGENCY_HALT_MODE_MASK;
    }
    let smt_root = ckb_types::molecule::bytes::Bytes::copy_from_slice(smt_root.as_ref());
    let sr = ckb_types::packed::Byte32::new_unchecked(smt_root);
    let rcrule = RCRuleBuilder::default()
        .flags(ckb_types::molecule::prelude::Byte::new(flags))
        .smt_root(sr)
        .build();
    let res = RCDataBuilder::default()
        .set(RCDataUnion::RCRule(rcrule))
        .build();
    ckb_types::bytes::Bytes::copy_from_slice(res.as_slice())
}

pub fn gen_random_out_point(rng: &mut ThreadRng) -> OutPoint {
    let hash = {
        let mut buf = [0u8; 32];
        rng.fill(&mut buf);
        Pack::pack(&buf)
    };
    OutPoint::new(hash, 0)
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
