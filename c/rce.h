#ifndef XUDT_RCE_SIMULATOR_C_RCE_H_
#define XUDT_RCE_SIMULATOR_C_RCE_H_
#include "ckb_smt.h"
#include "xudt_rce_mol.h"
#include "xudt_rce_mol2.h"

enum ErrorCode {
  // 0 is the only success code. We can use 0 directly.

  // inherit from simple_udt
  ERROR_ARGUMENTS_LEN = -1,
  ERROR_ENCODING = -2,
  ERROR_SYSCALL = -3,
  ERROR_SCRIPT_TOO_LONG = -21,
  ERROR_OVERFLOWING = -51,
  ERROR_AMOUNT = -52,

  // error code is starting from 40, to avoid conflict with
  // common error code in other scripts.
  ERROR_CANT_LOAD_LIB = 40,
  ERROR_CANT_FIND_SYMBOL,
  ERROR_INVALID_RCE_ARGS,
  ERROR_NOT_ENOUGH_BUFF,
  ERROR_INVALID_FLAG,
  ERROR_INVALID_ARGS_FORMAT,
  ERROR_INVALID_WITNESS_FORMAT,
  ERROR_INVALID_MOL_FORMAT,
  ERROR_BLAKE2B_ERROR,
  ERROR_HASH_MISMATCHED,
  ERROR_RCRULES_TOO_DEEP,
  ERROR_TOO_MANY_RCRULES,
  ERROR_RCRULES_PROOFS_MISMATCHED,
  ERROR_SMT_VERIFY_FAILED,
  ERROR_RCE_EMERGENCY_HALT,
  ERROR_NOT_VALIDATED,
  ERROR_TOO_MANY_LOCK,
  ERROR_ON_BLACK_LIST,
  ERROR_TYPE_FREEZED,
  ERROR_APPEND_ONLY,
  ERROR_EOF,
  ERROR_TOO_LONG_PROOF,
};

#define CHECK2(cond, code) \
  do {                     \
    if (!(cond)) {         \
      err = code;          \
      ASSERT(0);           \
      goto exit;           \
    }                      \
  } while (0)

#define CHECK(_code)    \
  do {                  \
    int code = (_code); \
    if (code != 0) {    \
      err = code;       \
      ASSERT(0);        \
      goto exit;        \
    }                   \
  } while (0)

int get_extension_data(uint32_t index, uint8_t* buff, uint32_t buff_len,
                       uint32_t* out_len);

#define BLAKE2B_BLOCK_SIZE 32
#define MAX_EXTENSION_DATA_SIZE 32768
#define MAX_LOCK_SCRIPT_HASH_COUNT 2048
#define MAX_RCRULES_COUNT 8192
#define MAX_RECURSIVE_DEPTH 16
#define MAX_TEMP_PROOF_LENGTH 32768

// RC stands for Regulation Compliance
typedef struct RCRule {
  uint8_t smt_root[32];
  uint8_t flags;
} RCRule;

typedef struct RceState {
  RCRule rcrules[MAX_RCRULES_COUNT];
  uint32_t rcrules_count;
} RceState;

void rce_init_state(RceState* state) { state->rcrules_count = 0; }

// molecule doesn't provide names
typedef enum RCDataUnionType {
  RCDataUnionRule = 0,
  RCDataUnionCellVec = 1
} RCDataUnionType;

// RCE scripts leverage optimized sparse merkle tree
// (https://github.com/jjyr/sparse-merkle-tree)(SMT) extensively to reduce
// storage costs. For each sparse merkle tree used here, the key will be lock
// script hash, values are either 0 or 1: 0 represents the corresponding lock
// hash is missing in the sparse merkle tree, whereas 1 means the lock hash is
// included in the sparse merkle tree.
uint8_t SMT_VALUE_NOT_EXISTING[SMT_VALUE_BYTES] = {0};
uint8_t SMT_VALUE_EXISTING[SMT_VALUE_BYTES] = {1};

bool rce_is_white_list(uint8_t flags) { return flags & 0x2; }

bool rce_is_emergency_halt_mode(uint8_t flags) { return flags & 0x1; }

static uint32_t rce_read_from_cell_data(uintptr_t* arg, uint8_t* ptr,
                                        uint32_t len, uint32_t offset) {
  int err;
  uint64_t output_len = len;
  err = ckb_checked_load_cell_data(ptr, &output_len, offset, arg[0], arg[1]);
  if (err != 0) {
    return 0;
  }
  return output_len;
}

int make_cursor_from_witness(WitnessArgsType* witness);

static int rce_get_proofs(uint32_t index, SmtProofVecType* res) {
  int err = 0;
  WitnessArgsType witness;

  err = make_cursor_from_witness(&witness);
  CHECK(err);

  BytesOptType input = witness.t->input_type(&witness);
  CHECK2(!input.t->is_none(&input), ERROR_INVALID_MOL_FORMAT);

  mol2_cursor_t bytes = input.t->unwrap(&input);
  // convert Bytes to XudtWitnessInputType
  XudtWitnessInputType witness_input = make_XudtWitnessInput(&bytes);
  BytesVecType extension_data_vec =
      witness_input.t->extension_data(&witness_input);

  bool existing = false;
  mol2_cursor_t extension_data =
      extension_data_vec.t->get(&extension_data_vec, index, &existing);
  CHECK2(existing, ERROR_INVALID_MOL_FORMAT);

  res->cur = extension_data;
  res->t = GetSmtProofVecVTable();

  err = 0;
exit:
  return err;
}

static int rce_make_cursor_from_cell_data(uint8_t* data_source,
                                          uint32_t max_cache_size,
                                          mol2_cursor_t* cell_data,
                                          size_t index) {
  int err = 0;
  uint64_t cell_data_len = 0;
  err = ckb_load_cell_data(NULL, &cell_data_len, 0, index, CKB_SOURCE_CELL_DEP);
  CHECK(err);
  CHECK2(cell_data_len > 0, ERROR_INVALID_MOL_FORMAT);

  cell_data->offset = 0;
  cell_data->size = cell_data_len;

  mol2_data_source_t* ptr = (mol2_data_source_t*)data_source;

  ptr->read = rce_read_from_cell_data;
  ptr->total_size = cell_data_len;
  // pass index and source as args
  ptr->args[0] = (uintptr_t)index;
  ptr->args[1] = CKB_SOURCE_CELL_DEP;

  ptr->cache_size = 0;
  ptr->start_point = 0;
  ptr->max_cache_size = max_cache_size;

  cell_data->data_source = ptr;

  err = 0;
exit:
  return err;
}

// Note: RCRules is ordered as depth-first search
int rce_gather_rcrules_recursively(RceState* rce_state,
                                   const uint8_t* rce_cell_hash, int depth) {
  int err = 0;

  if (depth > MAX_RECURSIVE_DEPTH) return ERROR_RCRULES_TOO_DEEP;

  size_t index = 0;
  // note: RCE Cell is with hash_type = 1
  err = ckb_look_for_dep_with_hash2(rce_cell_hash, 1, &index);
  if (err != 0) return err;

  // data_source's lifetime should be long enough, it can't be defined inside
  // rce_make_cursor_from_cell_data
  const uint32_t max_cache_size = 128;
  uint8_t data_source_buff[MOL2_DATA_SOURCE_LEN(128)];

  mol2_cursor_t cell_data;
  err = rce_make_cursor_from_cell_data(data_source_buff, max_cache_size,
                                       &cell_data, index);
  CHECK(err);

  RCDataType rc_data = make_RCData(&cell_data);

  uint32_t item_id = rc_data.t->item_id(&rc_data);
  if (item_id == RCDataUnionRule) {
    RCRuleType rule = rc_data.t->as_RCRule(&rc_data);
    // "Any more RCRule structures will result in an immediate failure."
    CHECK2(rce_state->rcrules_count < MAX_RCRULES_COUNT,
           ERROR_TOO_MANY_RCRULES);

    rce_state->rcrules[rce_state->rcrules_count].flags = rule.t->flags(&rule);
    mol2_cursor_t smt_root = rule.t->smt_root(&rule);
    mol2_read_at(&smt_root,
                 rce_state->rcrules[rce_state->rcrules_count].smt_root,
                 SMT_KEY_BYTES);

    rce_state->rcrules_count++;
  } else if (item_id == RCDataUnionCellVec) {
    RCCellVecType cell_vec = rc_data.t->as_RCCellVec(&rc_data);

    uint32_t len = cell_vec.t->len(&cell_vec);
    for (uint32_t i = 0; i < len; i++) {
      uint8_t hash[BLAKE2B_BLOCK_SIZE];

      bool existing = false;
      mol2_cursor_t item = cell_vec.t->get(&cell_vec, i, &existing);
      CHECK2(existing, ERROR_INVALID_MOL_FORMAT);
      CHECK2(item.size == BLAKE2B_BLOCK_SIZE, ERROR_INVALID_MOL_FORMAT);

      uint32_t read_len = mol2_read_at(&item, hash, sizeof(hash));
      CHECK2(read_len == sizeof(hash), ERROR_INVALID_MOL_FORMAT);
      err = rce_gather_rcrules_recursively(rce_state, hash, depth + 1);
      CHECK(err);
    }
  } else {
    CHECK2(false, ERROR_INVALID_MOL_FORMAT);
  }

  err = 0;
exit:
  return err;
}

int rce_collect_hashes(smt_state_t* bl_states, smt_state_t* wl_states) {
  int err = 0;
  uint32_t index = 0;

  uint8_t lock_script_hash[SMT_KEY_BYTES];
  uint64_t lock_script_hash_len = SMT_KEY_BYTES;

  index = 0;
  while (true) {
    err = ckb_checked_load_cell_by_field(
        lock_script_hash, &lock_script_hash_len, 0, index,
        CKB_SOURCE_GROUP_INPUT, CKB_CELL_FIELD_LOCK_HASH);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    err = smt_state_insert(wl_states, lock_script_hash, SMT_VALUE_EXISTING);
    CHECK(err);
    err = smt_state_insert(bl_states, lock_script_hash, SMT_VALUE_NOT_EXISTING);
    CHECK(err);
    index++;
  }
  index = 0;
  while (true) {
    err = ckb_checked_load_cell_by_field(
        lock_script_hash, &lock_script_hash_len, 0, index,
        CKB_SOURCE_GROUP_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    err = smt_state_insert(wl_states, lock_script_hash, SMT_VALUE_EXISTING);
    CHECK(err);
    err = smt_state_insert(bl_states, lock_script_hash, SMT_VALUE_NOT_EXISTING);
    CHECK(err);
    index++;
  }

  err = 0;
exit:
  return err;
}

int rce_validate(int is_owner_mode, size_t extension_index, const uint8_t* args,
                 size_t args_len) {
  int err = 0;
  RceState rce_state;
  rce_init_state(&rce_state);

  uint32_t index = 0;

  CHECK2(args_len == BLAKE2B_BLOCK_SIZE, ERROR_INVALID_MOL_FORMAT);
  CHECK2(args != NULL, ERROR_INVALID_RCE_ARGS);
  if (is_owner_mode) return 0;

  rce_state.rcrules_count = 0;
  err = rce_gather_rcrules_recursively(&rce_state, args, 0);
  CHECK(err);

  SmtProofVecType proofs;
  err = rce_get_proofs(extension_index, &proofs);
  CHECK(err);

  uint32_t proof_len = proofs.t->len(&proofs);
  // count of proof should be same as size of RCRules
  CHECK2(proof_len == rce_state.rcrules_count, ERROR_RCRULES_PROOFS_MISMATCHED);

  smt_pair_t wl_entries[MAX_LOCK_SCRIPT_HASH_COUNT];
  smt_pair_t bl_entries[MAX_LOCK_SCRIPT_HASH_COUNT];
  smt_state_t wl_states;
  smt_state_t bl_states;
  smt_state_init(&wl_states, wl_entries, MAX_LOCK_SCRIPT_HASH_COUNT);
  smt_state_init(&bl_states, bl_entries, MAX_LOCK_SCRIPT_HASH_COUNT);

  err = rce_collect_hashes(&bl_states, &wl_states);
  CHECK(err);

  smt_state_normalize(&wl_states);
  smt_state_normalize(&bl_states);

  err = ERROR_SMT_VERIFY_FAILED;
  bool on_white_list = false;
  bool on_black_list = false;

  uint8_t temp_proof[MAX_TEMP_PROOF_LENGTH];

  for (index = 0; index < proof_len; index++) {
    bool existing = false;
    mol2_cursor_t proof = proofs.t->get(&proofs, index, &existing);
    CHECK2(existing, ERROR_INVALID_MOL_FORMAT);

    const RCRule* current_rule = &rce_state.rcrules[index];

    const uint8_t* root_hash = current_rule->smt_root;
    // "Current RCRule must not be in Emergency Halt mode."
    if (rce_is_emergency_halt_mode(current_rule->flags)) {
      err = ERROR_RCE_EMERGENCY_HALT;
      // the emergency halt has the highest priority, can return immediately
      goto exit;
    }
    uint32_t temp_proof_len =
        mol2_read_at(&proof, temp_proof, MAX_TEMP_PROOF_LENGTH);
    CHECK2(temp_proof_len <= MAX_TEMP_PROOF_LENGTH, ERROR_TOO_LONG_PROOF);

    if (rce_is_white_list(current_rule->flags)) {
      err = smt_verify(root_hash, &wl_states, temp_proof, temp_proof_len);
      // For all RCRules using whitelists, as long as there is one RCRule which
      // satisfies err == 0, we consider validation to be success.
      if (err == 0) {
        // *** all hashes on white list
        on_white_list = true;
        // don't break when verify successfully: it's possible to be on
        // emergency halt afterward.
      }
      //  else *** not all hashes on white list
    } else {
      // black list
      err = smt_verify(root_hash, &bl_states, temp_proof, temp_proof_len);
      if (err != 0) {
        // *** any one of hashes on black list
        on_black_list = true;
      }
      //  else *** all hashes *not* on black list

      // don't break when verify failed: it's possible to be on white list
      // afterward.
    }
  }
  if (on_white_list) {
    err = 0;
  } else {
    if (on_black_list) {
      err = ERROR_ON_BLACK_LIST;
    } else {
      err = 0;
    }
  }
exit:
  return err;
}

#endif
