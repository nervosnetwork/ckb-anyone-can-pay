// # RCE Validator
//
// A type script used to ensure *RCE cell* is correctly formatted.
// For more details on RCE cell, please refer to this post:
// https://talk.nervos.org/t/rfc-regulation-compliance-extension/5338

// it's used by blockchain-api2.h, the behavior when panic
#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif
int ckb_exit(signed char);

#include <stdbool.h>
#include <string.h>

#include "blockchain-api2.h"
#include "ckb_syscalls.h"
#include "ckb_type_id.h"
#include "rce.h"

#define FLAG_APPEND_ONLY 0x1
#define FLAG_FREEZE_TYPE 0x2

#define CACHE_SIZE 256
#define MAX_UPDATES_PER_TX 1024
#define MAX_PROOF_LENGTH (33 * MAX_UPDATES_PER_TX)

static uint32_t read_from_cell_data(uintptr_t* arg, uint8_t* ptr, uint32_t len,
                                    uint32_t offset) {
  int err;
  uint64_t output_len = len;
  err = ckb_checked_load_cell_data(ptr, &output_len, offset, arg[0], arg[1]);
  if (err != 0) {
    DEBUG("Error reading cell data!");
    ckb_exit(ERROR_EOF);
  }
  return output_len;
}

static int _make_cursor(uint8_t* buffer, uint32_t cache_size, size_t index,
                        size_t source, mol2_cursor_t* cursor,
                        mol2_source_t read) {
  mol2_data_source_t* ptr = (mol2_data_source_t*)buffer;

  uint64_t len = cache_size;
  int err = ckb_load_cell_data(ptr->cache, &len, 0, index, source);
  CHECK(err);
  CHECK2(len > 0, ERROR_INVALID_MOL_FORMAT);

  ptr->read = read;
  ptr->total_size = len;
  // pass index and source as args
  ptr->args[0] = (uintptr_t)index;
  ptr->args[1] = (uintptr_t)source;

  ptr->cache_size = (len > cache_size) ? cache_size : len;
  ptr->start_point = 0;
  ptr->max_cache_size = cache_size;

  cursor->offset = 0;
  cursor->size = len;
  cursor->data_source = ptr;

  err = CKB_SUCCESS;
exit:
  return err;
}

static int make_data_cursor(uint8_t* buffer, uint32_t cache_size, size_t index,
                            size_t source, mol2_cursor_t* cursor) {
  return _make_cursor(buffer, cache_size, index, source, cursor,
                      read_from_cell_data);
}

static uint32_t read_from_witness(uintptr_t* arg, uint8_t* ptr, uint32_t len,
                                  uint32_t offset) {
  int err;
  uint64_t output_len = len;
  err = ckb_checked_load_witness(ptr, &output_len, offset, arg[0], arg[1]);
  if (err != 0) {
    DEBUG("Error reading witness!");
    ckb_exit(ERROR_EOF);
  }
  return output_len;
}

static int make_witness_cursor(uint8_t* buffer, uint32_t cache_size,
                               size_t index, size_t source,
                               mol2_cursor_t* cursor) {
  return _make_cursor(buffer, cache_size, index, source, cursor,
                      read_from_witness);
}

int main() {
  uint8_t type_id[32];
  int err = ckb_load_type_id_from_script_args(0, type_id);
  if (err != CKB_SUCCESS) {
    return err;
  }
  err = ckb_validate_type_id(type_id);
  if (err != CKB_SUCCESS) {
    return err;
  }

  uint8_t flags = 0;
  uint64_t len = 1;
  err = ckb_load_script(&flags, &len, 32);
  if (err != CKB_SUCCESS) {
    DEBUG("Cannot load current script!");
    return err;
  }
  if (len > 1) {
    DEBUG("Current script is too large!");
    return ERROR_ARGUMENTS_LEN;
  }
  bool append_only = (flags & FLAG_APPEND_ONLY) != 0;

  uint8_t input_hash[SMT_KEY_BYTES];
  memset(input_hash, 0, SMT_KEY_BYTES);
  bool has_input = false, input_is_rule = false;

  if (_ckb_has_type_id_cell(0, 1) == 1) {
    has_input = true;
    uint8_t input_data_buffer[MOL2_DATA_SOURCE_LEN(CACHE_SIZE)];
    mol2_cursor_t input_cell_data;
    err = make_data_cursor(input_data_buffer, CACHE_SIZE, 0,
                           CKB_SOURCE_GROUP_INPUT, &input_cell_data);
    CHECK(err);

    RCDataType rc_data = make_RCData(&input_cell_data);
    uint32_t item_id = rc_data.t->item_id(&rc_data);
    if (item_id == RCDataUnionRule) {
      RCRuleType rule = rc_data.t->as_RCRule(&rc_data);
      mol2_cursor_t smt_root = rule.t->smt_root(&rule);
      uint32_t read = mol2_read_at(&smt_root, input_hash, SMT_KEY_BYTES);
      CHECK2(read == SMT_KEY_BYTES, ERROR_INVALID_MOL_FORMAT);
      input_is_rule = true;
    } else if (item_id == RCDataUnionCellVec) {
      input_is_rule = false;
    } else {
      return ERROR_INVALID_MOL_FORMAT;
    }
  }

  uint8_t output_data_buffer[MOL2_DATA_SOURCE_LEN(CACHE_SIZE)];
  mol2_cursor_t output_cell_data;
  err = make_data_cursor(output_data_buffer, CACHE_SIZE, 0,
                         CKB_SOURCE_GROUP_OUTPUT, &output_cell_data);
  CHECK(err);

  RCDataType rc_data = make_RCData(&output_cell_data);
  uint32_t item_id = rc_data.t->item_id(&rc_data);
  if (item_id == RCDataUnionRule) {
    if (((flags & FLAG_FREEZE_TYPE) != 0) && (has_input) && (!input_is_rule)) {
      return ERROR_TYPE_FREEZED;
    }
    RCRuleType rule = rc_data.t->as_RCRule(&rc_data);
    mol2_cursor_t smt_root = rule.t->smt_root(&rule);
    uint8_t output_hash[SMT_KEY_BYTES];
    uint32_t read = mol2_read_at(&smt_root, output_hash, SMT_KEY_BYTES);
    CHECK2(read == SMT_KEY_BYTES, ERROR_INVALID_MOL_FORMAT);

    // SMT update validation
    uint8_t witness_buffer[MOL2_DATA_SOURCE_LEN(CACHE_SIZE)];
    mol2_cursor_t witness_data;
    err = make_witness_cursor(witness_buffer, CACHE_SIZE, 0,
                              CKB_SOURCE_GROUP_OUTPUT, &witness_data);
    CHECK(err);

    WitnessArgsType witness_args = make_WitnessArgs(&witness_data);
    BytesOptType output = witness_args.t->output_type(&witness_args);
    CHECK2(!output.t->is_none(&output), ERROR_INVALID_MOL_FORMAT);
    mol2_cursor_t bytes = output.t->unwrap(&output);
    // Bytes stored here are in fact SmtUpdate type
    SmtUpdateType smt_update = make_SmtUpdate(&bytes);
    SmtUpdateVecType smt_items = smt_update.t->update(&smt_update);

    smt_pair_t entries[MAX_UPDATES_PER_TX];
    smt_pair_t old_entries[MAX_UPDATES_PER_TX];
    smt_state_t states;
    smt_state_t old_states;
    smt_state_init(&states, entries, MAX_UPDATES_PER_TX);
    smt_state_init(&old_states, old_entries, MAX_UPDATES_PER_TX);

    for (uint32_t i = 0; i < smt_items.t->len(&smt_items); i++) {
      bool exists = false;
      SmtUpdateItemType item = smt_items.t->get(&smt_items, i, &exists);
      if (!exists) {
        return ERROR_INVALID_MOL_FORMAT;
      }

      mol2_cursor_t key_cursor = item.t->key(&item);
      uint8_t values = item.t->values(&item);

      uint8_t key[SMT_KEY_BYTES];
      uint8_t* old_value;
      uint8_t* value;

      /*
        High 4 bits of values : old_value
        Low 4 bits of values: new_value
        They can be either 0(SMT_VALUE_NOT_EXISTING) or 1(SMT_VALUE_EXISTING).
        Other values like 2, 3, .. 0xF are not allowed.
       */
      if ((values & 0xF0) == 0x10) {
        old_value = SMT_VALUE_EXISTING;
      } else {
        old_value = SMT_VALUE_NOT_EXISTING;
        CHECK2((values & 0xF0) == 0, ERROR_INVALID_MOL_FORMAT);
      }
      if ((values & 0x0F) == 0x01) {
        value = SMT_VALUE_EXISTING;
      } else {
        value = SMT_VALUE_NOT_EXISTING;
        CHECK2((values & 0x0F) == 0, ERROR_INVALID_MOL_FORMAT);
      }

      uint32_t read = mol2_read_at(&key_cursor, key, SMT_KEY_BYTES);
      CHECK2(read == SMT_KEY_BYTES, ERROR_INVALID_MOL_FORMAT);

      if (append_only) {
        if (memcmp(value, SMT_VALUE_EXISTING, SMT_VALUE_BYTES) != 0) {
          return ERROR_APPEND_ONLY;
        }
      }

      err = smt_state_insert(&states, key, value);
      CHECK(err);
      err = smt_state_insert(&old_states, key, old_value);
      CHECK(err);
    }

    mol2_cursor_t proof_cursor = smt_update.t->proof(&smt_update);
    if (proof_cursor.size > MAX_PROOF_LENGTH) {
      return ERROR_INVALID_MOL_FORMAT;
    }
    uint8_t proof[MAX_PROOF_LENGTH];
    uint32_t proof_length =
        mol2_read_at(&proof_cursor, proof, MAX_PROOF_LENGTH);
    CHECK2(proof_length == proof_cursor.size, ERROR_INVALID_MOL_FORMAT);

    // First validate old values & proof are correct
    err = smt_verify(input_hash, &old_states, proof, proof_length);
    CHECK2(err == 0, ERROR_SMT_VERIFY_FAILED);
    // Now validate new hash
    err = smt_verify(output_hash, &states, proof, proof_length);
    CHECK2(err == 0, ERROR_SMT_VERIFY_FAILED);
  } else if (item_id == RCDataUnionCellVec) {
    if (((flags & FLAG_FREEZE_TYPE) != 0) && (has_input) && (input_is_rule)) {
      return ERROR_TYPE_FREEZED;
    }
    // When changing from RCRule to RCCellVec, or from RCCellVec to RCCellVec,
    // no further action is needed.
  } else {
    return ERROR_INVALID_MOL_FORMAT;
  }

  err = CKB_SUCCESS;
exit:
  return err;
}
