// note, this macro must be same as in ckb_syscall.h
#ifndef CKB_C_STDLIB_CKB_SYSCALLS_H_
#define CKB_C_STDLIB_CKB_SYSCALLS_H_
#include <stddef.h>
#include <stdint.h>
#undef ASSERT
#include <assert.h>
#define ASSERT assert
#define countof(s) (sizeof(s) / sizeof(s[0]))

// set by users
typedef struct RcLockInputType {
  uint8_t flags;            // in args in lock script
  uint8_t pubkey_hash[20];  // in args in lock script
  uint8_t rc_rule[32];      // in args in lock script
  uint8_t signature[65];    // in witness

  uint8_t lock_script_hash_on_wl[32];
  uint8_t proof[16][8196];  // max proof
  uint32_t proof_len[16];

  uint8_t lock_script_hash[64][32];
  uint8_t lock_script_hash_count;
} RcLockInputType;

RcLockInputType g_input;
// states are generated by input
typedef struct RcLockStates {
  RcLockInputType input;

  uint8_t args[256];
  uint32_t args_len;

  uint8_t witness_lock[32768];
  uint32_t witness_lock_len;
} RcLockStates;

RcLockStates g_states;

void convert_input_to_states(void) {
  g_states.args[0] = g_input.flags;
  if (g_input.flags == 1) {
    memcpy(g_states.args + 1, g_input.pubkey_hash, 20);
    memcpy(g_states.args + 1 + 20, g_input.rc_rule, 32);
    g_states.args_len = 1 + 20 + 32;
  } else {
    ASSERT(false);
  }
  memcpy(g_states.witness_lock, g_input.signature, 65);
  //  memcpy(g_states.witness_lock + 65, g_input.proof, g_input.proof_len);
  //  g_states.witness_lock_len = 65 + g_input.proof_len;
}

mol_seg_t build_bytes(const uint8_t* data, uint32_t len);
mol_seg_t build_script(const uint8_t* code_hash, uint8_t hash_type,
                       const uint8_t* args, uint32_t args_len);

int ckb_exit(int8_t code) {
  exit(code);
  return 0;
}

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) { return 0; }

int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset);

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index,
                  size_t source);

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index,
                   size_t source);

int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index,
                    size_t source);

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset) { return 0; }

int ckb_checked_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  uint64_t old_len = *len;
  int ret = ckb_load_script_hash(addr, len, offset);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source) {
  if (index > 1) {
    return CKB_INDEX_OUT_OF_BOUND;
  }
  mol_builder_t w;
  MolBuilder_WitnessArgs_init(&w);

  mol_seg_t lock = build_bytes(g_states.args, g_states.args_len);
  MolBuilder_WitnessArgs_set_lock(&w, lock.ptr, lock.size);
  free(lock.ptr);

  mol_seg_res_t res = MolBuilder_WitnessArgs_build(w);
  assert(res.errno == 0);

  if (res.seg.size <= offset) {
    *len = 0;
    return 0;
  }
  if (addr == NULL) {
    *len = res.seg.size;
    return 0;
  }

  uint32_t remaining = res.seg.size - offset;
  if (remaining > *len) {
    memcpy(addr, res.seg.ptr + offset, *len);
  } else {
    memcpy(addr, res.seg.ptr + offset, remaining);
  }
  *len = remaining;

  free(res.seg.ptr);

  return 0;
}

int ckb_checked_load_witness(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source) {
  uint64_t old_len = *len;
  int ret = ckb_load_witness(addr, len, offset, index, source);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

mol_seg_t build_bytes(const uint8_t* data, uint32_t len) {
  mol_builder_t b;
  mol_seg_res_t res;
  MolBuilder_Bytes_init(&b);
  for (uint32_t i = 0; i < len; i++) {
    MolBuilder_Bytes_push(&b, data[i]);
  }
  res = MolBuilder_Bytes_build(b);
  return res.seg;
}

mol_seg_t build_script(const uint8_t* code_hash, uint8_t hash_type,
                       const uint8_t* args, uint32_t args_len) {
  mol_builder_t b;
  mol_seg_res_t res;
  MolBuilder_Script_init(&b);

  MolBuilder_Script_set_code_hash(&b, code_hash, 32);
  MolBuilder_Script_set_hash_type(&b, hash_type);
  mol_seg_t bytes = build_bytes(args, args_len);
  MolBuilder_Script_set_args(&b, bytes.ptr, bytes.size);

  res = MolBuilder_Script_build(b);
  assert(res.errno == 0);
  assert(MolReader_Script_verify(&res.seg, false) == 0);
  free(bytes.ptr);
  return res.seg;
}

int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset) {
  assert(offset == 0);

  uint8_t dummy_code_hash[32];
  mol_seg_t seg =
      build_script(dummy_code_hash, 0, g_states.args, g_states.args_len);

  if (*len < seg.size) {
    return -1;
  }
  memcpy(addr, seg.ptr, seg.size);
  *len = seg.size;

  free(seg.ptr);
  return 0;
}

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field);

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field);

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field);

int ckb_load_cell_code(void* addr, size_t memory_size, size_t content_offset,
                       size_t content_size, size_t index, size_t source);

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
  ASSERT(false);
  return 0;
}

int ckb_checked_load_cell_data(void* addr, uint64_t* len, size_t offset,
                               size_t index, size_t source) {
  return ckb_load_cell_data(addr, len, offset, index, source);
}

int ckb_debug(const char* s);

/* load the actual witness for the current type verify group.
   use this instead of ckb_load_witness if type contract needs args to verify
   input/output.
 */
int load_actual_type_witness(uint8_t* buf, uint64_t* len, size_t index,
                             size_t* type_source);

int ckb_look_for_dep_with_hash(const uint8_t* data_hash, size_t* index);

int ckb_calculate_inputs_len() { return 0; }

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field) {
  if (field == CKB_CELL_FIELD_LOCK_HASH) {
    if (source == CKB_SOURCE_GROUP_OUTPUT || source == CKB_SOURCE_OUTPUT) {
      ASSERT(false);
    } else if (source == CKB_SOURCE_GROUP_INPUT || source == CKB_SOURCE_INPUT) {
      ASSERT(offset == 0);
      ASSERT(*len >= 32);

      if (index >= g_states.input.lock_script_hash_count) {
        return CKB_INDEX_OUT_OF_BOUND;
      }
      memcpy(addr, g_states.input.lock_script_hash[index], 32);
      *len = 32;
    } else {
      ASSERT(false);
    }
  }
  return 0;
}

int ckb_checked_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                                   size_t index, size_t source, size_t field) {
  uint64_t old_len = *len;
  int ret = ckb_load_cell_by_field(addr, len, offset, index, source, field);
  if (ret == 0 && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_look_for_dep_with_hash2(const uint8_t* code_hash, uint8_t hash_type,
                                size_t* index) {
  *index = *(uint16_t*)code_hash;
  return 0;
}

#undef ASSERT
#define ASSERT(s) (void)0

#endif
