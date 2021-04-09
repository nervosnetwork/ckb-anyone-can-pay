// note, this macro must be same as in ckb_syscall.h
#ifndef CKB_C_STDLIB_CKB_SYSCALLS_H_
#define CKB_C_STDLIB_CKB_SYSCALLS_H_
#include <stddef.h>
#include <stdint.h>
#undef ASSERT
#include <assert.h>
#define ASSERT assert

#include "xudt_rce_mol.h"

#define countof(s) (sizeof(s) / sizeof(s[0]))

// forward declarations
void ckbsim_map_lib(const uint8_t* dep_cell_hash, const char* path);
mol_seg_t build_bytes(const uint8_t* data, uint32_t len);
mol_seg_t build_script(const uint8_t* code_hash, uint8_t hash_type,
                       const uint8_t* args, uint32_t args_len);
extern int g_lib_size;
// simulator for RCData
typedef uint16_t RCHashType;

typedef struct SIMRCRule {
  uint8_t id;  // id = 0
  uint8_t flags;
  uint8_t smt_root[32];
} SIMRCRule;
#define MAX_RCRULE_IN_CELL 16
typedef struct SIMRCCellVec {
  uint8_t id;  // id = 1
  uint8_t hash_count;
  RCHashType hash[MAX_RCRULE_IN_CELL];
} SIMRCCellVec;

typedef union SIMRCData {
  SIMRCRule rcrule;
  SIMRCCellVec rccell_vec;
} SIMRCData;

#define MAX_RCDATA_COUNT (8192 * 2)

SIMRCData g_sim_rcdata[MAX_RCDATA_COUNT];
uint16_t g_sim_rcdata_count = 0;

uint32_t g_flags = 0;
void xudt_set_flags(uint32_t flags) { g_flags = flags; }

mol_builder_t g_extension_script_hash_builder = {0};
mol_seg_t g_extension_script_hash = {0};

mol_builder_t g_proof_builder = {0};

mol_builder_t g_structure_builder = {0};
mol_seg_t g_structure = {0};

uint8_t g_hash_in_args[32] = {0};

uint8_t g_input_lock_script_hash[32][16];
uint32_t g_input_lock_script_hash_count = 0;

uint8_t g_output_lock_script_hash[32][16];
uint32_t g_output_lock_script_hash_count = 0;

__int128 g_input_amount[32] = {0};
uint32_t g_input_count = 0;
__int128 g_output_amount[32] = {0};
uint32_t g_output_count = 0;

void xudt_add_extension_script(const uint8_t* hash, uint8_t hash_type,
                               uint8_t* args, uint32_t args_len,
                               const char* path) {
  mol_seg_t script = build_script(hash, hash_type, args, args_len);

  MolBuilder_ScriptVec_push(&g_extension_script_hash_builder, script.ptr,
                            script.size);
  ckbsim_map_lib(hash, path);

  free(script.ptr);
}

void xudt_calc_extension_script_hash(const uint8_t* hash, uint8_t hash_type,
                                     uint8_t* args, uint32_t args_len,
                                     uint8_t* out_hash) {
  mol_seg_t script = build_script(hash, hash_type, args, args_len);
  int err = blake2b(out_hash, 32, script.ptr, script.size, NULL, 0);
  ASSERT(err == 0);

  free(script.ptr);
}

void xudt_add_structure_item(const uint8_t* item, uint32_t len) {
  mol_seg_t seg = build_bytes(item, len);
  MolBuilder_BytesVec_push(&g_structure_builder, seg.ptr, seg.size);
  free(seg.ptr);
}

void rce_begin_proof() { MolBuilder_SmtProofVec_init(&g_proof_builder); }

void rce_add_proof(const uint8_t* proof, uint32_t proof_len) {
  mol_seg_t seg = build_bytes(proof, proof_len);
  MolBuilder_SmtProofVec_push(&g_proof_builder, seg.ptr, seg.size);
  free(seg.ptr);
}

void rce_end_proof() {
  mol_seg_res_t res = MolBuilder_SmtProofVec_build(g_proof_builder);
  ASSERT(res.errno == 0);

  xudt_add_structure_item(res.seg.ptr, res.seg.size);
  free(res.seg.ptr);
}

void xudt_add_data(const uint8_t* data, uint32_t len) {
  // not used
}

void xudt_add_input_lock_script_hash(uint8_t* hash) {
  if (g_input_lock_script_hash_count >= 16) {
    ASSERT(false);
    return;
  }
  memcpy(g_input_lock_script_hash[g_input_lock_script_hash_count], hash, 32);
  g_input_lock_script_hash_count++;
}

// set them to same to enable owner mode
void xudt_set_owner_mode(uint8_t* hash_in_args, uint8_t* lock_script_hash) {
  memcpy(g_hash_in_args, hash_in_args, 32);
  xudt_add_input_lock_script_hash(lock_script_hash);
}

void xudt_add_output_lock_script_hash(uint8_t* hash) {
  if (g_output_lock_script_hash_count > 16) {
    return;
  }
  memcpy(g_output_lock_script_hash[g_output_lock_script_hash_count], hash, 32);
  g_output_lock_script_hash_count++;
}

void xudt_add_input_amount(__int128 val) {
  g_input_amount[g_input_count] = val;
  g_input_count++;
}

void xudt_add_output_amount(__int128 val) {
  g_output_amount[g_output_count] = val;
  g_output_count++;
}

void xudt_begin_data(void) {
  g_flags = 0;
  MolBuilder_ScriptVec_init(&g_extension_script_hash_builder);
  if (g_extension_script_hash.ptr) free(g_extension_script_hash.ptr);

  MolBuilder_BytesVec_init(&g_structure_builder);
  if (g_structure.ptr) free(g_structure.ptr);

  g_extension_script_hash.ptr = 0;
  g_extension_script_hash.size = 0;
  g_input_count = 0;
  g_output_count = 0;
  memset(g_input_lock_script_hash, 0, sizeof(g_input_lock_script_hash));
  memset(g_output_lock_script_hash, 0, sizeof(g_output_lock_script_hash));
  memset(g_hash_in_args, 0, sizeof(g_hash_in_args));

  g_lib_size = 0;
  g_input_lock_script_hash_count = 0;
  g_output_lock_script_hash_count = 0;

  g_sim_rcdata_count = 0;
}

void xudt_end_data(void) {
  mol_seg_res_t res =
      MolBuilder_ScriptVec_build(g_extension_script_hash_builder);
  ASSERT(res.errno == 0);
  g_extension_script_hash = res.seg;

  mol_seg_res_t res2 = MolBuilder_BytesVec_build(g_structure_builder);
  g_structure = res2.seg;
}

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
    return 1;  // CKB_INDEX_OUT_OF_BOUND;
  }
  mol_builder_t w;
  MolBuilder_WitnessArgs_init(&w);

  mol_builder_t xwi_builder;
  MolBuilder_XudtWitnessInput_init(&xwi_builder);
  if (g_flags == 2) {
    MolBuilder_XudtWitnessInput_set_raw_extension_data(
        &xwi_builder, g_extension_script_hash.ptr,
        g_extension_script_hash.size);
  }
  MolBuilder_XudtWitnessInput_set_extension_data(&xwi_builder, g_structure.ptr,
                                                 g_structure.size);

  mol_seg_res_t xwi_res = MolBuilder_XudtWitnessInput_build(xwi_builder);
  ASSERT(xwi_res.errno == MOL_OK);

  mol_seg_t seg = build_bytes(xwi_res.seg.ptr, xwi_res.seg.size);
  MolBuilder_WitnessArgs_set_input_type(&w, seg.ptr, seg.size);
  free(seg.ptr);

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
    // keep "len" unchanged
  } else {
    memcpy(addr, res.seg.ptr + offset, remaining);
    *len = remaining;
  }

  free(res.seg.ptr);
  free(xwi_res.seg.ptr);

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

mol_seg_t build_rcdata(SIMRCData* rcdata) {
  mol_builder_t b2;
  mol_union_builder_initialize(&b2, 64, 0, MolDefault_RCRule, 33);
  if (rcdata->rcrule.id == 0) {
    // RCRule
    mol_builder_t b;
    MolBuilder_RCRule_init(&b);
    MolBuilder_RCRule_set_flags(&b, rcdata->rcrule.flags);
    MolBuilder_RCRule_set_smt_root(&b, rcdata->rcrule.smt_root);
    mol_seg_res_t res = MolBuilder_RCRule_build(b);
    ASSERT(res.errno == 0);

    MolBuilder_RCData_set_RCRule(&b2, res.seg.ptr, res.seg.size);
    free(res.seg.ptr);
  } else if (rcdata->rcrule.id == 1) {
    // RCCellVec
    mol_builder_t b;
    MolBuilder_RCCellVec_init(&b);
    for (uint8_t i = 0; i < rcdata->rccell_vec.hash_count; i++) {
      uint8_t hash[32] = {0};
      // very small 2-byte hash
      *((RCHashType*)hash) = rcdata->rccell_vec.hash[i];
      MolBuilder_RCCellVec_push(&b, hash);
    }
    mol_seg_res_t res = MolBuilder_RCCellVec_build(b);
    ASSERT(res.errno == 0);

    MolBuilder_RCData_set_RCCellVec(&b2, res.seg.ptr, res.seg.size);
    free(res.seg.ptr);
  } else {
    ASSERT(false);
  }
  mol_seg_res_t res2 = MolBuilder_RCData_build(b2);
  ASSERT(res2.errno == 0);
  return res2.seg;
}

int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset) {
  mol_builder_t b = {0};
  mol_seg_res_t res = {0};
  assert(offset == 0);

  MolBuilder_Script_init(&b);
  uint8_t hash_type = 0;
  MolBuilder_Script_set_code_hash(&b, g_hash_in_args, 32);
  MolBuilder_Script_set_hash_type(&b, hash_type);
  {
    uint32_t args_len = 32 + 4 + g_extension_script_hash.size;
    uint8_t args[args_len];

    memcpy(args, g_hash_in_args, 32);
    memcpy(args + 32, &g_flags, 4);

    mol_seg_t seg = {0};
    if (g_flags == 1) {
      memcpy(args + 32 + 4, g_extension_script_hash.ptr,
             g_extension_script_hash.size);
      seg = build_bytes(args, args_len);
    } else if (g_flags == 2) {
      uint8_t hash[32] = {0};
      int err = blake2b(hash, 32, g_extension_script_hash.ptr,
                        g_extension_script_hash.size, NULL, 0);
      ASSERT(err == 0);
      memcpy(args + 32 + 4, hash, 20);
      // blake160 hash
      seg = build_bytes(args, 32 + 4 + 20);
    } else if (g_flags == 0) {
      seg = build_bytes(args, 32);
    } else if (g_flags == 0xFF) {
      // test flags, make flags available, but value is zero
      uint32_t flags = 0;
      memcpy(args + 32, &flags, 4);
      seg = build_bytes(args, 32 + 4);
    } else {
      ASSERT(false);
    }
    MolBuilder_Script_set_args(&b, seg.ptr, seg.size);
    free(seg.ptr);
  }
  res = MolBuilder_Script_build(b);
  assert(res.errno == 0);

  if (*len < res.seg.size) {
    return -1;
  }
  memcpy(addr, res.seg.ptr, res.seg.size);
  *len = res.seg.size;

  free(res.seg.ptr);
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
  if (source == CKB_SOURCE_GROUP_INPUT) {
    ASSERT(offset == 0);
    if (index >= g_input_count) {
      return CKB_INDEX_OUT_OF_BOUND;
    } else {
      if (addr) {
        memcpy(addr, &g_input_amount[index], sizeof(__int128));
      }
      *len = sizeof(__int128);
    }
  } else if (source == CKB_SOURCE_GROUP_OUTPUT) {
    ASSERT(offset == 0);
    if (index >= g_output_count) {
      return CKB_INDEX_OUT_OF_BOUND;
    } else {
      if (addr) {
        memcpy(addr, &g_output_amount[index], sizeof(__int128));
      }
      *len = sizeof(__int128);
    }
  } else if (source == CKB_SOURCE_CELL_DEP) {
    ASSERT(index < g_sim_rcdata_count);
    SIMRCData* curr = g_sim_rcdata + index;
    mol_seg_t seg = build_rcdata(curr);

    if (addr == NULL) {
      ASSERT(*len == 0);
      *len = seg.size;
      return 0;
    }
    if (seg.size <= offset) {
      *len = 0;
      return 0;
    }
    uint32_t remaining = seg.size - offset;
    if (remaining > *len) {
      memcpy(addr, seg.ptr + offset, *len);
      // keep "len" unchanged
    } else {
      memcpy(addr, seg.ptr + offset, remaining);
      *len = remaining;
    }

    free(seg.ptr);
  } else {
    ASSERT(false);
  }
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
      ASSERT(offset == 0);
      ASSERT(*len >= 32);
      if (index >= g_output_lock_script_hash_count) {
        return CKB_INDEX_OUT_OF_BOUND;
      }
      memcpy(addr, g_output_lock_script_hash[index], 32);
      *len = 32;
    } else if (source == CKB_SOURCE_GROUP_INPUT || source == CKB_SOURCE_INPUT) {
      ASSERT(offset == 0);
      ASSERT(*len >= 32);
      if (index >= g_input_lock_script_hash_count) {
        return CKB_INDEX_OUT_OF_BOUND;
      }
      memcpy(addr, g_input_lock_script_hash[index], 32);
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

// return index as hash
uint16_t rce_add_rcrule(uint8_t* rcrule, uint8_t flags) {
  ASSERT(g_sim_rcdata_count < countof(g_sim_rcdata));

  SIMRCData* curr = g_sim_rcdata + g_sim_rcdata_count;
  curr->rcrule.id = 0;
  curr->rcrule.flags = flags;
  memcpy(curr->rcrule.smt_root, rcrule, 32);
  g_sim_rcdata_count++;
  return g_sim_rcdata_count - 1;
}

// return index as hash
RCHashType rce_modify_rcrule(uint32_t index, uint8_t* rcrule, uint8_t flags) {
  ASSERT(index < g_sim_rcdata_count);

  SIMRCData* curr = g_sim_rcdata + index;
  curr->rcrule.flags = flags;
  memcpy(curr->rcrule.smt_root, rcrule, 32);
  return index;
}

RCHashType rce_add_rccellvec(RCHashType* hash, uint32_t length) {
  ASSERT(g_sim_rcdata_count < countof(g_sim_rcdata));
  SIMRCData* curr = g_sim_rcdata + g_sim_rcdata_count;
  curr->rccell_vec.id = 1;
  curr->rccell_vec.hash_count = length;
  memcpy(curr->rccell_vec.hash, hash, length * sizeof(RCHashType));
  g_sim_rcdata_count++;
  return g_sim_rcdata_count - 1;
}

int ckb_look_for_dep_with_hash2(const uint8_t* code_hash, uint8_t hash_type,
                                size_t* index) {
  *index = *(uint16_t*)code_hash;
  return 0;
}

// dlopen simulator
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>

#define ERROR_MEMORY_NOT_ENOUGH -23
#define ERROR_DYNAMIC_LOADING -24
#define RISCV_PGSIZE 4096
#define ROUNDUP(a, b) ((((a)-1) / (b) + 1) * (b))
#define MAX_PATH_SIZE 1024

typedef struct LibMappingEntry {
  uint8_t dep_cell_hash[32];
  char path[MAX_PATH_SIZE];
} LibMappingEntry;

#define MAX_LIB_MAPPING_COUNT 64
LibMappingEntry g_lib_mapping[MAX_LIB_MAPPING_COUNT];
int g_lib_size = 0;

void ckbsim_map_lib(const uint8_t* dep_cell_hash, const char* path) {
  if (g_lib_size >= MAX_LIB_MAPPING_COUNT) {
    ASSERT(false);
    return;
  }
  ASSERT(strlen(path) < MAX_PATH_SIZE);

  memcpy(g_lib_mapping[g_lib_size].dep_cell_hash, dep_cell_hash, 32);
  strcpy(g_lib_mapping[g_lib_size].path, path);

  g_lib_size++;
}

bool file_exists(const char* path) {
  FILE* fp = fopen(path, "r");
  if (fp != NULL) {
    fclose(fp);
  };
  return fp != NULL;
}

void file_with_so(const char* input, char* output, uint32_t output_len) {
  strcpy(output, input);
  char* pos = strchr(output, '.');
  if (pos != NULL) {
    *pos = 0;
    strcat(output, ".so");
  }
}

int ckbsim_get_lib(const uint8_t* dep_cell_hash, char* path) {
  for (int i = 0; i < g_lib_size; i++) {
    if (memcmp(g_lib_mapping[i].dep_cell_hash, dep_cell_hash, 32) == 0) {
      const char* target = g_lib_mapping[i].path;
      if (file_exists(target)) {
        strcpy(path, target);
      } else {
        char output[1024] = {0};
        file_with_so(target, output, sizeof(output));
        if (file_exists(output)) {
          strcpy(path, output);
        } else {
          ASSERT(false);
          return -1;
        }
      }
      return 0;
    }
  }
  return 1;
}

size_t get_file_size(const char* path) {
  FILE* fp = fopen(path, "r");
  ASSERT(fp != NULL);
  fseek(fp, 0L, SEEK_END);
  long size = ftell(fp);
  fclose(fp);

  return size;
}

int ckb_dlopen2(const uint8_t* dep_cell_hash, uint8_t hash_type,
                uint8_t* aligned_addr, size_t aligned_size, void** handle,
                size_t* consumed_size) {
  int err = 0;
  (void)hash_type;
  (void)aligned_size;

  char path[MAX_PATH_SIZE] = {0};
  ASSERT((aligned_size % RISCV_PGSIZE) == 0);
  ASSERT(((size_t)aligned_addr) % RISCV_PGSIZE == 0);

  err = ckbsim_get_lib(dep_cell_hash, path);
  ASSERT(err == 0);

  *handle = dlopen(path, RTLD_NOW);
  *consumed_size = ROUNDUP(get_file_size(path), RISCV_PGSIZE);

  if (*consumed_size >= aligned_size) {
    ASSERT(false);
    return -1;
  }
  if (*handle == NULL) {
    printf("Error occurs in dlopen: %s\n", dlerror());
    ASSERT(false);
    return -1;
  }
  return 0;
}

void* ckb_dlsym(void* handle, const char* symbol) {
  void* ret = dlsym(handle, symbol);
  ASSERT(ret != NULL);
  return ret;
}

#undef ASSERT
#define ASSERT(s) (void)0

#endif
