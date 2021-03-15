#ifndef ASSERT
#define ASSERT(s) (void)0
#endif

#include <stdbool.h>
#include <string.h>

#include "blake2b.h"
#include "blockchain-api2.h"
#include "ckb_consts.h"
#include "xudt_rce_mol.h"
#include "xudt_rce_mol2.h"

#if defined(CKB_USE_SIM)
#include <stdio.h>

#include "ckb_syscall_xudt_sim.h"
#define xudt_printf printf
#else
// it will be re-defined in ckb_dlfcn.h
#undef MAX
#undef MIN
#include "ckb_dlfcn.h"
#include "ckb_syscalls.h"
#define xudt_printf(x, ...) (void)0
#endif

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
  ERROR_INVALID_ARGS,
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
  ERROR_RCE_EMERGENCY_HATL,
  ERROR_NOT_VALIDATED,
};

#define CHECK2(cond, code) \
  do {                     \
    if (!(cond)) {         \
      err = code;          \
      ASSERT(0);           \
      goto exit;           \
    }                      \
  } while (0)

#define CHECK(code)  \
  do {               \
    if (code != 0) { \
      err = code;    \
      ASSERT(0);     \
      goto exit;     \
    }                \
  } while (0)

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define SCRIPT_SIZE 32768
#define WITNESS_SIZE 32768
#define EXPORTED_FUNC_NAME "validate"
#define MAX_CODE_SIZE (1024 * 1024)
#define FLAGS_SIZE 4
#define MAX_LOCK_SCRIPT_HASH_COUNT 2048

#include "rce.h"

// global variables, type definitions, etc

// We will leverage gcc's 128-bit integer extension here for number crunching.
typedef unsigned __int128 uint128_t;

uint8_t g_script[SCRIPT_SIZE] = {0};
uint8_t g_witness[WITNESS_SIZE] = {0};
uint32_t g_witness_len = 0;
bool g_witness_inited = false;

uint8_t g_code_buffer[MAX_CODE_SIZE] __attribute__((aligned(RISCV_PGSIZE)));
uint32_t g_code_used = 0;

/*
is_owner_mode indicates if current xUDT is unlocked via owner mode(as
described by sUDT), extension_index refers to the index of current extension in
the ScriptVec structure. args and args_length are set to the script args
included in Script structure of current extension script.

If this function returns 0, the validation for current extension script is
consider successful.
 */
typedef int (*ValidateFuncType)(int is_owner_mode, size_t extension_index,
                                const uint8_t* args, size_t args_len);

typedef enum XUDTFlags {
  XUDTFlags_Plain = 0,
  XUDTFlags_InArgs = 1,
  XUDTFlags_InWitness = 2,
} XUDTFlags;

typedef enum XUDTValidateFuncCategory {
  XVFC_Normal = 0,  // normal extension script
  XVFC_RCE = 1,     // Regulation Compliance Extension
} XUDTValidateFuncCategory;

uint8_t RCE_HASH[32] = {1};

// functions
int load_validate_func(const uint8_t* hash, uint8_t hash_type,
                       ValidateFuncType* func, XUDTValidateFuncCategory* cat) {
  int err = 0;
  void* handle = NULL;
  size_t consumed_size = 0;

  if (memcmp(RCE_HASH, hash, 32) == 0 && hash_type == 1) {
    *cat = XVFC_RCE;
    *func = rce_validate;
    return 0;
  }

  CHECK2(MAX_CODE_SIZE > g_code_used, ERROR_NOT_ENOUGH_BUFF);
  err = ckb_dlopen2(hash, hash_type, &g_code_buffer[g_code_used],
                    MAX_CODE_SIZE - g_code_used, &handle, &consumed_size);
  CHECK(err);
  CHECK2(handle != NULL, ERROR_CANT_LOAD_LIB);
  ASSERT(consumed_size % RISCV_PGSIZE == 0);
  g_code_used += consumed_size;

  *func = (ValidateFuncType)ckb_dlsym(handle, EXPORTED_FUNC_NAME);
  CHECK2(*func != NULL, ERROR_CANT_LOAD_LIB);

  *cat = XVFC_Normal;
  err = 0;
exit:
  return err;
}

int verify_script_vec(uint8_t* ptr, uint32_t size, uint32_t* real_size) {
  int err = 0;

  CHECK2(size >= MOL_NUM_T_SIZE, ERROR_INVALID_MOL_FORMAT);
  mol_num_t full_size = mol_unpack_number(ptr);
  *real_size = full_size;
  CHECK2(*real_size <= size, ERROR_INVALID_MOL_FORMAT);
  err = 0;
exit:
  return err;
}

int get_extension_data(uint32_t index, mol_seg_t* item) {
  int err = 0;
  if (!g_witness_inited) {
    uint64_t witness_len = WITNESS_SIZE;
    err = ckb_checked_load_witness(g_witness, &witness_len, 0, 0,
                                   CKB_SOURCE_GROUP_INPUT);
    CHECK(err);
    g_witness_len = witness_len;
    g_witness_inited = true;
  }

  mol_seg_t seg = {.ptr = g_witness, .size = g_witness_len};

  mol_seg_t output = MolReader_WitnessArgs_get_input_type(&seg);
  CHECK2(MolReader_Bytes_verify(&output, false) == MOL_OK,
         ERROR_INVALID_MOL_FORMAT);

  mol_seg_t raw = MolReader_Bytes_raw_bytes(&output);
  mol_seg_t structures = MolReader_XudtWitnessInput_get_structure(&raw);
  CHECK2(MolReader_BytesVec_verify(&structures, false) == MOL_OK,
         ERROR_INVALID_MOL_FORMAT);

  mol_seg_res_t structure = MolReader_BytesVec_get(&structures, index);
  CHECK(structure.errno);
  CHECK2(MolReader_Bytes_verify(&structure.seg, false) == MOL_OK,
         ERROR_INVALID_MOL_FORMAT);

  *item = structure.seg;

  err = 0;
exit:
  return err;
}

static uint32_t read_from_witness(uintptr_t arg[], uint8_t* ptr, uint32_t len,
                                  uint32_t offset) {
  int err;
  uint64_t output_len = len;
  err = ckb_checked_load_witness(ptr, &output_len, offset, arg[0], arg[1]);
  if (err != 0) {
    return 0;
  }
  return output_len;
}

int make_cursor_from_witness(mol2_cursor_t* result) {
  int err = 0;
  uint64_t witness_len = 0;
  err = ckb_checked_load_witness(NULL, &witness_len, 0, 0,
                                 CKB_SOURCE_GROUP_INPUT);
  CHECK(err);

  result->offset = 0;
  result->size = witness_len;

  static mol2_data_source_t s_data_source = {0};

  s_data_source.read = read_from_witness;
  s_data_source.total_size = witness_len;
  s_data_source.args[0] = 0;
  s_data_source.args[1] = CKB_SOURCE_GROUP_INPUT;

  s_data_source.cache_size = 0;
  s_data_source.start_point = 0;
  s_data_source.max_cache_size = MAX_CACHE_SIZE;
  result->data_source = &s_data_source;

  err = 0;
exit:
  return err;
}

// the *var_len may be bigger than real length of raw extension data
int load_raw_extension_data(uint8_t** var_data, uint32_t* var_len) {
  int err = 0;
  // Load witness of first input
  uint64_t witness_len = WITNESS_SIZE;
  err = ckb_checked_load_witness(g_witness, &witness_len, 0, 0,
                                 CKB_SOURCE_GROUP_INPUT);
  CHECK(err);
  mol_seg_t seg = {.ptr = g_witness, .size = witness_len};
  g_witness_len = witness_len;
  g_witness_inited = true;

  err = MolReader_WitnessArgs_verify(&seg, true);
  CHECK2(err == MOL_OK, ERROR_INVALID_MOL_FORMAT);
  mol_seg_t input_seg = MolReader_WitnessArgs_get_input_type(&seg);
  CHECK2(input_seg.size > 0, ERROR_INVALID_MOL_FORMAT);

  mol_seg_t input_content_seg = MolReader_Bytes_raw_bytes(&input_seg);
  CHECK2(input_content_seg.size > 0, ERROR_INVALID_MOL_FORMAT);

  CHECK2(MolReader_XudtWitnessInput_verify(&input_content_seg, false) == MOL_OK,
         ERROR_INVALID_MOL_FORMAT);
  mol_seg_t data =
      MolReader_XudtWitnessInput_get_raw_extension_data(&input_content_seg);
  *var_data = data.ptr;
  *var_len = data.size;

  err = 0;
exit:
  return err;
}

// *var_data will point to "Raw Extension Data", which can be in args or witness
// *var_data will refer to a memory location of g_script or g_witness
int parse_args(int* owner_mode, XUDTFlags* flags, uint8_t** var_data,
               uint32_t* var_len, uint8_t* input_lock_script_hashes,
               uint32_t* input_lock_script_hashes_count) {
  int err = 0;

  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_checked_load_script(g_script, &len, 0);
  CHECK(ret);
  CHECK2(len <= SCRIPT_SIZE, ERROR_SCRIPT_TOO_LONG);

  mol_seg_t script_seg;
  script_seg.ptr = g_script;
  script_seg.size = len;

  mol_errno mol_err = MolReader_Script_verify(&script_seg, false);
  CHECK2(mol_err == MOL_OK, ERROR_ENCODING);

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  CHECK2(args_bytes_seg.size >= BLAKE2B_BLOCK_SIZE, ERROR_ARGUMENTS_LEN);

  *input_lock_script_hashes_count = 0;
  // With owner lock script extracted, we will look through each input in the
  // current transaction to see if any unlocked cell uses owner lock.
  *owner_mode = 0;
  size_t i = 0;
  while (1) {
    uint8_t buffer[BLAKE2B_BLOCK_SIZE];
    uint64_t len2 = BLAKE2B_BLOCK_SIZE;
    // There are 2 points worth mentioning here:
    //
    // * First, we are using the checked version of CKB syscalls, the checked
    // versions will return an error if our provided buffer is not enough to
    // hold all returned data. This can help us ensure that we are processing
    // enough data here.
    // * Second, `CKB_CELL_FIELD_LOCK_HASH` is used here to directly load the
    // lock script hash, so we don't have to manually calculate the hash again
    // here.
    ret = ckb_checked_load_cell_by_field(buffer, &len2, 0, i, CKB_SOURCE_INPUT,
                                         CKB_CELL_FIELD_LOCK_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    CHECK(ret);
    if (i < MAX_LOCK_SCRIPT_HASH_COUNT) {
      memcpy(&input_lock_script_hashes[i * BLAKE2B_BLOCK_SIZE], buffer,
             BLAKE2B_BLOCK_SIZE);
      *input_lock_script_hashes_count += 1;
    }

    if (args_bytes_seg.size == BLAKE2B_BLOCK_SIZE &&
        memcmp(buffer, args_bytes_seg.ptr, BLAKE2B_BLOCK_SIZE) == 0) {
      *owner_mode = 1;
      break;
    }
    i += 1;
  }

  // parse xUDT args
  if (args_bytes_seg.size < (FLAGS_SIZE + BLAKE2B_BLOCK_SIZE)) {
    *var_data = NULL;
    *var_len = 0;
    *flags = XUDTFlags_Plain;
  } else {
    uint32_t* flag_ptr = (uint32_t*)(args_bytes_seg.ptr + BLAKE2B_BLOCK_SIZE);
    if (*flag_ptr == XUDTFlags_Plain) {
      *flags = XUDTFlags_Plain;
    } else if (*flag_ptr == XUDTFlags_InArgs) {
      uint32_t real_size = 0;
      *flags = XUDTFlags_InArgs;
      *var_len = args_bytes_seg.size - BLAKE2B_BLOCK_SIZE - FLAGS_SIZE;
      *var_data = args_bytes_seg.ptr + BLAKE2B_BLOCK_SIZE + FLAGS_SIZE;

      err = verify_script_vec(*var_data, *var_len, &real_size);
      CHECK(err);
      // note, it's different than "flag = 2"
      CHECK2(real_size == *var_len, ERROR_INVALID_ARGS_FORMAT);
    } else if (*flag_ptr == XUDTFlags_InWitness) {
      *flags = XUDTFlags_InWitness;
      uint32_t hash_size =
          args_bytes_seg.size - BLAKE2B_BLOCK_SIZE - FLAGS_SIZE;
      CHECK2(hash_size == BLAKE160_SIZE, ERROR_INVALID_FLAG);

      err = load_raw_extension_data(var_data, var_len);
      CHECK(err);
      CHECK2(var_len > 0, ERROR_INVALID_MOL_FORMAT);
      // verify the hash
      uint8_t hash[BLAKE2B_BLOCK_SIZE] = {0};
      uint8_t* blake160_hash =
          args_bytes_seg.ptr + BLAKE2B_BLOCK_SIZE + FLAGS_SIZE;
      err = blake2b(hash, BLAKE2B_BLOCK_SIZE, *var_data, *var_len, NULL, 0);
      CHECK2(err == 0, ERROR_BLAKE2B_ERROR);
      CHECK2(memcmp(blake160_hash, hash, BLAKE160_SIZE) == 0,
             ERROR_HASH_MISMATCHED);
    } else {
      CHECK2(false, ERROR_INVALID_FLAG);
    }
  }
  err = 0;
exit:
  return err;
}

// copied from simple_udt.c
int simple_udt(int owner_mode) {
  if (owner_mode) return CKB_SUCCESS;

  int ret = 0;
  // When the owner mode is not enabled, however, we will then need to ensure
  // the sum of all input tokens is not smaller than the sum of all output
  // tokens. First, let's loop through all input cells containing current UDTs,
  // and gather the sum of all input tokens.
  uint128_t input_amount = 0;
  size_t i = 0;
  uint64_t len = 0;
  while (1) {
    uint128_t current_amount = 0;
    len = 16;
    // The implementation here does not require that the transaction only
    // contains UDT cells for the current UDT type. It's perfectly fine to mix
    // the cells for multiple different types of UDT together in one
    // transaction. But that also means we need a way to tell one UDT type from
    // another UDT type. The trick is in the `CKB_SOURCE_GROUP_INPUT` value used
    // here. When using it as the source part of the syscall, the syscall would
    // only iterate through cells with the same script as the current running
    // script. Since different UDT types will naturally have different
    // script(the args part will be different), we can be sure here that this
    // loop would only iterate through UDTs that are of the same type as the one
    // identified by the current running script.
    //
    // In the case that multiple UDT types are included in the same transaction,
    // this simple UDT script will be run multiple times to validate the
    // transaction, each time with a different script containing different
    // script args, representing different UDT types.
    //
    // A different trick used here, is that our current implementation assumes
    // that the amount of UDT is stored as unsigned 128-bit little endian
    // integer in the first 16 bytes of cell data. Since RISC-V also uses little
    // endian format, we can just read the first 16 bytes of cell data into
    // `current_amount`, which is just an unsigned 128-bit integer in C. The
    // memory layout of a C program will ensure that the value is set correctly.
    ret = ckb_checked_load_cell_data((uint8_t*)&current_amount, &len, 0, i,
                                     CKB_SOURCE_GROUP_INPUT);
    // When `CKB_INDEX_OUT_OF_BOUND` is reached, we know we have iterated
    // through all cells of current type.
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len < 16) {
      return ERROR_ENCODING;
    }
    input_amount += current_amount;
    // Like any serious smart contract out there, we will need to check for
    // overflows.
    if (input_amount < current_amount) {
      return ERROR_OVERFLOWING;
    }
    i += 1;
  }

  // With the sum of all input UDT tokens gathered, let's now iterate through
  // output cells to grab the sum of all output UDT tokens.
  uint128_t output_amount = 0;
  i = 0;
  while (1) {
    uint128_t current_amount = 0;
    len = 16;
    // Similar to the above code piece, we are also looping through output cells
    // with the same script as current running script here by using
    // `CKB_SOURCE_GROUP_OUTPUT`.
    ret = ckb_checked_load_cell_data((uint8_t*)&current_amount, &len, 0, i,
                                     CKB_SOURCE_GROUP_OUTPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len < 16) {
      return ERROR_ENCODING;
    }
    output_amount += current_amount;
    // Like any serious smart contract out there, we will need to check for
    // overflows.
    if (output_amount < current_amount) {
      return ERROR_OVERFLOWING;
    }
    i += 1;
  }

  // When both value are gathered, we can perform the final check here to
  // prevent non-authorized token issurance.
  if (input_amount < output_amount) {
    return ERROR_AMOUNT;
  }
  return CKB_SUCCESS;
}

//   If the extension script is identical to a lock script of one input cell in
//   current transaction, we consider the extension script to be already
//   validated, no additional check is needed for current extension
int is_extension_script_validated(mol_seg_t extension_script,
                                  uint8_t* input_lock_script_hash,
                                  uint32_t input_lock_script_hash_count) {
  int err = 0;

  // verify the hash
  uint8_t hash[BLAKE2B_BLOCK_SIZE];
  err = blake2b(hash, BLAKE2B_BLOCK_SIZE, extension_script.ptr,
                extension_script.size, NULL, 0);
  CHECK2(err == 0, ERROR_BLAKE2B_ERROR);

  for (uint32_t i = 0; i < input_lock_script_hash_count; i++) {
    if (memcmp(&input_lock_script_hash[i * BLAKE2B_BLOCK_SIZE], hash,
               BLAKE160_SIZE) == 0) {
      return 0;
    }
  }
  err = ERROR_NOT_VALIDATED;
exit:
  return err;
}

#ifdef CKB_USE_SIM
int simulator_main() {
#else
int main() {
#endif
  int err = 0;
  int owner_mode = 0;
  uint8_t* raw_extension_data = NULL;
  uint32_t raw_extension_len = 0;
  XUDTFlags flags = XUDTFlags_Plain;
  uint8_t
      input_lock_script_hash[MAX_LOCK_SCRIPT_HASH_COUNT * BLAKE2B_BLOCKBYTES];
  uint32_t input_lock_script_hash_count = 0;
  err = parse_args(&owner_mode, &flags, &raw_extension_data, &raw_extension_len,
                   input_lock_script_hash, &input_lock_script_hash_count);
  CHECK(err);
  CHECK2(owner_mode == 1 || owner_mode == 0, ERROR_INVALID_ARGS_FORMAT);
  if (flags != XUDTFlags_Plain) {
    CHECK2(raw_extension_data != NULL, ERROR_INVALID_ARGS_FORMAT);
    CHECK2(raw_extension_len > 0, ERROR_INVALID_ARGS_FORMAT);
  }
  err = simple_udt(owner_mode);
  CHECK(err);

  if (flags == XUDTFlags_Plain) {
    return CKB_SUCCESS;
  }

  mol_seg_t raw_extension_seg = {0};
  raw_extension_seg.ptr = raw_extension_data;
  raw_extension_seg.size = raw_extension_len;
  CHECK2(MolReader_ScriptVec_verify(&raw_extension_seg, true) == MOL_OK,
         ERROR_INVALID_ARGS_FORMAT);
  uint32_t size = MolReader_ScriptVec_length(&raw_extension_seg);
  for (uint32_t i = 0; i < size; i++) {
    ValidateFuncType func;
    mol_seg_res_t res = MolReader_ScriptVec_get(&raw_extension_seg, i);
    CHECK2(res.errno == 0, ERROR_INVALID_MOL_FORMAT);
    CHECK2(MolReader_Script_verify(&res.seg, false) == MOL_OK,
           ERROR_INVALID_MOL_FORMAT);

    mol_seg_t code_hash = MolReader_Script_get_code_hash(&res.seg);
    mol_seg_t hash_type = MolReader_Script_get_hash_type(&res.seg);
    mol_seg_t args = MolReader_Script_get_args(&res.seg);

    uint8_t hash_type2 = *((uint8_t*)hash_type.ptr);
    XUDTValidateFuncCategory cat = XVFC_Normal;
    err = load_validate_func(code_hash.ptr, hash_type2, &func, &cat);
    CHECK(err);
    // RCE is with high priority, must be checked
    if (cat != XVFC_RCE) {
      int err2 = is_extension_script_validated(res.seg, input_lock_script_hash,
                                               input_lock_script_hash_count);
      if (err2 == 0) {
        continue;
      }
    }
    mol_seg_t args_raw_bytes = MolReader_Bytes_raw_bytes(&args);

    int result = 0;
    result = func(owner_mode, i, args_raw_bytes.ptr, args_raw_bytes.size);
    if (result != 0) {
      xudt_printf("A non-zero returned from xUDT extension scripts.\n");
    }
    CHECK(result);
  }

  err = 0;
exit:
  return err;
}