// uncomment to enable printf in CKB-VM
// #define CKB_C_STDLIB_PRINTF

// it's used by blockchain-api2.h, the behavior when panic
#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif
int ckb_exit(signed char);

// clang-format off
#include <stdio.h>
#include "blockchain-api2.h"
#include "blockchain.h"
#include "ckb_consts.h"

#if defined(CKB_USE_SIM)
#include "ckb_syscall_rc_lock_sim.h"
#else
#include "ckb_syscalls.h"
#endif
#include "ckb_identity.h"
#include "ckb_smt.h"

// CHECK is defined in secp256k1
#undef CHECK
#include "rce.h"
#include "rc_lock_mol2.h"
// clang-format on

#define SCRIPT_SIZE 32768
#define MAX_LOCK_SCRIPT_HASH_COUNT 2048

enum RcLockErrorCode {
  // rc lock error code is starting from 80
  ERROR_UNKNOWN_FLAGS = 80,
  ERROR_PROOF_LENGTH_MISMATCHED,
  ERROR_NO_RCRULE,
  ERROR_NO_WHITE_LIST,
};

typedef struct ArgsType {
  CkbIdentityType id;
  uint8_t rc_root[32];
} ArgsType;

// make compiler happy
int make_cursor_from_witness(WitnessArgsType *witness, bool *_input) {
  return -1;
}

int parse_args(ArgsType *args, bool has_rc_identity) {
  int err = 0;
  uint8_t script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  err = ckb_checked_load_script(script, &len, 0);
  CHECK(err);

  mol_seg_t script_seg;
  script_seg.ptr = script;
  script_seg.size = (mol_num_t)len;

  mol_errno mol_err = MolReader_Script_verify(&script_seg, false);
  CHECK2(mol_err == MOL_OK, ERROR_ENCODING);

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  CHECK2(args_bytes_seg.size >= 1, ERROR_ARGUMENTS_LEN);
  uint8_t flags = args_bytes_seg.ptr[0];
  CHECK2(flags == IdentityFlagsPubkeyHash || flags == IdentityFlagsOwnerLock,
         ERROR_UNKNOWN_FLAGS);
  args->id.flags = flags;

  CHECK2(args_bytes_seg.size >= (1 + BLAKE160_SIZE), ERROR_INVALID_MOL_FORMAT);
  memcpy(args->id.blake160, args_bytes_seg.ptr + 1, BLAKE160_SIZE);

  if (has_rc_identity) {
    CHECK2(args_bytes_seg.size >= (1 + BLAKE160_SIZE + BLAKE2B_BLOCK_SIZE),
           ERROR_INVALID_MOL_FORMAT);
    memcpy(args->rc_root, args_bytes_seg.ptr + 1 + BLAKE160_SIZE,
           sizeof(args->rc_root));
  }

exit:
  return err;
}

static uint32_t read_from_witness(uintptr_t arg[], uint8_t *ptr, uint32_t len,
                                  uint32_t offset) {
  int err;
  uint64_t output_len = len;
  err = ckb_load_witness(ptr, &output_len, offset, arg[0], arg[1]);
  if (err != 0) {
    return 0;
  }
  if (output_len > len) {
    return len;
  } else {
    return (uint32_t)output_len;
  }
}

uint8_t g_witness_data_source[DEFAULT_DATA_SOURCE_LENGTH];
int make_witness(WitnessArgsType *witness) {
  int err = 0;
  uint64_t witness_len = 0;
  size_t source = CKB_SOURCE_GROUP_INPUT;
  err = ckb_load_witness(NULL, &witness_len, 0, 0, source);
  // when witness is missing, empty or not accessible, make it zero length.
  // don't fail, because owner lock without rc doesn't require witness.
  // when it's zero length, any further actions on witness will fail.
  if (err != 0) {
    witness_len = 0;
  }

  mol2_cursor_t cur;

  cur.offset = 0;
  cur.size = (mol_num_t)witness_len;

  mol2_data_source_t *ptr = (mol2_data_source_t *)g_witness_data_source;

  ptr->read = read_from_witness;
  ptr->total_size = (uint32_t)witness_len;
  // pass index and source as args
  ptr->args[0] = 0;
  ptr->args[1] = source;

  ptr->cache_size = 0;
  ptr->start_point = 0;
  ptr->max_cache_size = MAX_CACHE_SIZE;
  cur.data_source = ptr;

  *witness = make_WitnessArgs(&cur);

  return 0;
}

int verify_identity(CkbIdentityType *id, SmtProofEntryVecType *proofs,
                    RceState *rce_state) {
  int err = 0;
  uint32_t proof_len = proofs->t->len(proofs);
  CHECK2(proof_len == rce_state->rcrules_count, ERROR_PROOF_LENGTH_MISMATCHED);

  uint8_t key[SMT_KEY_BYTES] = {0};
  key[0] = id->flags;
  memcpy(key + 1, id->blake160, BLAKE160_SIZE);

  smt_pair_t entries[1];
  smt_state_t states;
  smt_state_init(&states, entries, 1);
  smt_state_insert(&states, key, SMT_VALUE_EMPTY);

  uint8_t proof_mask = 0x3;  // both
  for (uint32_t i = 0; i < proof_len; i++) {
    bool existing = false;
    SmtProofEntryType proof_entry = proofs->t->get(proofs, i, &existing);
    CHECK2(existing, ERROR_INVALID_MOL_FORMAT);
    mol2_cursor_t proof = proof_entry.t->proof(&proof_entry);

    const RCRule *current_rule = &rce_state->rcrules[i];
    err = rce_verify_one_rule(rce_state, &states, NULL, NULL, proof_mask, proof,
                              current_rule);
    CHECK(err);
  }
  if (rce_state->has_wl) {
    if (rce_state->both_on_wl) {
      err = 0;
    } else {
      err = ERROR_NOT_ON_WHITE_LIST;
    }
  } else {
    // all black list, it's not allowed
    err = ERROR_NO_WHITE_LIST;
  }
exit:
  return err;
}

#ifdef CKB_USE_SIM
int simulator_main() {
#else
int main() {
#endif
  int err = 0;
  // if has_rc_identity is true, it's one of the following:
  // - Unlock via administrator’s lock script hash
  // - Unlock via administrator’s public key hash
  bool has_rc_identity = false;
  CkbIdentityType identity = {0};
  RcIdentityType rc_identity = {0};
  bool witness_lock_existing = false;
  bool witness_existing = false;

  WitnessArgsType witness;
  err = make_witness(&witness);
  CHECK(err);
  witness_existing = witness.cur.size > 0;

  BytesOptType lock = {0};
  mol2_cursor_t lock_bytes = {0};
  RcLockWitnessLockType witness_lock = {0};

  // witness or witness lock can be empty if owner lock without rc is used
  if (witness_existing) {
    lock = witness.t->lock(&witness);
    if (!lock.t->is_none(&lock)) {
      witness_lock_existing = true;
      lock_bytes = lock.t->unwrap(&lock);
      // convert Bytes to RcLockWitnessLock
      witness_lock = make_RcLockWitnessLock(&lock_bytes);
      RcIdentityOptType rc_identity_opt =
          witness_lock.t->rc_identity(&witness_lock);
      has_rc_identity = rc_identity_opt.t->is_some(&rc_identity_opt);
      if (has_rc_identity) {
        rc_identity = rc_identity_opt.t->unwrap(&rc_identity_opt);
        mol2_cursor_t id_cur = rc_identity.t->identity(&rc_identity);
        uint8_t buff[CKB_IDENTITY_LEN] = {0};
        uint32_t read_len = mol2_read_at(&id_cur, buff, sizeof(buff));
        CHECK2(read_len == CKB_IDENTITY_LEN, ERROR_INVALID_MOL_FORMAT);
        identity.flags = buff[0];
        memcpy(identity.blake160, buff + 1, CKB_IDENTITY_LEN - 1);
      }
    } else {
      witness_lock_existing = false;
    }
  } else {
    witness_lock_existing = false;
  }

  ArgsType args = {0};
  err = parse_args(&args, has_rc_identity);
  CHECK(err);
  // When rc_identity is missing, the identity included in lock script args will
  // then be used in further validation.
  if (!has_rc_identity) {
    identity = args.id;
  }

  uint8_t signature_bytes[SIGNATURE_SIZE] = {0};
  if (identity.flags == IdentityFlagsPubkeyHash) {
    CHECK2(witness_lock_existing, ERROR_INVALID_MOL_FORMAT);

    BytesOptType signature_opt = witness_lock.t->signature(&witness_lock);
    mol2_cursor_t signature_cursor = signature_opt.t->unwrap(&signature_opt);

    uint32_t read_len =
        mol2_read_at(&signature_cursor, signature_bytes, SIGNATURE_SIZE);
    CHECK2(read_len == SIGNATURE_SIZE, ERROR_INVALID_MOL_FORMAT);
  }

  err = ckb_verify_identity(&identity, signature_bytes);

  // regulation compliance
  if (has_rc_identity) {
    CHECK2(witness_lock_existing, ERROR_INVALID_MOL_FORMAT);

    // collect rc rules
    RceState rce_state;
    rce_init_state(&rce_state);
    err = rce_gather_rcrules_recursively(&rce_state, args.rc_root, 0);
    CHECK(err);
    CHECK2(rce_state.rcrules_count > 0, ERROR_NO_RCRULE);
    CHECK2(rce_state.has_wl, ERROR_NO_WHITE_LIST);

    // collect proof
    SmtProofEntryVecType proofs = rc_identity.t->proofs(&rc_identity);

    // verify blake160 against proof, using rc rules
    err = verify_identity(&identity, &proofs, &rce_state);
    CHECK(err);
  }

exit:
  return err;
}
