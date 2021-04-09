/* UDT anyone-can-pay lock script
 * For simplify, we call a cell with anyone-can-pay lock a wallet cell.
 *
 * Wallet cell can be unlocked without a signature, if:
 *
 * 1. There is 1 output wallet cell that has the same type hash with the
 * unlocked wallet cell.
 * 2. The UDT or CKB(if type script is none) in the output wallet is more than
 * the unlocked wallet.
 * 3. if the type script is none, the cell data is empty.
 *
 * otherwise, the script perform secp256k1_blake160_sighash_all verification.
 */

#include "blake2b.h"
#include "blockchain.h"
#include "ckb_syscalls.h"
#include "defs.h"
#include "overflow_add.h"
#include "quick_pow10.h"
#include "secp256k1_helper.h"
#include "secp256k1_lock.h"

#define BLAKE2B_BLOCK_SIZE 32
#define SCRIPT_SIZE 32768
#define CKB_LEN 8
#define UDT_LEN 16
#define MAX_WITNESS_SIZE 32768
#define MAX_TYPE_HASH 256

/* anyone can pay errors */
#define ERROR_OVERFLOW -41
#define ERROR_OUTPUT_AMOUNT_NOT_ENOUGH -42
#define ERROR_TOO_MUCH_TYPE_HASH_INPUTS -43
#define ERROR_NO_PAIR -44
#define ERROR_DUPLICATED_INPUTS -45
#define ERROR_DUPLICATED_OUTPUTS -46

typedef struct {
  int is_ckb_only;
  unsigned char type_hash[BLAKE2B_BLOCK_SIZE];
  uint64_t ckb_amount;
  uint128_t udt_amount;
  uint32_t output_cnt;
} InputWallet;

int load_type_hash_and_amount(uint64_t cell_index, uint64_t cell_source,
                              uint8_t type_hash[BLAKE2B_BLOCK_SIZE],
                              uint64_t *ckb_amount, uint128_t *udt_amount,
                              int *is_ckb_only) {
  uint64_t len = BLAKE2B_BLOCK_SIZE;
  int ret = ckb_checked_load_cell_by_field(
      type_hash, &len, 0, cell_index, cell_source, CKB_CELL_FIELD_TYPE_HASH);
  if (ret == CKB_INDEX_OUT_OF_BOUND) {
    return ret;
  }

  if (ret == CKB_SUCCESS) {
    if (len != BLAKE2B_BLOCK_SIZE) {
      return ERROR_ENCODING;
    }
  } else if (ret != CKB_ITEM_MISSING) {
    return ERROR_SYSCALL;
  }

  *is_ckb_only = ret == CKB_ITEM_MISSING;

  /* load amount */
  len = CKB_LEN;
  ret =
      ckb_checked_load_cell_by_field((uint8_t *)ckb_amount, &len, 0, cell_index,
                                     cell_source, CKB_CELL_FIELD_CAPACITY);
  if (ret != CKB_SUCCESS) {
    *ckb_amount = 0;
    return ERROR_SYSCALL;
  }
  if (len != CKB_LEN) {
    return ERROR_ENCODING;
  }
  len = UDT_LEN;
  ret = ckb_load_cell_data((uint8_t *)udt_amount, &len, 0, cell_index,
                           cell_source);
  if (ret != CKB_SUCCESS) {
    *udt_amount = 0;
    if (ret != CKB_ITEM_MISSING) {
      return ERROR_SYSCALL;
    }

    return CKB_SUCCESS;
  }

  /* check data length */
  if (*is_ckb_only) {
    /* ckb only wallet should has no data */
    if (len != 0) {
      return ERROR_ENCODING;
    }
  } else {
    if (len < UDT_LEN) {
      return ERROR_ENCODING;
    }
  }

  return CKB_SUCCESS;
}

int check_payment_unlock(uint64_t min_ckb_amount, uint128_t min_udt_amount) {
  unsigned char lock_hash[BLAKE2B_BLOCK_SIZE] = {0};
  InputWallet input_wallets[MAX_TYPE_HASH] = {0};
  uint64_t len = BLAKE2B_BLOCK_SIZE;
  /* load wallet lock hash */
  int ret = ckb_load_script_hash(lock_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > BLAKE2B_BLOCK_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }

  /* iterate inputs and find input wallet cell */
  int i = 0;
  len = BLAKE2B_BLOCK_SIZE;
  while (1) {
    if (i >= MAX_TYPE_HASH) {
      return ERROR_TOO_MUCH_TYPE_HASH_INPUTS;
    }

    ret = load_type_hash_and_amount(
        i, CKB_SOURCE_GROUP_INPUT, input_wallets[i].type_hash,
        &input_wallets[i].ckb_amount, &input_wallets[i].udt_amount,
        &input_wallets[i].is_ckb_only);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    } else if (ret != CKB_SUCCESS) {
      return ret;
    }

    i++;
  }

  int input_wallets_cnt = i;

  /* iterate outputs wallet cell */
  i = 0;
  while (1) {
    uint8_t output_lock_hash[BLAKE2B_BLOCK_SIZE] = {0};
    uint8_t output_type_hash[BLAKE2B_BLOCK_SIZE] = {0};
    uint64_t len = BLAKE2B_BLOCK_SIZE;
    /* check lock hash */
    ret = ckb_checked_load_cell_by_field(output_lock_hash, &len, 0, i,
                                         CKB_SOURCE_OUTPUT,
                                         CKB_CELL_FIELD_LOCK_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len != BLAKE2B_BLOCK_SIZE) {
      return ERROR_ENCODING;
    }
    int has_same_lock =
        memcmp(output_lock_hash, lock_hash, BLAKE2B_BLOCK_SIZE) == 0;

    /* skip non ACP lock cells*/
    if (!has_same_lock) {
      i++;
      continue;
    }

    /* load output cell */
    int is_ckb_only = 0;
    uint64_t ckb_amount = 0;
    uint128_t udt_amount = 0;
    ret = load_type_hash_and_amount(i, CKB_SOURCE_OUTPUT, output_type_hash,
                                    &ckb_amount, &udt_amount, &is_ckb_only);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    } else if (ret != CKB_SUCCESS) {
      return ret;
    }

    /* find input wallet which has same type hash */
    int found_inputs = 0;
    for (int j = 0; j < input_wallets_cnt; j++) {
      int has_same_type = 0;
      /* check type hash */
      if (is_ckb_only) {
        has_same_type = input_wallets[j].is_ckb_only;
      } else {
        has_same_type = memcmp(output_type_hash, input_wallets[j].type_hash,
                               BLAKE2B_BLOCK_SIZE) == 0;
      }
      if (!has_same_type) {
        continue;
      }
      /* compare amount */
      uint64_t min_output_ckb_amount = 0;
      uint128_t min_output_udt_amount = 0;
      int overflow = 0;
      overflow = uint64_overflow_add(
          &min_output_ckb_amount, input_wallets[j].ckb_amount, min_ckb_amount);
      int meet_ckb_cond = !overflow && ckb_amount >= min_output_ckb_amount;
      overflow = uint128_overflow_add(
          &min_output_udt_amount, input_wallets[j].udt_amount, min_udt_amount);
      int meet_udt_cond = !overflow && udt_amount >= min_output_udt_amount;

      /* fail if can't meet both conditions */
      if (!(meet_ckb_cond || meet_udt_cond)) {
        return ERROR_OUTPUT_AMOUNT_NOT_ENOUGH;
      }
      /* output coins must meet condition, or remain the old amount */
      if ((!meet_ckb_cond && ckb_amount != input_wallets[j].ckb_amount) ||
          (!meet_udt_cond && udt_amount != input_wallets[j].udt_amount)) {
        return ERROR_OUTPUT_AMOUNT_NOT_ENOUGH;
      }

      /* increase counter */
      found_inputs++;
      input_wallets[j].output_cnt += 1;
      if (found_inputs > 1) {
        return ERROR_DUPLICATED_INPUTS;
      }
      if (input_wallets[j].output_cnt > 1) {
        return ERROR_DUPLICATED_OUTPUTS;
      }
    }

    /* one output should pair with one input */
    if (found_inputs == 0) {
      return ERROR_NO_PAIR;
    } else if (found_inputs > 1) {
      return ERROR_DUPLICATED_INPUTS;
    }

    i++;
  }

  /* check inputs wallet, one input should pair with one output */
  for (int j = 0; j < input_wallets_cnt; j++) {
    if (input_wallets[j].output_cnt == 0) {
      return ERROR_NO_PAIR;
    } else if (input_wallets[j].output_cnt > 1) {
      return ERROR_DUPLICATED_OUTPUTS;
    }
  }

  return CKB_SUCCESS;
}

int read_args(unsigned char *pubkey_hash, uint64_t *min_ckb_amount,
              uint128_t *min_udt_amount) {
  int ret;
  uint64_t len = 0;

  /* Load args */
  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size < BLAKE160_SIZE ||
      args_bytes_seg.size > BLAKE160_SIZE + 2) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(pubkey_hash, args_bytes_seg.ptr, BLAKE160_SIZE);
  *min_ckb_amount = 0;
  *min_udt_amount = 0;
  if (args_bytes_seg.size > BLAKE160_SIZE) {
    int x = args_bytes_seg.ptr[BLAKE160_SIZE];
    int is_overflow = quick_pow10(x, min_ckb_amount);
    if (is_overflow) {
      *min_ckb_amount = MAX_UINT64;
    }
  }
  if (args_bytes_seg.size > BLAKE160_SIZE + 1) {
    int x = args_bytes_seg.ptr[BLAKE160_SIZE + 1];
    int is_overflow = uint128_quick_pow10(x, min_udt_amount);
    if (is_overflow) {
      *min_udt_amount = MAX_UINT128;
    }
  }
  return CKB_SUCCESS;
}

int main() {
  int ret;
  /* read script args */
  unsigned char pubkey_hash[BLAKE160_SIZE] = {0};
  uint64_t min_ckb_amount = 0;
  uint128_t min_udt_amount = 0;
  ret = read_args(pubkey_hash, &min_ckb_amount, &min_udt_amount);
  if (ret != CKB_SUCCESS) {
    return ret;
  }

  /* try load signature */
  unsigned char first_witness[MAX_WITNESS_SIZE];
  uint64_t first_witness_len = 0;
  ret = load_secp256k1_first_witness_and_check_signature(first_witness,
                                                         &first_witness_len);
  int has_sig = ret == CKB_SUCCESS;

  /* ACP verification */
  if (has_sig) {
    /* unlock via signature */
    return verify_secp256k1_blake160_sighash_all_with_witness(
        pubkey_hash, first_witness, first_witness_len);
  } else {
    /* unlock via payment */
    return check_payment_unlock(min_ckb_amount, min_udt_amount);
  }
}
