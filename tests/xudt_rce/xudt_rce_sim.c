#if defined(CKB_COVERAGE)
#define ASSERT(s) (void)0
#else
#define ASSERT(s) (void)0
#endif

int ckb_exit(signed char code);

#include "utest.h"
#include "xudt_rce.c"
void debug_print_hex(const char* prefix, const uint8_t* buf, size_t length) {
  printf("%s: ", prefix);
  for (size_t i = 0; i < length; i++) {
    printf("%02x ", buf[i]);
  }
  printf("\n");
}

/* hex2bin modified from
 * https://chromium.googlesource.com/chromium/deps/xz/+/77022065014d48cf51d83322264ab4836fd175ec/debug/hex2bin.c
 */
int getbin(int x) {
  if (x >= '0' && x <= '9') return x - '0';
  if (x >= 'A' && x <= 'F') return x - 'A' + 10;
  return x - 'a' + 10;
}

int hex2bin(uint8_t* buf, const char* src) {
  size_t length = strlen(src) / 2;
  if (src[0] == '0' && (src[1] == 'x' || src[1] == 'X')) {
    src += 2;
    length--;
  }
  for (size_t i = 0; i < length; i++) {
    buf[i] = (getbin(src[i * 2]) << 4) | getbin(src[i * 2 + 1]);
  }
  return length;
}

void set_basic_data() {
  xudt_set_flags(1);
  xudt_add_input_amount(999);
  xudt_add_output_amount(999);

  // lock script hash
  uint8_t input_lock_script_hash[32] = {11};
  uint8_t output_lock_script_hash[32] = {22};
  xudt_add_input_lock_script_hash(input_lock_script_hash);
  xudt_add_output_lock_script_hash(output_lock_script_hash);
}

// the following hash_root, proof pairs are verified successfully
// with the following lock script hash:
//  uint8_t input_lock_script_hash[32] = {11};
//  uint8_t output_lock_script_hash[32] = {22};

uint8_t BLACK_LIST_HASH_ROOT[32] = {143, 95,  66,  207, 251, 51,  58,  199,
                                    247, 61,  211, 60,  28,  25,  51,  99,
                                    174, 94,  226, 239, 134, 201, 125, 79,
                                    63,  194, 180, 109, 161, 2,   92,  178};
uint8_t BLACK_LIST_PROOF[] = {
    76,  76,  72,  4,   80,  6,   62,  195, 223, 65,  89,  79,  50, 133, 172,
    95,  118, 228, 237, 101, 113, 8,   175, 152, 171, 153, 202, 45, 125, 177,
    0,   236, 236, 176, 183, 31,  109, 113, 80,  7,   88,  178, 89, 155, 132,
    146, 222, 163, 40,  147, 106, 150, 97,  234, 134, 107, 237, 60, 9,   193,
    0,   16,  226, 17,  209, 89,  52,  22,  71,  135, 172, 225};

uint8_t WHITE_LIST_HASH_ROOT[32] = {151, 81,  37,  242, 189, 99,  62,  175,
                                    115, 9,   251, 94,  105, 190, 173, 153,
                                    42,  249, 87,  115, 253, 152, 110, 88,
                                    1,   58,  224, 21,  51,  99,  72,  182};
uint8_t WHITE_LIST_PROOF[] = {76, 76, 72, 4};

void set_rce_not_on_black_list_data() {
  int err = 0;
  set_basic_data();
  uint16_t root_rcrule =
      rce_add_rcrule(BLACK_LIST_HASH_ROOT, 0x0);  // black list
  rce_begin_proof();
  rce_add_proof(BLACK_LIST_PROOF, countof(BLACK_LIST_PROOF));
  rce_end_proof();
  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
}

void set_rce_on_black_list_data() {
  int err = 0;
  set_basic_data();
  uint8_t hash[32] = {
      0};  // invalid hash, so the verify result is false: it's on black list.
  uint16_t root_rcrule = rce_add_rcrule(hash, 0x0);  // on black list
  rce_begin_proof();
  rce_add_proof(BLACK_LIST_PROOF, countof(BLACK_LIST_PROOF));
  rce_end_proof();

  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
}

UTEST(xudt, main) {
  int err = 0;

  // prepare basic data
  xudt_begin_data();
  set_basic_data();

  uint8_t hash0[BLAKE2B_BLOCK_SIZE] = {0};
  uint8_t hash1[BLAKE2B_BLOCK_SIZE] = {1};
  uint8_t extension_hash[BLAKE2B_BLOCK_SIZE] = {0x66};
  uint8_t args[32] = {0};
  xudt_set_owner_mode(hash0, hash1);
  xudt_add_extension_script(
      extension_hash, 1, args, sizeof(args),
      "tests/xudt_rce/simulator-build-debug/libextension_script_0.dylib");

  xudt_end_data();

  // flags = 1
  xudt_set_flags(1);
  err = simulator_main();
  ASSERT_EQ(err, 0);
  CHECK(err);
  // flags = 2
  xudt_set_flags(2);
  err = simulator_main();
  ASSERT_EQ(err, 0);
  CHECK(err);
  // flags is not available
  xudt_set_flags(0);
  err = simulator_main();
  ASSERT_EQ(err, 0);
  CHECK(err);
  // flags is available, but it's value is 0,
  // Note: testing purpose, there is no such 0xFF flags.
  xudt_set_flags(0xFF);
  err = simulator_main();
  ASSERT_EQ(err, 0);
  CHECK(err);

  // owner mode is true
  xudt_set_owner_mode(hash0, hash0);
  err = simulator_main();
  ASSERT_EQ(err, 0);
  CHECK(err);

  err = 0;
exit:
  ASSERT_EQ(err, 0);
}

UTEST(rce, white_list) {
  int err = 0;
  xudt_begin_data();
  set_basic_data();
  uint16_t root_rcrule =
      rce_add_rcrule(WHITE_LIST_HASH_ROOT, 0x2);  // white list
  rce_begin_proof();
  rce_add_proof(WHITE_LIST_PROOF, countof(WHITE_LIST_PROOF));
  rce_end_proof();
  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
  xudt_end_data();

  err = simulator_main();
  ASSERT_EQ(err, 0);
exit:
  return;
}

UTEST(rce, not_on_white_list) {
  int err = 0;
  xudt_begin_data();
  set_basic_data();

  uint8_t rcrule[32] = {0};                            // invalid root_hash
  uint16_t root_rcrule = rce_add_rcrule(rcrule, 0x2);  // white list
  uint8_t proof[] = {76, 76, 72, 4};
  rce_begin_proof();
  rce_add_proof(proof, countof(proof));
  rce_end_proof();
  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
  xudt_end_data();

  err = simulator_main();
  ASSERT_EQ(err, 0);
exit:
  return;
}

UTEST(smt, verify_not_on_bl) {
  uint8_t key1[32] = {11};
  uint8_t value1[32] = {0};
  uint8_t key2[32] = {22};
  uint8_t value2[32] = {0};

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key1, value1);
  smt_state_insert(&changes, key2, value2);
  smt_state_normalize(&changes);

  int err = smt_verify(BLACK_LIST_HASH_ROOT, &changes, BLACK_LIST_PROOF,
                       sizeof(BLACK_LIST_PROOF));
  ASSERT_EQ(0, err);
}

UTEST(rce, black_list) {
  int err = 0;
  xudt_begin_data();
  set_basic_data();
  uint16_t root_rcrule =
      rce_add_rcrule(BLACK_LIST_HASH_ROOT, 0x0);  // black list
  rce_begin_proof();
  rce_add_proof(BLACK_LIST_PROOF, countof(BLACK_LIST_PROOF));
  rce_end_proof();
  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
  xudt_end_data();
  err = simulator_main();
  ASSERT_EQ(0, err);
exit:
  return;
}

UTEST(xudt, simple_udt) {
  int err = 0;
  xudt_begin_data();
  set_rce_not_on_black_list_data();
  xudt_add_input_amount(999);
  xudt_add_output_amount(1000);
  xudt_end_data();
  err = simulator_main();
  ASSERT_EQ(err, ERROR_AMOUNT);

exit:
  return;
}

UTEST(xudt, emergency_halt_mode) {
  int err = 0;
  xudt_begin_data();
  xudt_set_flags(2);

  uint16_t root_rcrule = rce_add_rcrule(
      BLACK_LIST_HASH_ROOT, 0x1);  // emergency halt mode, black list
  rce_begin_proof();
  rce_add_proof(BLACK_LIST_PROOF, countof(BLACK_LIST_PROOF));
  rce_end_proof();
  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
  xudt_end_data();
  err = simulator_main();
  ASSERT_EQ(err, ERROR_RCE_EMERGENCY_HALT);
exit:
  return;
}

UTEST(xudt, extension_script_is_realdy_validated) {
  int err = 0;

  xudt_begin_data();

  xudt_set_flags(1);
  xudt_add_input_amount(999);
  xudt_add_output_amount(999);
  uint8_t extension_hash[BLAKE2B_BLOCK_SIZE] = {0x66};
  uint8_t args[32] = {0};

  xudt_add_extension_script(
      extension_hash, 1, args, sizeof(args),
      "tests/xudt_rce/simulator-build-debug/libextension_script_0.dylib");
  uint8_t hash[32];
  xudt_calc_extension_script_hash(extension_hash, 1, args, sizeof(args), hash);
  uint8_t output_lock_script_hash[32] = {22};
  // extension script hash is identical to lock script hash
  xudt_add_input_lock_script_hash(hash);
  xudt_add_output_lock_script_hash(output_lock_script_hash);

  // finish data
  xudt_end_data();

  err = simulator_main();
  ASSERT_EQ(err, 0);
exit:
  return;
}

UTEST(xudt, extension_script_returns_non_zero) {
  int err = 0;
  xudt_begin_data();
  set_rce_on_black_list_data();
  uint8_t extension_hash[BLAKE2B_BLOCK_SIZE] = {0x66};
  uint8_t args[32] = {0};
  xudt_add_extension_script(
      extension_hash, 1, args, sizeof(args),
      "tests/xudt_rce/simulator-build-debug/libextension_script_1.dylib");
  xudt_end_data();
  err = simulator_main();
  ASSERT_EQ(ERROR_ON_BLACK_LIST, err);

exit:
  return;
}

UTEST(rce, use_rc_cell_vec) {
  int err = 0;
  // prepare basic data
  xudt_begin_data();
  set_basic_data();
  uint16_t rcrulevec[MAX_RCRULE_IN_CELL] = {0};
  for (int i = 0; i < MAX_RCRULE_IN_CELL; i++) {
    rcrulevec[i] =
        rce_add_rcrule(BLACK_LIST_HASH_ROOT, 0x0);  // not on black list
  }
  RCHashType root_rcrule = rce_add_rccellvec(rcrulevec, MAX_RCRULE_IN_CELL);
  rce_begin_proof();
  for (int i = 0; i < MAX_RCRULE_IN_CELL; i++) {
    rce_add_proof(BLACK_LIST_PROOF, countof(BLACK_LIST_PROOF));
  }
  rce_end_proof();
  uint8_t args[32] = {0};
  memcpy(args, &root_rcrule, 2);
  xudt_add_extension_script(RCE_HASH, 1, args, sizeof(args),
                            "internal extension script, no path");
  xudt_end_data();

  err = simulator_main();
  ASSERT_EQ(0, err);
exit:
  return;
}

UTEST(smt, verify_not_existing) {
  uint8_t key1[32] = {11};
  uint8_t value1[32] = {0};
  uint8_t key2[32] = {22};
  uint8_t value2[32] = {0};
  uint8_t root_hash[32] = {143, 95, 66, 207, 251, 51,  58,  199, 247, 61,  211,
                           60,  28, 25, 51,  99,  174, 94,  226, 239, 134, 201,
                           125, 79, 63, 194, 180, 109, 161, 2,   92,  178};
  uint8_t proof[] = {
      76,  76,  72,  4,   80,  6,   62,  195, 223, 65,  89,  79,  50, 133, 172,
      95,  118, 228, 237, 101, 113, 8,   175, 152, 171, 153, 202, 45, 125, 177,
      0,   236, 236, 176, 183, 31,  109, 113, 80,  7,   88,  178, 89, 155, 132,
      146, 222, 163, 40,  147, 106, 150, 97,  234, 134, 107, 237, 60, 9,   193,
      0,   16,  226, 17,  209, 89,  52,  22,  71,  135, 172, 225};

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key1, value1);
  smt_state_insert(&changes, key2, value2);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, sizeof(proof)));
}

// this is the case from
// https://github.com/nervosnetwork/ckb-simple-account-layer/blob/1970c0382271837ff46fdc276c5b63bccb4324db/c/tests/main.c#L136
// the names are changed accordingly.
UTEST(smt, verify_empty) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0x0101010101010101010101010101010101010101010101010101010101010101");
  hex2bin(value,
          "0x0000000000000000000000000000000000000000000000000000000000000000");
  hex2bin(root_hash,
          "0x0000000000000000000000000000000000000000000000000000000000000000");
  int proof_length = hex2bin(proof, "0x4c");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_empty2) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0x0101010101010101010101010101010101010101010101010101010101010101");
  hex2bin(value,
          "0x0000000000000000000000000000000000000000000000000000000000000000");
  hex2bin(root_hash,
          "0x27cdd63d6d03e2a8dfc28d1919def1324b11b44733937ce66b8cf343a2fb536e");
  int proof_length = hex2bin(proof,
                             "0x4c50f027cdd63d6d03e2a8dfc28d1919def1324b11b4473"
                             "3937ce66b8cf343a2fb536e");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify1) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(
      proof,
      "0x4c50f85faa7bccd1095c904fe34c99236f0734f909823d8d48b81b0b92bab531f372c1"
      "50fe3f2a0a59ba1081f2d343682b200a778191a4e5838a46774eda8e1ee201c6cb2f");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify2) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(
      proof,
      "0x4c50f8a9cee9b111fddde5dd16c6684715587ba628bf73407e03e9db579e41af0c09b8"
      "50fe3f2a0a59ba1081f2d343682b200a778191a4e5838a46774eda8e1ee201c6cb2f");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify3) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(
      proof,
      "0x4c50fe32845309d34f132cd6f7ac6a7881962401adc35c19a08d4fffeb511b97ea"
      "bf86");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_invalid_hash) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(
      proof,
      "0x4c50fe32845309d34f132cd6f7ac6a7881962401adc35c19a18d4fffeb511b97ea"
      "bf86");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_NE(0, smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_all_leaves_used) {}

UTEST(smt, verify_multi_2) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(root_hash,
          "0xaa84c1a9b237e29e78bf2c59539e0ab2aa4ddd727f1d43bda03cc37ca9c523ca");
  int proof_length = hex2bin(
      proof,
      "0x4c4c48f950fe32845309d34f132cd6f7ac6a7881962401adc35c19a08d4fffeb51"
      "1b97eabf86");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  smt_state_insert(&changes, key, value);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e6");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19ec");
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_multi_3) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(proof, "0x4c4c48f84c48fe");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  smt_state_insert(&changes, key, value);
  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  smt_state_insert(&changes, key, value);
  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_EQ(0, smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, verify_invalid_height) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t proof[96];

  hex2bin(root_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  int proof_length = hex2bin(proof, "0x4c4c48204c4840");

  smt_pair_t entries[8];
  smt_state_t changes;
  smt_state_init(&changes, entries, 32);
  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  smt_state_insert(&changes, key, value);
  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  smt_state_insert(&changes, key, value);
  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);

  ASSERT_NE(0, smt_verify(root_hash, &changes, proof, proof_length));
}

UTEST(smt, update) {
  uint8_t key[32];
  uint8_t value[32];
  uint8_t root_hash[32];
  uint8_t expected_hash[32];
  uint8_t proof[96];
  smt_pair_t entries[8];
  smt_state_t changes;

  memset(root_hash, 0, 32);
  hex2bin(key,
          "0xa9bb945be71f0bd2757d33d2465b6387383da42f321072e47472f0c9c7428a8a");
  hex2bin(value,
          "0xa939a47335f777eac4c40fbc0970e25f832a24e1d55adc45a7b76d63fe364e82");
  int proof_length = hex2bin(proof, "0x4c");
  memset(&proof[32], 0, 64);
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);
  ASSERT_EQ(0, smt_calculate_root(root_hash, &changes, proof, proof_length));
  hex2bin(expected_hash,
          "0x5faa7bccd1095c904fe34c99236f0734f909823d8d48b81b0b92bab531f372c1");
  ASSERT_EQ(0, memcmp(root_hash, expected_hash, 32));

  hex2bin(key,
          "0x381dc5391dab099da5e28acd1ad859a051cf18ace804d037f12819c6fbc0e18b");
  hex2bin(value,
          "0x9158ce9b0e11dd150ba2ae5d55c1db04b1c5986ec626f2e38a93fe8ad0b2923b");
  proof_length = hex2bin(
      proof,
      "0x4c50f85faa7bccd1095c904fe34c99236f0734f909823d8d48b81b0b92bab531f3"
      "72c1");
  memset(&proof[64], 0, 32);
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);
  ASSERT_EQ(0, smt_calculate_root(root_hash, &changes, proof, proof_length));
  hex2bin(expected_hash,
          "0x32845309d34f132cd6f7ac6a7881962401adc35c19a08d4fffeb511b97eabf86");
  ASSERT_EQ(0, memcmp(root_hash, expected_hash, 32));

  hex2bin(key,
          "0xe8c0265680a02b680b6cbc880348f062b825b28e237da7169aded4bcac0a04e5");
  hex2bin(value,
          "0x2ca41595841e46ce8e74ad749e5c3f1d17202150f99c3d8631233ebdd19b19eb");
  proof_length = hex2bin(
      proof,
      "0x4c50fe32845309d34f132cd6f7ac6a7881962401adc35c19a08d4fffeb511b97ea"
      "bf86");
  smt_state_init(&changes, entries, 32);
  smt_state_insert(&changes, key, value);
  smt_state_normalize(&changes);
  ASSERT_EQ(0, smt_calculate_root(root_hash, &changes, proof, proof_length));
  hex2bin(expected_hash,
          "0xa4cbf1b69a848396ac759f362679e2b185ac87a17cba747d2db1ef6fd929042f");
  ASSERT_EQ(0, memcmp(root_hash, expected_hash, 32));
}

UTEST_MAIN();
