#if defined(CKB_COVERAGE)
#define ASSERT(s) (void)0
#else
#define ASSERT(s) (void)0
#endif

int ckb_exit(signed char code);

#include "rc_lock.c"
#include "utest.h"
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

UTEST(pubkey_hash, pass) {
  init_input(&g_setting);
  g_setting.flags = IdentityFlagsPubkeyHash;
  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(0, r);
}

UTEST(pubkey_hash, wrong_signature) {
  init_input(&g_setting);
  g_setting.flags = IdentityFlagsPubkeyHash;

  g_setting.wrong_signature = true;
  convert_setting_to_states();

  int r = simulator_main();
  bool b = (r == ERROR_IDENTITY_PUBKEY_BLAKE160_HASH ||
            r == ERROR_IDENTITY_SECP_RECOVER_PUBKEY ||
            r == ERROR_IDENTITY_SECP_PARSE_SIGNATURE);
  ASSERT_TRUE(b);
}

UTEST(pubkey_hash, wrong_pubkey_hash) {
  init_input(&g_setting);
  g_setting.flags = IdentityFlagsPubkeyHash;

  g_setting.wrong_pubkey_hash = true;
  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_IDENTITY_PUBKEY_BLAKE160_HASH, r);
}

UTEST(owner_lock, pass) {
  init_input(&g_setting);
  g_setting.flags = IdentityFlagsOwnerLock;

  uint8_t blake160[20] = {0xBE, 0xEF};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(0, r);
}

UTEST(owner_lock_without_witness, pass) {
  init_input(&g_setting);
  g_setting.flags = IdentityFlagsOwnerLock;
  g_setting.empty_witness = true;

  uint8_t blake160[20] = {0xBE, 0xEF};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(0, r);
}

UTEST(owner_lock, not_pass) {
  init_input(&g_setting);
  g_setting.flags = IdentityFlagsOwnerLock;

  uint8_t blake160[20] = {0xBE, 0xEF};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;
  g_setting.input_lsh_count = 1;

  g_setting.blake160[0] = 0x00;

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_IDENTITY_LOCK_SCRIPT_HASH_NOT_FOUND, r);
}

void set_smt_settings(uint8_t flags, slice_t* rc_rules, slice_t* proofs,
                      uint8_t* smt_flags, size_t count) {
  g_setting.flags = flags;
  g_setting.proof_count = count;
  for (size_t i = 0; i < count; i++) {
    g_setting.proofs[i] = copy_slice(proofs[i].ptr, proofs[i].size);
    memcpy(g_setting.rc_rules[i].smt_root, rc_rules[i].ptr, rc_rules[i].size);
    g_setting.rc_rules[i].flags = smt_flags[i];  // white list
  }
}

UTEST(owner_lock_rc, on_wl_pass) {
  init_input(&g_setting);

  uint8_t rcrule[] = {249, 66,  221, 47, 190, 232, 225, 55, 103, 103, 249,
                      137, 17,  180, 35, 62,  28,  221, 15, 158, 58,  216,
                      31,  134, 177, 3,  114, 216, 112, 23, 153, 187};
  uint8_t proof[] = {76,  80,  167, 132, 225, 80,  249, 77,  218, 113, 177, 125,
                     47,  220, 235, 79,  189, 236, 109, 165, 246, 42,  250, 67,
                     238, 16,  247, 227, 139, 242, 240, 143, 31,  28,  184};

  slice_t proof_slice = copy_slice(proof, sizeof(proof));
  slice_t rcrule_slice = copy_slice(rcrule, sizeof(rcrule));
  uint8_t smt_flags = 0x2;  // white list
  g_setting.use_rc = true;
  set_smt_settings(IdentityFlagsOwnerLock, &rcrule_slice, &proof_slice,
                   &smt_flags, 1);

  // the true smt key will be {1(IdentityFlagsOwnerLockRc), 11, 0, 0, ...}
  uint8_t blake160[20] = {11};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(0, r);
}

UTEST(owner_lock_rc, no_rcrule_not_pass) {
  init_input(&g_setting);

  g_setting.flags = IdentityFlagsOwnerLock;
  g_setting.use_rc = true;

  uint8_t blake160[20] = {11};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_NO_RCRULE, r);
}

UTEST(owner_lock_rc, one_white_list_not_pass) {
  init_input(&g_setting);

  uint8_t rcrule[] = {211, 74,  208, 180, 70,  53,  171, 243, 13,  204, 148,
                      95,  152, 163, 82,  95,  176, 182, 11,  34,  193, 72,
                      23,  199, 82,  246, 171, 83,  254, 32,  178, 80};
  uint8_t proof[] = {76,  80,  12,  158, 217, 132, 249, 31,  18,  82,  14,  27,
                     234, 204, 18,  228, 250, 0,   102, 243, 203, 175, 243, 145,
                     127, 36,  142, 33,  32,  101, 195, 51,  115, 252, 192};

  rcrule[0] ^= 0x1;  // make it not pass

  slice_t proof_slice = copy_slice(proof, sizeof(proof));
  slice_t rcrule_slice = copy_slice(rcrule, sizeof(rcrule));
  uint8_t smt_flags = 0x2;  // white list

  g_setting.use_rc = true;
  set_smt_settings(IdentityFlagsOwnerLock, &rcrule_slice, &proof_slice,
                   &smt_flags, 1);

  // the true smt key will be {3(IdentityFlagsOwnerLockRc), 11, 0, 0, ...}
  uint8_t blake160[20] = {11};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_NOT_ON_WHITE_LIST, r);
}

UTEST(owner_lock_rc, on_wl_and_not_on_bl_pass) {
  init_input(&g_setting);

  uint8_t wl_rcrule[] = {249, 66,  221, 47, 190, 232, 225, 55, 103, 103, 249,
                         137, 17,  180, 35, 62,  28,  221, 15, 158, 58,  216,
                         31,  134, 177, 3,  114, 216, 112, 23, 153, 187};
  uint8_t wl_proof[] = {76,  80,  167, 132, 225, 80,  249, 77,  218,
                        113, 177, 125, 47,  220, 235, 79,  189, 236,
                        109, 165, 246, 42,  250, 67,  238, 16,  247,
                        227, 139, 242, 240, 143, 31,  28,  184};

  uint8_t bl_rcrule[] = {151, 81,  37,  242, 189, 99, 62,  175, 115, 9,   251,
                         94,  105, 190, 173, 153, 42, 249, 87,  115, 253, 152,
                         110, 88,  1,   58,  224, 21, 51,  99,  72,  182};
  uint8_t bl_proof[] = {76,  80,  11,  151, 81,  37,  242, 189, 99,
                        62,  175, 115, 9,   251, 94,  105, 190, 173,
                        153, 42,  249, 87,  115, 253, 152, 110, 88,
                        1,   58,  224, 21,  51,  99,  72,  182};

  slice_t rcrules[2] = {copy_slice(wl_rcrule, sizeof(wl_rcrule)),
                        copy_slice(bl_rcrule, sizeof(bl_rcrule))};
  slice_t proofs[2] = {copy_slice(wl_proof, sizeof(wl_proof)),
                       copy_slice(bl_proof, sizeof(bl_proof))};
  uint8_t smt_flags[2] = {0x2, 0x0};  // white list, black list

  g_setting.use_rc = true;
  set_smt_settings(IdentityFlagsOwnerLock, rcrules, proofs, smt_flags,
                   countof(smt_flags));

  // the true smt key will be {1(IdentityFlagsOwnerLockRc), 11, 0, 0, ...}
  uint8_t blake160[20] = {11};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(0, r);
}

UTEST(owner_lock_rc, not_on_bl_not_pass) {
  init_input(&g_setting);

  uint8_t bl_rcrule[] = {151, 81,  37,  242, 189, 99, 62,  175, 115, 9,   251,
                         94,  105, 190, 173, 153, 42, 249, 87,  115, 253, 152,
                         110, 88,  1,   58,  224, 21, 51,  99,  72,  182};
  uint8_t bl_proof[] = {76,  80,  11,  151, 81,  37,  242, 189, 99,
                        62,  175, 115, 9,   251, 94,  105, 190, 173,
                        153, 42,  249, 87,  115, 253, 152, 110, 88,
                        1,   58,  224, 21,  51,  99,  72,  182};

  slice_t rcrules[1] = {copy_slice(bl_rcrule, sizeof(bl_rcrule))};
  slice_t proofs[1] = {copy_slice(bl_proof, sizeof(bl_proof))};
  uint8_t smt_flags[1] = {0x0};

  g_setting.use_rc = true;
  set_smt_settings(IdentityFlagsOwnerLock, rcrules, proofs, smt_flags,
                   countof(smt_flags));

  // the true smt key will be {3(IdentityFlagsOwnerLockRc), 11, 0, 0, ...}
  uint8_t blake160[20] = {11};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_NO_WHITE_LIST, r);
}

UTEST(owner_lock_rc, on_wl_and_on_bl_not_pass) {
  init_input(&g_setting);

  uint8_t wl_rcrule[] = {211, 74,  208, 180, 70,  53,  171, 243, 13,  204, 148,
                         95,  152, 163, 82,  95,  176, 182, 11,  34,  193, 72,
                         23,  199, 82,  246, 171, 83,  254, 32,  178, 80};
  uint8_t wl_proof[] = {76,  80,  12,  158, 217, 132, 249, 31,  18,
                        82,  14,  27,  234, 204, 18,  228, 250, 0,
                        102, 243, 203, 175, 243, 145, 127, 36,  142,
                        33,  32,  101, 195, 51,  115, 252, 192};

  uint8_t bl_rcrule[] = {151, 81,  37,  242, 189, 99, 62,  175, 115, 9,   251,
                         94,  105, 190, 173, 153, 42, 249, 87,  115, 253, 152,
                         110, 88,  1,   58,  224, 21, 51,  99,  72,  182};
  uint8_t bl_proof[] = {76,  80,  11,  151, 81,  37,  242, 189, 99,
                        62,  175, 115, 9,   251, 94,  105, 190, 173,
                        153, 42,  249, 87,  115, 253, 152, 110, 88,
                        1,   58,  224, 21,  51,  99,  72,  182};

  bl_rcrule[0] ^= 0x1;  // make "verify it not on black list" failed

  slice_t rcrules[2] = {copy_slice(wl_rcrule, sizeof(wl_rcrule)),
                        copy_slice(bl_rcrule, sizeof(bl_rcrule))};
  slice_t proofs[2] = {copy_slice(wl_proof, sizeof(wl_proof)),
                       copy_slice(bl_proof, sizeof(bl_proof))};
  uint8_t smt_flags[2] = {0x2, 0x0};  // white list, black list

  g_setting.use_rc = true;
  set_smt_settings(IdentityFlagsOwnerLock, rcrules, proofs, smt_flags,
                   countof(smt_flags));

  // the true smt key will be {3(IdentityFlagsOwnerLockRc), 11, 0, 0, ...}
  uint8_t blake160[20] = {11};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_ON_BLACK_LIST, r);
}

UTEST(pubkey_hash_rc, on_wl_pass) {
  init_input(&g_setting);

  uint8_t rcrule[] = {60,  88, 9,  38,  78,  115, 57, 222, 226, 199, 240,
                      180, 76, 66, 80,  104, 114, 61, 25,  62,  103, 233,
                      89,  48, 51, 148, 166, 3,   99, 236, 63,  103};
  uint8_t proof[] = {76,  80,  167, 47,  46,  156, 221, 185, 1,  120, 166, 245,
                     121, 170, 246, 116, 57,  123, 204, 225, 14, 189, 214, 33,
                     164, 181, 166, 211, 225, 70,  88,  66,  69, 236, 96};

  slice_t proof_slice = copy_slice(proof, sizeof(proof));
  slice_t rcrule_slice = copy_slice(rcrule, sizeof(rcrule));
  uint8_t smt_flags = 0x2;  // white list
  g_setting.use_rc = true;
  set_smt_settings(IdentityFlagsPubkeyHash, &rcrule_slice, &proof_slice,
                   &smt_flags, 1);

  // blake160 of pubkey
  uint8_t blake160[20] = {184, 141, 45,  152, 205, 241, 253, 130, 123, 22,
                          22,  120, 131, 153, 185, 150, 222, 107, 17,  248};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(0, r);
}

UTEST(pubkey_hash_rc, on_wl_not_on_bl_pass) {
  init_input(&g_setting);

  uint8_t wl_rcrule[] = {60,  88, 9,  38,  78,  115, 57, 222, 226, 199, 240,
                         180, 76, 66, 80,  104, 114, 61, 25,  62,  103, 233,
                         89,  48, 51, 148, 166, 3,   99, 236, 63,  103};
  uint8_t wl_proof[] = {76,  80,  167, 47,  46,  156, 221, 185, 1,
                        120, 166, 245, 121, 170, 246, 116, 57,  123,
                        204, 225, 14,  189, 214, 33,  164, 181, 166,
                        211, 225, 70,  88,  66,  69,  236, 96};

  uint8_t bl_proof[] = {76,  80,  167, 151, 81,  37,  242, 189, 99,
                        62,  175, 115, 9,   251, 94,  105, 190, 173,
                        153, 42,  249, 87,  115, 253, 152, 110, 88,
                        1,   58,  224, 21,  51,  99,  72,  182};
  uint8_t bl_rcrule[] = {151, 81,  37,  242, 189, 99, 62,  175, 115, 9,   251,
                         94,  105, 190, 173, 153, 42, 249, 87,  115, 253, 152,
                         110, 88,  1,   58,  224, 21, 51,  99,  72,  182};

  slice_t rcrule_slice[] = {copy_slice(wl_rcrule, sizeof(wl_rcrule)),
                            copy_slice(bl_rcrule, sizeof(bl_rcrule))};
  slice_t proof_slice[] = {copy_slice(wl_proof, sizeof(wl_proof)),
                           copy_slice(bl_proof, sizeof(bl_proof))};
  uint8_t smt_flags[] = {0x2, 0};
  g_setting.use_rc = true;
  set_smt_settings(IdentityFlagsPubkeyHash, rcrule_slice, proof_slice,
                   smt_flags, countof(smt_flags));

  // blake160 of pubkey
  uint8_t blake160[20] = {184, 141, 45,  152, 205, 241, 253, 130, 123, 22,
                          22,  120, 131, 153, 185, 150, 222, 107, 17,  248};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(0, r);
}

UTEST(pubkey_hash_rc, not_bl_not_pass) {
  init_input(&g_setting);

  uint8_t bl_proof[] = {76,  80,  167, 151, 81,  37,  242, 189, 99,
                        62,  175, 115, 9,   251, 94,  105, 190, 173,
                        153, 42,  249, 87,  115, 253, 152, 110, 88,
                        1,   58,  224, 21,  51,  99,  72,  182};
  uint8_t bl_rcrule[] = {151, 81,  37,  242, 189, 99, 62,  175, 115, 9,   251,
                         94,  105, 190, 173, 153, 42, 249, 87,  115, 253, 152,
                         110, 88,  1,   58,  224, 21, 51,  99,  72,  182};

  slice_t rcrule_slice[] = {copy_slice(bl_rcrule, sizeof(bl_rcrule))};
  slice_t proof_slice[] = {copy_slice(bl_proof, sizeof(bl_proof))};
  uint8_t smt_flags[] = {0};
  g_setting.use_rc = true;
  set_smt_settings(IdentityFlagsPubkeyHash, rcrule_slice, proof_slice,
                   smt_flags, countof(smt_flags));

  // blake160 of pubkey
  uint8_t blake160[20] = {184, 141, 45,  152, 205, 241, 253, 130, 123, 22,
                          22,  120, 131, 153, 185, 150, 222, 107, 17,  248};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_NO_WHITE_LIST, r);
}

UTEST(pubkey_hash_rc, on_wl_on_bl_not_pass) {
  init_input(&g_setting);

  uint8_t wl_rcrule[] = {180, 114, 189, 251, 177, 152, 11,  244, 252, 16,  169,
                         249, 218, 80,  90,  86,  112, 210, 59,  128, 251, 216,
                         193, 197, 100, 4,   225, 10,  237, 48,  69,  42};
  uint8_t wl_proof[] = {76,  80,  167, 158, 217, 132, 249, 31,  18,
                        82,  14,  27,  234, 204, 18,  228, 250, 0,
                        102, 243, 203, 175, 243, 145, 127, 36,  142,
                        33,  32,  101, 195, 51,  115, 252, 192};

  uint8_t bl_proof[] = {76,  80,  167, 151, 81,  37,  242, 189, 99,
                        62,  175, 115, 9,   251, 94,  105, 190, 173,
                        153, 42,  249, 87,  115, 253, 152, 110, 88,
                        1,   58,  224, 21,  51,  99,  72,  182};
  uint8_t bl_rcrule[] = {151, 81,  37,  242, 189, 99, 62,  175, 115, 9,   251,
                         94,  105, 190, 173, 153, 42, 249, 87,  115, 253, 152,
                         110, 88,  1,   58,  224, 21, 51,  99,  72,  182};
  bl_rcrule[0] ^= 0x1;  // make "not on black list" failed

  slice_t rcrule_slice[] = {copy_slice(wl_rcrule, sizeof(wl_rcrule)),
                            copy_slice(bl_rcrule, sizeof(bl_rcrule))};
  slice_t proof_slice[] = {copy_slice(wl_proof, sizeof(wl_proof)),
                           copy_slice(bl_proof, sizeof(bl_proof))};
  uint8_t smt_flags[] = {0x2, 0};
  g_setting.use_rc = true;
  set_smt_settings(IdentityFlagsPubkeyHash, rcrule_slice, proof_slice,
                   smt_flags, countof(smt_flags));

  // blake160 of pubkey
  uint8_t blake160[20] = {184, 141, 45,  152, 205, 241, 253, 130, 123, 22,
                          22,  120, 131, 153, 185, 150, 222, 107, 17,  248};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_ON_BLACK_LIST, r);
}

UTEST(pubkey_hash_rc, not_on_wl_not_pass) {
  init_input(&g_setting);

  uint8_t rcrule[] = {180, 114, 189, 251, 177, 152, 11,  244, 252, 16,  169,
                      249, 218, 80,  90,  86,  112, 210, 59,  128, 251, 216,
                      193, 197, 100, 4,   225, 10,  237, 48,  69,  42};
  uint8_t proof[] = {76,  80,  167, 158, 217, 132, 249, 31,  18,  82,  14,  27,
                     234, 204, 18,  228, 250, 0,   102, 243, 203, 175, 243, 145,
                     127, 36,  142, 33,  32,  101, 195, 51,  115, 252, 192};
  rcrule[0] ^= 0x1;

  slice_t proof_slice = copy_slice(proof, sizeof(proof));
  slice_t rcrule_slice = copy_slice(rcrule, sizeof(rcrule));
  uint8_t smt_flags = 0x2;  // white list
  g_setting.use_rc = true;
  set_smt_settings(IdentityFlagsPubkeyHash, &rcrule_slice, &proof_slice,
                   &smt_flags, 1);

  // blake160 of pubkey
  uint8_t blake160[20] = {184, 141, 45,  152, 205, 241, 253, 130, 123, 22,
                          22,  120, 131, 153, 185, 150, 222, 107, 17,  248};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_NOT_ON_WHITE_LIST, r);
}

UTEST(pubkey_hash_rc, no_rcrule_not_pass) {
  init_input(&g_setting);
  g_setting.use_rc = true;
  g_setting.flags = IdentityFlagsPubkeyHash;

  uint8_t blake160[20] = {11};

  g_setting.input_lsh[0] = new_slice(32);
  memcpy(g_setting.input_lsh[0].ptr, blake160, sizeof(blake160));
  g_setting.input_lsh[0].size = 32;

  g_setting.input_lsh_count = 1;
  memcpy(g_setting.blake160, blake160, sizeof(blake160));

  convert_setting_to_states();

  int r = simulator_main();
  ASSERT_EQ(ERROR_NO_RCRULE, r);
}

UTEST_MAIN();
