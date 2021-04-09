
#ifndef _BLOCKCHAIN_MOL2_API2_H_
#define _BLOCKCHAIN_MOL2_API2_H_

#ifndef MOLECULEC_VERSION
#define MOLECULEC_VERSION 6001
#endif
#ifndef MOLECULE_API_VERSION_MIN
#define MOLECULE_API_VERSION_MIN 5000
#endif

#define MOLECULEC2_VERSION 6001
#define MOLECULE2_API_VERSION_MIN 5000

#include "molecule2_reader.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// ----forward declaration--------
struct ScriptVecType;
struct ScriptVecVTable;
struct ScriptVecVTable *GetScriptVecVTable(void);
struct ScriptVecType make_ScriptVec(mol2_cursor_t *cur);
uint32_t ScriptVec_len_impl(struct ScriptVecType *);
struct ScriptType ScriptVec_get_impl(struct ScriptVecType *, uint32_t, bool *);
struct ScriptVecOptType;
struct ScriptVecOptVTable;
struct ScriptVecOptVTable *GetScriptVecOptVTable(void);
struct ScriptVecOptType make_ScriptVecOpt(mol2_cursor_t *cur);
bool ScriptVecOpt_is_none_impl(struct ScriptVecOptType *);
bool ScriptVecOpt_is_some_impl(struct ScriptVecOptType *);
struct ScriptVecType ScriptVecOpt_unwrap_impl(struct ScriptVecOptType *);
struct XudtWitnessInputType;
struct XudtWitnessInputVTable;
struct XudtWitnessInputVTable *GetXudtWitnessInputVTable(void);
struct XudtWitnessInputType make_XudtWitnessInput(mol2_cursor_t *cur);
struct ScriptVecOptType XudtWitnessInput_get_raw_extension_data_impl(
    struct XudtWitnessInputType *);
struct BytesVecType XudtWitnessInput_get_extension_data_impl(
    struct XudtWitnessInputType *);
struct RCRuleType;
struct RCRuleVTable;
struct RCRuleVTable *GetRCRuleVTable(void);
struct RCRuleType make_RCRule(mol2_cursor_t *cur);
mol2_cursor_t RCRule_get_smt_root_impl(struct RCRuleType *);
uint8_t RCRule_get_flags_impl(struct RCRuleType *);
struct RCCellVecType;
struct RCCellVecVTable;
struct RCCellVecVTable *GetRCCellVecVTable(void);
struct RCCellVecType make_RCCellVec(mol2_cursor_t *cur);
uint32_t RCCellVec_len_impl(struct RCCellVecType *);
mol2_cursor_t RCCellVec_get_impl(struct RCCellVecType *, uint32_t, bool *);
struct RCDataType;
struct RCDataVTable;
struct RCDataVTable *GetRCDataVTable(void);
struct RCDataType make_RCData(mol2_cursor_t *cur);
uint32_t RCData_item_id_impl(struct RCDataType *);
struct RCRuleType RCData_as_RCRule_impl(struct RCDataType *);
struct RCCellVecType RCData_as_RCCellVec_impl(struct RCDataType *);
struct SmtProofType;
struct SmtProofVTable;
struct SmtProofVTable *GetSmtProofVTable(void);
struct SmtProofType make_SmtProof(mol2_cursor_t *cur);
uint32_t SmtProof_len_impl(struct SmtProofType *);
uint8_t SmtProof_get_impl(struct SmtProofType *, uint32_t, bool *);
struct SmtProofVecType;
struct SmtProofVecVTable;
struct SmtProofVecVTable *GetSmtProofVecVTable(void);
struct SmtProofVecType make_SmtProofVec(mol2_cursor_t *cur);
uint32_t SmtProofVec_len_impl(struct SmtProofVecType *);
mol2_cursor_t SmtProofVec_get_impl(struct SmtProofVecType *, uint32_t, bool *);
struct SmtUpdateItemType;
struct SmtUpdateItemVTable;
struct SmtUpdateItemVTable *GetSmtUpdateItemVTable(void);
struct SmtUpdateItemType make_SmtUpdateItem(mol2_cursor_t *cur);
mol2_cursor_t SmtUpdateItem_get_key_impl(struct SmtUpdateItemType *);
uint8_t SmtUpdateItem_get_values_impl(struct SmtUpdateItemType *);
struct SmtUpdateVecType;
struct SmtUpdateVecVTable;
struct SmtUpdateVecVTable *GetSmtUpdateVecVTable(void);
struct SmtUpdateVecType make_SmtUpdateVec(mol2_cursor_t *cur);
uint32_t SmtUpdateVec_len_impl(struct SmtUpdateVecType *);
struct SmtUpdateItemType SmtUpdateVec_get_impl(struct SmtUpdateVecType *,
                                               uint32_t, bool *);
struct SmtUpdateType;
struct SmtUpdateVTable;
struct SmtUpdateVTable *GetSmtUpdateVTable(void);
struct SmtUpdateType make_SmtUpdate(mol2_cursor_t *cur);
struct SmtUpdateVecType SmtUpdate_get_update_impl(struct SmtUpdateType *);
mol2_cursor_t SmtUpdate_get_proof_impl(struct SmtUpdateType *);
struct XudtDataType;
struct XudtDataVTable;
struct XudtDataVTable *GetXudtDataVTable(void);
struct XudtDataType make_XudtData(mol2_cursor_t *cur);
mol2_cursor_t XudtData_get_lock_impl(struct XudtDataType *);
struct BytesVecType XudtData_get_data_impl(struct XudtDataType *);

// ----definition-----------------
typedef struct ScriptVecVTable {
  uint32_t (*len)(struct ScriptVecType *);
  struct ScriptType (*get)(struct ScriptVecType *, uint32_t, bool *);
} ScriptVecVTable;
typedef struct ScriptVecType {
  mol2_cursor_t cur;
  ScriptVecVTable *t;
} ScriptVecType;

typedef struct ScriptVecOptVTable {
  bool (*is_none)(struct ScriptVecOptType *);
  bool (*is_some)(struct ScriptVecOptType *);
  struct ScriptVecType (*unwrap)(struct ScriptVecOptType *);
} ScriptVecOptVTable;
typedef struct ScriptVecOptType {
  mol2_cursor_t cur;
  ScriptVecOptVTable *t;
} ScriptVecOptType;

typedef struct XudtWitnessInputVTable {
  struct ScriptVecOptType (*raw_extension_data)(struct XudtWitnessInputType *);
  struct BytesVecType (*extension_data)(struct XudtWitnessInputType *);
} XudtWitnessInputVTable;
typedef struct XudtWitnessInputType {
  mol2_cursor_t cur;
  XudtWitnessInputVTable *t;
} XudtWitnessInputType;

typedef struct RCRuleVTable {
  mol2_cursor_t (*smt_root)(struct RCRuleType *);
  uint8_t (*flags)(struct RCRuleType *);
} RCRuleVTable;
typedef struct RCRuleType {
  mol2_cursor_t cur;
  RCRuleVTable *t;
} RCRuleType;

typedef struct RCCellVecVTable {
  uint32_t (*len)(struct RCCellVecType *);
  mol2_cursor_t (*get)(struct RCCellVecType *, uint32_t, bool *);
} RCCellVecVTable;
typedef struct RCCellVecType {
  mol2_cursor_t cur;
  RCCellVecVTable *t;
} RCCellVecType;

typedef struct RCDataVTable {
  uint32_t (*item_id)(struct RCDataType *);
  struct RCRuleType (*as_RCRule)(struct RCDataType *);
  struct RCCellVecType (*as_RCCellVec)(struct RCDataType *);
} RCDataVTable;
typedef struct RCDataType {
  mol2_cursor_t cur;
  RCDataVTable *t;
} RCDataType;

typedef struct SmtProofVTable {
  uint32_t (*len)(struct SmtProofType *);
  uint8_t (*get)(struct SmtProofType *, uint32_t, bool *);
} SmtProofVTable;
typedef struct SmtProofType {
  mol2_cursor_t cur;
  SmtProofVTable *t;
} SmtProofType;

typedef struct SmtProofVecVTable {
  uint32_t (*len)(struct SmtProofVecType *);
  mol2_cursor_t (*get)(struct SmtProofVecType *, uint32_t, bool *);
} SmtProofVecVTable;
typedef struct SmtProofVecType {
  mol2_cursor_t cur;
  SmtProofVecVTable *t;
} SmtProofVecType;

typedef struct SmtUpdateItemVTable {
  mol2_cursor_t (*key)(struct SmtUpdateItemType *);
  uint8_t (*values)(struct SmtUpdateItemType *);
} SmtUpdateItemVTable;
typedef struct SmtUpdateItemType {
  mol2_cursor_t cur;
  SmtUpdateItemVTable *t;
} SmtUpdateItemType;

typedef struct SmtUpdateVecVTable {
  uint32_t (*len)(struct SmtUpdateVecType *);
  struct SmtUpdateItemType (*get)(struct SmtUpdateVecType *, uint32_t, bool *);
} SmtUpdateVecVTable;
typedef struct SmtUpdateVecType {
  mol2_cursor_t cur;
  SmtUpdateVecVTable *t;
} SmtUpdateVecType;

typedef struct SmtUpdateVTable {
  struct SmtUpdateVecType (*update)(struct SmtUpdateType *);
  mol2_cursor_t (*proof)(struct SmtUpdateType *);
} SmtUpdateVTable;
typedef struct SmtUpdateType {
  mol2_cursor_t cur;
  SmtUpdateVTable *t;
} SmtUpdateType;

typedef struct XudtDataVTable {
  mol2_cursor_t (*lock)(struct XudtDataType *);
  struct BytesVecType (*data)(struct XudtDataType *);
} XudtDataVTable;
typedef struct XudtDataType {
  mol2_cursor_t cur;
  XudtDataVTable *t;
} XudtDataType;

#ifndef MOLECULEC_C2_DECLARATION_ONLY

// ----implementation-------------
struct ScriptVecType make_ScriptVec(mol2_cursor_t *cur) {
  ScriptVecType ret;
  ret.cur = *cur;
  ret.t = GetScriptVecVTable();
  return ret;
}
struct ScriptVecVTable *GetScriptVecVTable(void) {
  static ScriptVecVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = ScriptVec_len_impl;
  s_vtable.get = ScriptVec_get_impl;
  return &s_vtable;
}
uint32_t ScriptVec_len_impl(ScriptVecType *this) {
  return mol2_dynvec_length(&this->cur);
}
ScriptType ScriptVec_get_impl(ScriptVecType *this, uint32_t index,
                              bool *existing) {
  ScriptType ret = {0};
  mol2_cursor_res_t res = mol2_dynvec_slice_by_index(&this->cur, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret.cur = res.cur;
  ret.t = GetScriptVTable();
  return ret;
}
struct ScriptVecOptType make_ScriptVecOpt(mol2_cursor_t *cur) {
  ScriptVecOptType ret;
  ret.cur = *cur;
  ret.t = GetScriptVecOptVTable();
  return ret;
}
struct ScriptVecOptVTable *GetScriptVecOptVTable(void) {
  static ScriptVecOptVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.is_none = ScriptVecOpt_is_none_impl;
  s_vtable.is_some = ScriptVecOpt_is_some_impl;
  s_vtable.unwrap = ScriptVecOpt_unwrap_impl;
  return &s_vtable;
}
bool ScriptVecOpt_is_none_impl(ScriptVecOptType *this) {
  return mol2_option_is_none(&this->cur);
}
bool ScriptVecOpt_is_some_impl(ScriptVecOptType *this) {
  return !mol2_option_is_none(&this->cur);
}
ScriptVecType ScriptVecOpt_unwrap_impl(ScriptVecOptType *this) {
  ScriptVecType ret;
  mol2_cursor_t cur = this->cur;
  ret.cur = cur;
  ret.t = GetScriptVecVTable();
  return ret;
}
struct XudtWitnessInputType make_XudtWitnessInput(mol2_cursor_t *cur) {
  XudtWitnessInputType ret;
  ret.cur = *cur;
  ret.t = GetXudtWitnessInputVTable();
  return ret;
}
struct XudtWitnessInputVTable *GetXudtWitnessInputVTable(void) {
  static XudtWitnessInputVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.raw_extension_data = XudtWitnessInput_get_raw_extension_data_impl;
  s_vtable.extension_data = XudtWitnessInput_get_extension_data_impl;
  return &s_vtable;
}
ScriptVecOptType XudtWitnessInput_get_raw_extension_data_impl(
    XudtWitnessInputType *this) {
  ScriptVecOptType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 0);
  ret.cur = cur;
  ret.t = GetScriptVecOptVTable();
  return ret;
}
BytesVecType XudtWitnessInput_get_extension_data_impl(
    XudtWitnessInputType *this) {
  BytesVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 1);
  ret.cur = cur;
  ret.t = GetBytesVecVTable();
  return ret;
}
struct RCRuleType make_RCRule(mol2_cursor_t *cur) {
  RCRuleType ret;
  ret.cur = *cur;
  ret.t = GetRCRuleVTable();
  return ret;
}
struct RCRuleVTable *GetRCRuleVTable(void) {
  static RCRuleVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.smt_root = RCRule_get_smt_root_impl;
  s_vtable.flags = RCRule_get_flags_impl;
  return &s_vtable;
}
mol2_cursor_t RCRule_get_smt_root_impl(RCRuleType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_slice_by_offset(&this->cur, 0, 32);
  ret = convert_to_array(&ret2);
  return ret;
}
uint8_t RCRule_get_flags_impl(RCRuleType *this) {
  uint8_t ret;
  mol2_cursor_t ret2 = mol2_slice_by_offset(&this->cur, 32, 1);
  ret = convert_to_Uint8(&ret2);
  return ret;
}
struct RCCellVecType make_RCCellVec(mol2_cursor_t *cur) {
  RCCellVecType ret;
  ret.cur = *cur;
  ret.t = GetRCCellVecVTable();
  return ret;
}
struct RCCellVecVTable *GetRCCellVecVTable(void) {
  static RCCellVecVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = RCCellVec_len_impl;
  s_vtable.get = RCCellVec_get_impl;
  return &s_vtable;
}
uint32_t RCCellVec_len_impl(RCCellVecType *this) {
  return mol2_fixvec_length(&this->cur);
}
mol2_cursor_t RCCellVec_get_impl(RCCellVecType *this, uint32_t index,
                                 bool *existing) {
  mol2_cursor_t ret = {0};
  mol2_cursor_res_t res = mol2_fixvec_slice_by_index(&this->cur, 32, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret = convert_to_array(&res.cur);
  return ret;
}
struct RCDataType make_RCData(mol2_cursor_t *cur) {
  RCDataType ret;
  ret.cur = *cur;
  ret.t = GetRCDataVTable();
  return ret;
}
struct RCDataVTable *GetRCDataVTable(void) {
  static RCDataVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.item_id = RCData_item_id_impl;
  s_vtable.as_RCRule = RCData_as_RCRule_impl;
  s_vtable.as_RCCellVec = RCData_as_RCCellVec_impl;
  return &s_vtable;
}
uint32_t RCData_item_id_impl(RCDataType *this) {
  return mol2_unpack_number(&this->cur);
}
RCRuleType RCData_as_RCRule_impl(RCDataType *this) {
  RCRuleType ret;
  mol2_union_t u = mol2_union_unpack(&this->cur);
  ret.cur = u.cursor;
  ret.t = GetRCRuleVTable();
  return ret;
}
RCCellVecType RCData_as_RCCellVec_impl(RCDataType *this) {
  RCCellVecType ret;
  mol2_union_t u = mol2_union_unpack(&this->cur);
  ret.cur = u.cursor;
  ret.t = GetRCCellVecVTable();
  return ret;
}
struct SmtProofType make_SmtProof(mol2_cursor_t *cur) {
  SmtProofType ret;
  ret.cur = *cur;
  ret.t = GetSmtProofVTable();
  return ret;
}
struct SmtProofVTable *GetSmtProofVTable(void) {
  static SmtProofVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = SmtProof_len_impl;
  s_vtable.get = SmtProof_get_impl;
  return &s_vtable;
}
uint32_t SmtProof_len_impl(SmtProofType *this) {
  return mol2_fixvec_length(&this->cur);
}
uint8_t SmtProof_get_impl(SmtProofType *this, uint32_t index, bool *existing) {
  uint8_t ret = {0};
  mol2_cursor_res_t res = mol2_fixvec_slice_by_index(&this->cur, 1, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret = convert_to_Uint8(&res.cur);
  return ret;
}
struct SmtProofVecType make_SmtProofVec(mol2_cursor_t *cur) {
  SmtProofVecType ret;
  ret.cur = *cur;
  ret.t = GetSmtProofVecVTable();
  return ret;
}
struct SmtProofVecVTable *GetSmtProofVecVTable(void) {
  static SmtProofVecVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = SmtProofVec_len_impl;
  s_vtable.get = SmtProofVec_get_impl;
  return &s_vtable;
}
uint32_t SmtProofVec_len_impl(SmtProofVecType *this) {
  return mol2_dynvec_length(&this->cur);
}
mol2_cursor_t SmtProofVec_get_impl(SmtProofVecType *this, uint32_t index,
                                   bool *existing) {
  mol2_cursor_t ret = {0};
  mol2_cursor_res_t res = mol2_dynvec_slice_by_index(&this->cur, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  return convert_to_rawbytes(&res.cur);
}
struct SmtUpdateItemType make_SmtUpdateItem(mol2_cursor_t *cur) {
  SmtUpdateItemType ret;
  ret.cur = *cur;
  ret.t = GetSmtUpdateItemVTable();
  return ret;
}
struct SmtUpdateItemVTable *GetSmtUpdateItemVTable(void) {
  static SmtUpdateItemVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.key = SmtUpdateItem_get_key_impl;
  s_vtable.values = SmtUpdateItem_get_values_impl;
  return &s_vtable;
}
mol2_cursor_t SmtUpdateItem_get_key_impl(SmtUpdateItemType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_slice_by_offset(&this->cur, 0, 32);
  ret = convert_to_array(&ret2);
  return ret;
}
uint8_t SmtUpdateItem_get_values_impl(SmtUpdateItemType *this) {
  uint8_t ret;
  mol2_cursor_t ret2 = mol2_slice_by_offset(&this->cur, 32, 1);
  ret = convert_to_Uint8(&ret2);
  return ret;
}
struct SmtUpdateVecType make_SmtUpdateVec(mol2_cursor_t *cur) {
  SmtUpdateVecType ret;
  ret.cur = *cur;
  ret.t = GetSmtUpdateVecVTable();
  return ret;
}
struct SmtUpdateVecVTable *GetSmtUpdateVecVTable(void) {
  static SmtUpdateVecVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = SmtUpdateVec_len_impl;
  s_vtable.get = SmtUpdateVec_get_impl;
  return &s_vtable;
}
uint32_t SmtUpdateVec_len_impl(SmtUpdateVecType *this) {
  return mol2_fixvec_length(&this->cur);
}
SmtUpdateItemType SmtUpdateVec_get_impl(SmtUpdateVecType *this, uint32_t index,
                                        bool *existing) {
  SmtUpdateItemType ret = {0};
  mol2_cursor_res_t res = mol2_fixvec_slice_by_index(&this->cur, 33, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret.cur = res.cur;
  ret.t = GetSmtUpdateItemVTable();
  return ret;
}
struct SmtUpdateType make_SmtUpdate(mol2_cursor_t *cur) {
  SmtUpdateType ret;
  ret.cur = *cur;
  ret.t = GetSmtUpdateVTable();
  return ret;
}
struct SmtUpdateVTable *GetSmtUpdateVTable(void) {
  static SmtUpdateVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.update = SmtUpdate_get_update_impl;
  s_vtable.proof = SmtUpdate_get_proof_impl;
  return &s_vtable;
}
SmtUpdateVecType SmtUpdate_get_update_impl(SmtUpdateType *this) {
  SmtUpdateVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 0);
  ret.cur = cur;
  ret.t = GetSmtUpdateVecVTable();
  return ret;
}
mol2_cursor_t SmtUpdate_get_proof_impl(SmtUpdateType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 1);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
struct XudtDataType make_XudtData(mol2_cursor_t *cur) {
  XudtDataType ret;
  ret.cur = *cur;
  ret.t = GetXudtDataVTable();
  return ret;
}
struct XudtDataVTable *GetXudtDataVTable(void) {
  static XudtDataVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.lock = XudtData_get_lock_impl;
  s_vtable.data = XudtData_get_data_impl;
  return &s_vtable;
}
mol2_cursor_t XudtData_get_lock_impl(XudtDataType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
BytesVecType XudtData_get_data_impl(XudtDataType *this) {
  BytesVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 1);
  ret.cur = cur;
  ret.t = GetBytesVecVTable();
  return ret;
}
#endif  // MOLECULEC_C2_DECLARATION_ONLY

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // _BLOCKCHAIN_MOL2_API2_H_
