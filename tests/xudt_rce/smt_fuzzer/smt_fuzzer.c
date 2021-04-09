#include "smt_func.h"


int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  smt_func(data, size);
  return 0;
}
