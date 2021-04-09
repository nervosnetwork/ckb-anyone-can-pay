#include <stddef.h>
#include <stdint.h>

__attribute__((visibility("default"))) int validate(int is_owner_mode,
                                                    size_t extension_index,
                                                    const uint8_t* args,
                                                    size_t args_len) {
  return 1;
}
