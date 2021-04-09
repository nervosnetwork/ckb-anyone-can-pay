# Testing Results for XUDT/RCE

Following [ckb-contract-guidelines](https://github.com/nervosnetwork/ckb-contract-guidelines)


### Rule 1: 100% test coverage
Uncomment the following in CMakeLists.txt to enable:
```cmake
# uncomment it for coverage test
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
#add_definitions(-DCKB_COVERAGE)
```
Then use ```tests/xudt_rce/run.sh``` to run the whole test case and get coverage results.

we have rce.h with 98% coverage and xudt_rce.c with 96% coverage. Some of code is hard to covered.
for example, in rce.h, 
```C
} else {
CHECK2(false, ERROR_INVALID_MOL_FORMAT);
}
```
It failed immediately when the data format is malformed.

In xudt_rce.c:
```C
  err = ckb_checked_load_witness(ptr, &output_len, offset, arg[0], arg[1]);
  if (err != 0) {
    return 0;
  }
```
They are also about the malformed data. They only have 1 or 2 lines of code, 
which can be easily inspected.

### Rule 2: Multiple execution environment for tests

#### Normal CKB-VM as used in CKB

require Rust test cases

#### At least 20 runs of CKB-VM running in chaos mode

require Rust test cases


#### Native x64 environment for gathering test coverage
See rule 1.

#### LLVM Undefined Behavior Sanitizer
See below.

#### LLVM Address Sanitizer
Uncomment the following in CMakeLists.txt to enable:
```
# uncomment it for sanitize
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined")
```

There 2 issues detected:

1. An overflow issue is detected and it's intended:

```
typedef struct mol2_data_source_t {
  // function "read" might have more arguments
  uintptr_t args[4];
  mol2_source_t read;
  // start point of the cache
  // if [offset, size) is in [start_point, start_point+cache_size), it returns
  // memory in cache directly otherwise, it will try to load first (like cache
  // miss)
  uint32_t start_point;
  uint32_t cache_size;
  // it's normally same as MAX_CACHE_SIZE.
  // modify it for testing purpose
  uint32_t max_cache_size;
  // sanitizer will report: Index ??? out of bounds for type 'uint8_t [64]'
  // it's safe: because we use variable length structure/array.
  uint8_t cache[MAX_CACHE_SIZE];
} mol2_data_source_t;

``` 

The sanitizer will report: Index ??? out of bounds for type `````'uint8_t [64]`````, it's intended.

2. The warning of misaligned address
   
```
report error:
Load of misaligned address ??? for type 'uint32_t' (aka 'unsigned int'), which requires 4 byte alignment

uint32_t* flag_ptr = (uint32_t*)(args_bytes_seg.ptr + BLAKE2B_BLOCK_SIZE);
```
don't have good solution to avoid.

### Fuzzing test on smt
It only works for "ckb_smt.h".

```bash
cd smt_fuzzer
make start-fuzzer
```

Get code coverage by:
```bash
make report
make show
```

Currently there is no issue (overflow, out of bounds) found. 
It is also served as an excellent coverage test.

