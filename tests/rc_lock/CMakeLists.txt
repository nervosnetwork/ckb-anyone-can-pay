cmake_minimum_required(VERSION 3.12)
project(rc_lock_simulator C)

set(CMAKE_C_STANDARD 11)
# uncomment it for sanitize
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined")

# uncomment it for coverage test
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
#add_definitions(-DCKB_COVERAGE)
#add_definitions(-Wno-incompatible-pointer-types)

#add_definitions(-DCKB_SIMULATOR)
add_definitions(-D__SHARED_LIBRARY__)
add_definitions(-DCKB_DECLARATION_ONLY)
add_definitions(-DCKB_USE_SIM)

include_directories(../../tests/rc_lock)
include_directories(../../deps/ckb-c-stdlib-add-identity)
# include_directories(deps/ckb-c-stdlib/libc)
# on simulator, we don't use own "libc"
include_directories(../../deps/secp256k1/src)
include_directories(../../deps/secp256k1)
include_directories(../../deps/ckb-c-stdlib-add-identity/molecule)
include_directories(../../c)
include_directories(../../build)

add_executable(rc_lock_simulator ../../tests/rc_lock/rc_lock_sim.c)
target_compile_definitions(rc_lock_simulator PUBLIC -D_FILE_OFFSET_BITS=64 -DCKB_DECLARATION_ONLY)
target_include_directories(rc_lock_simulator PUBLIC deps/ckb-c-stdlib-add-identity/libc)
