OS = Unknown
ifneq ($(shell uname -a | grep -i Darwin),)
	OS = MacOS
endif
ifneq ($(shell uname -a | grep -i Linux),)
	OS = Linux
endif
ifeq ($(OS),Unknown)
	echo "error: unsupported OS"; exit 1
endif

NPROC?=4
CC=clang
LLVM_PROFDATA=llvm-profdata
LLVM_COV=llvm-cov

CORPUS_DIR=corpus

FUZZER_FLAGS=-g -O1 -fsanitize=fuzzer,address,undefined -I ../../../c -I ../../../deps/ckb-c-stdlib-simulator-only2

COVERAGE_DIR=coverage
COVERAGE_FLAGS=-fprofile-instr-generate -fcoverage-mapping -I ../../../c -I ../../../deps/ckb-c-stdlib-simulator-only2

ifeq ($(OS),MacOS)
	COVERAGE_FLAGS+=-Wl,-U,_LLVMFuzzerCustomMutator -Wl,-U,_LLVMFuzzerInitialize
endif

EXTERNAL_HEADERS=../../../deps/ckb-c-stdlib-simulator-only2/ckb_smt.h

all: fuzzer coverage

show: $(COVERAGE_DIR)/fuzzer.profdata
	$(LLVM_COV) show --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata smt_coverage

report: $(COVERAGE_DIR)/fuzzer.profdata coverage $(EXTERNAL_HEADERS)
	$(LLVM_COV) report --show-functions --instr-profile=$(COVERAGE_DIR)/fuzzer.profdata smt_coverage $(EXTERNAL_HEADERS)

fuzzer: $(EXTERNAL_HEADERS)
	clang  $(FUZZER_FLAGS) smt_fuzzer.c -o smt_fuzzer

coverage: $(EXTERNAL_HEADERS)
	clang $(COVERAGE_FLAGS) smt_coverage.c smt_fuzzer.c -o smt_coverage

start-fuzzer: fuzzer
	./smt_fuzzer -max_len=800000 -workers=$(NPROC) -jobs=$(NPROC) corpus

start-fuzzer2: fuzzer
	./smt_fuzzer -max_len=800000 corpus

clean:
	rm -rf smt_fuzzer smt_coverage smt_fuzzer.dSYM

#%.h:
#	ln -s $(CURDIR)/../$@ $(CURDIR)/$@

%.profraw: coverage
	LLVM_PROFILE_FILE=$@ ./smt_coverage $(CORPUS_DIR)/*

%.profdata: %.profraw
	$(LLVM_PROFDATA) merge --sparse $< -o $@

.PHONY: all fuzzer coverage report

.PRECIOUS: $(COVERAGE_DIR)/fuzzer.profraw $(COVERAGE_DIR)/fuzzer.profdata
