# Builds every variant in variants.mk, then one libFuzzer binary per target that
# links all variants side by side. `make cross` replays the corpus on the
# architectures in arches.mk instead.

SECP        ?= external/secp256k1
BUILD       ?= build
CORPUS      ?= corpus
# Compilers of the variants in variants.mk. CI sets GCC=gcc-14 CLANG=clang-19,
# the versions Guix builds releases with.
GCC         ?= gcc
CLANG       ?= clang
FUZZ_CC     ?= $(CLANG)
OBJCOPY     ?= objcopy
SMOKE_RUNS  ?= 1000
# Seconds per target for `make fuzz`, and extra libFuzzer flags such as -fork=N.
FUZZ_TIME   ?= 600
FUZZ_ARGS   ?=
# Boundary values such as p, n and n/2 that the fuzzer rarely builds on its
# own; empty to fuzz without.
FUZZ_DICT   ?= fuzz.dict
DOCKER      ?= docker
CROSS_IMAGE ?= diffsecp-cross
# `make coverage` builds with this variant's flags minus its sanitizers, and
# needs the LLVM tools of CLANG's version.
COVERAGE_VARIANT ?= guide
LLVM_PROFDATA    ?= llvm-profdata
LLVM_COV         ?= llvm-cov

TARGETS := ecdsa schnorrsig field scalar group keys ellswift recovery musig silentpayments

# libsecp's own build defaults (CMake and autotools): -O2 from RelWithDebInfo,
# ECMULT_WINDOW_SIZE=15 and ECMULT_GEN_KB=86. Its x86_64 asm is also on by
# default wherever it compiles. Compiling src/secp256k1.c without these, as the
# guide variant does, gives a 22 kB signing table instead.
LIBSECP_DEFAULT_CFLAGS := -O2 -DECMULT_WINDOW_SIZE=15 -DCOMB_BLOCKS=43 -DCOMB_TEETH=6
LIBSECP_ASM_X86_64     := -DUSE_ASM_X86_64

include variants.mk
include arches.mk

WARNINGS := -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -Wundef -Wcast-align \
            -Wno-unused-function -Wno-overlength-strings
COMMON_CFLAGS := -std=c11 -g $(WARNINGS)

# The reference build with one transcript byte flipped (src/variant.c). It is
# linked only into the selftest fuzzers, which must report it as a divergence.
REFERENCE       := $(firstword $(VARIANTS))
selftest_CC     := $($(REFERENCE)_CC)
selftest_CFLAGS := $($(REFERENCE)_CFLAGS) -DDIFFSECP_SELFTEST

# The same for `make cross`: the reference architecture with one transcript byte
# flipped, whose digests must differ from the reference's in every target.
CROSS_REFERENCE       := $(firstword $(ARCHES))
cross_selftest_CC     := $($(CROSS_REFERENCE)_CC)
cross_selftest_CFLAGS := $($(CROSS_REFERENCE)_CFLAGS) -DDIFFSECP_SELFTEST
cross_selftest_RUN    := $($(CROSS_REFERENCE)_RUN)
cross_selftest_EXE    := $($(CROSS_REFERENCE)_EXE)

VARIANT_OBJS  := $(VARIANTS:%=$(BUILD)/variants/%.o)
SELFTEST_OBJS := $(VARIANT_OBJS) $(BUILD)/variants/selftest.o
FUZZERS       := $(TARGETS:%=$(BUILD)/fuzz_%)
FUZZ_COMPILE   = $(FUZZ_CC) $(COMMON_CFLAGS) -O1 -fsanitize=fuzzer,address,undefined \
                 -fno-sanitize-recover=all
VARIANTS_H          := \#define DIFFSECP_VARIANTS(X) $(foreach v,$(VARIANTS),X($(v)))
SELFTEST_VARIANTS_H := \#define DIFFSECP_VARIANTS(X) $(foreach v,$(VARIANTS) selftest,X($(v)))

.PHONY: all check $(TARGETS:%=check-%) selftest $(TARGETS:%=selftest-%) \
        fuzz $(TARGETS:%=fuzz-%) merge $(TARGETS:%=merge-%) minimize $(TARGETS:%=minimize-%) \
        coverage readme-coverage cross cross-selftest cross-image docker-cross docker-cross-selftest clean FORCE
.DELETE_ON_ERROR:

all: $(FUZZERS)

# *.flags files hold the exact compile command and are rewritten only when it
# changes, so overriding a compiler or flags on the command line rebuilds.
#
# Localizing libsecp's symbols (secp256k1_*, and ecdsa_* from contrib) leaves
# diffsecp_variant_<name> as the only global definition. A new libsecp global
# outside these patterns shows up as a duplicate symbol at link time.
define VARIANT_RULE
$(1)_SECP ?= $$(SECP)
$(1)_COMPILE = $$($(1)_CC) $$(COMMON_CFLAGS) $$($(1)_CFLAGS) -I$$($(1)_SECP) -I$$($(1)_SECP)/include \
               -DDIFFSECP_VARIANT=$(1)

$(BUILD)/variants/$(1).flags: FORCE | $(BUILD)/variants
	@echo '$$($(1)_COMPILE)' | cmp -s - $$@ || echo '$$($(1)_COMPILE)' > $$@

$(BUILD)/variants/$(1).o: src/variant.c $(BUILD)/variants/$(1).flags
	$$($(1)_COMPILE) -MMD -MP -MT $$@ -MF $$(@:.o=.d) -c $$< -o $$(@:.o=.raw.o)
	$$(OBJCOPY) --wildcard -L 'secp256k1_*' -L 'ecdsa_*' -L '__odr_asan_gen_*' $$(@:.o=.raw.o) $$@
endef
$(foreach v,$(VARIANTS) selftest,$(eval $(call VARIANT_RULE,$(v))))

$(BUILD)/variants.h: FORCE | $(BUILD)
	@echo '$(VARIANTS_H)' | cmp -s - $@ || echo '$(VARIANTS_H)' > $@

$(BUILD)/selftest/variants.h: FORCE | $(BUILD)/selftest
	@echo '$(SELFTEST_VARIANTS_H)' | cmp -s - $@ || echo '$(SELFTEST_VARIANTS_H)' > $@

$(BUILD)/fuzz.flags: FORCE | $(BUILD)
	@echo '$(FUZZ_COMPILE)' | cmp -s - $@ || echo '$(FUZZ_COMPILE)' > $@

$(BUILD)/fuzz_%: src/fuzz.c src/diffsecp.h $(BUILD)/variants.h $(BUILD)/fuzz.flags $(VARIANT_OBJS)
	$(FUZZ_COMPILE) -I$(BUILD) -DDIFFSECP_TARGET=$* $< $(VARIANT_OBJS) -o $@

$(BUILD)/selftest/fuzz_%: src/fuzz.c src/diffsecp.h $(BUILD)/selftest/variants.h $(BUILD)/fuzz.flags $(SELFTEST_OBJS)
	$(FUZZ_COMPILE) -I$(BUILD)/selftest -DDIFFSECP_TARGET=$* $< $(SELFTEST_OBJS) -o $@

# Replays the corpus through every variant, then fuzzes briefly from it: catches
# build breakage, harness contract violations and divergences on known inputs.
# The corpus always replays in full; SMOKE_RUNS only bounds the fuzzing after
# it. New inputs go to the build tree so the committed corpus stays untouched.
check: selftest $(TARGETS:%=check-%)

$(TARGETS:%=check-%): check-%: $(BUILD)/fuzz_% | $(CORPUS)/%
	@log=$(BUILD)/$@.log; new=$(BUILD)/$@.new; \
	rm -rf $$new && mkdir -p $$new; \
	if ! $< -runs=$(SMOKE_RUNS) -seed=1 $$new $(CORPUS)/$* > $$log 2>&1; then \
		cat $$log; echo "FAIL $*"; exit 1; \
	fi; \
	echo "ok   $*: $$(tail -n 1 $$log)"

# Proves a divergence is reported: fails if the harness stops comparing every
# byte of every variant, or if per-variant flags stop reaching the compiler.
selftest: $(TARGETS:%=selftest-%)

$(TARGETS:%=selftest-%): selftest-%: $(BUILD)/selftest/fuzz_%
	@log=$(BUILD)/$@.log; \
	if $< -runs=$(SMOKE_RUNS) -seed=1 -artifact_prefix=$(BUILD)/selftest/ > $$log 2>&1 || \
	   ! grep -q 'diverges between $(REFERENCE) and selftest' $$log; then \
		cat $$log; echo "FAIL $@: divergence from selftest not reported"; exit 1; \
	fi; \
	echo "ok   $@: $$(grep -m 1 'diverges' $$log)"

# A missing corpus is seeded with a short fuzzing run. Only missing ones depend
# on their fuzzer, so an existing corpus needs no clang, and the fuzzers are
# built once in this make rather than racing in one sub-make per target.
MISSING_CORPORA := $(filter-out $(wildcard $(TARGETS:%=$(CORPUS)/%)),$(TARGETS:%=$(CORPUS)/%))

$(MISSING_CORPORA): $(CORPUS)/%: $(BUILD)/fuzz_%
	mkdir -p $@
	$< -runs=$(SMOKE_RUNS) -seed=1 $@ > $(BUILD)/seed_$*.log 2>&1

# Long runs from the corpus; `make -j fuzz` runs every target at once. New
# inputs land in $(BUILD)/new/<target> and reproducers in $(BUILD)/crashes.
fuzz: $(TARGETS:%=fuzz-%)

$(TARGETS:%=fuzz-%): fuzz-%: $(BUILD)/fuzz_% | $(CORPUS)/%
	@log=$(BUILD)/$@.log; mkdir -p $(BUILD)/new/$* $(BUILD)/crashes; \
	if ! $< -max_total_time=$(FUZZ_TIME) -artifact_prefix=$(BUILD)/crashes/$*- \
	     $(if $(FUZZ_DICT),-dict=$(FUZZ_DICT)) $(FUZZ_ARGS) $(BUILD)/new/$* $(CORPUS)/$* > $$log 2>&1; then \
		tail -n 40 $$log; echo "FAIL $*: see $$log and $(BUILD)/crashes"; exit 1; \
	fi; \
	echo "ok   $*: $$(ls $(BUILD)/new/$* | wc -l) new inputs, $$(grep -E '^#[0-9]+' $$log | tail -n 1)"

# Adds the new inputs that raise coverage to the corpus. Merging runs each input
# again and skips any that crash, so a divergence never lands in the corpus.
merge: $(TARGETS:%=merge-%)

$(TARGETS:%=merge-%): merge-%: $(BUILD)/fuzz_% | $(CORPUS)/%
	@log=$(BUILD)/$@.log; before=$$(ls $(CORPUS)/$* | wc -l); mkdir -p $(BUILD)/new/$*; \
	$< -merge=1 $(CORPUS)/$* $(BUILD)/new/$* > $$log 2>&1 || { cat $$log; exit 1; }; \
	echo "ok   $*: $$(( $$(ls $(CORPUS)/$* | wc -l) - before )) inputs added"

# Rebuilds each corpus from scratch with only the inputs its coverage needs, for
# when a target or libsecp changed what the old inputs reach.
minimize: $(TARGETS:%=minimize-%)

$(TARGETS:%=minimize-%): minimize-%: $(BUILD)/fuzz_% | $(CORPUS)/%
	@log=$(BUILD)/$@.log; tmp=$(BUILD)/minimize/$*; before=$$(ls $(CORPUS)/$* | wc -l); \
	rm -rf $$tmp && mkdir -p $$tmp; \
	$< -merge=1 $$tmp $(CORPUS)/$* > $$log 2>&1 || { cat $$log; exit 1; }; \
	rm -rf $(CORPUS)/$* && mv $$tmp $(CORPUS)/$*; \
	echo "ok   $*: $$before -> $$(ls $(CORPUS)/$* | wc -l) inputs"

# Source coverage of the corpus replayed through one variant's flags, without
# its sanitizers: what the fuzzer reaches. The report goes to $(BUILD)/coverage.
COVERAGE_COMPILE = $(CLANG) $(COMMON_CFLAGS) $(filter-out $(SANITIZE_CFLAGS),$($(COVERAGE_VARIANT)_CFLAGS)) \
                   -fprofile-instr-generate -fcoverage-mapping -I$($(COVERAGE_VARIANT)_SECP) \
                   -I$($(COVERAGE_VARIANT)_SECP)/include -DDIFFSECP_VARIANT=coverage

$(BUILD)/coverage/flags: FORCE | $(BUILD)/coverage
	@echo '$(COVERAGE_COMPILE)' | cmp -s - $@ || echo '$(COVERAGE_COMPILE)' > $@

$(BUILD)/coverage/%.o: src/%.c $(BUILD)/coverage/flags
	$(COVERAGE_COMPILE) -MMD -MP -MT $@ -MF $(@:.o=.d) -c $< -o $@

$(BUILD)/coverage/replay: $(BUILD)/coverage/variant.o $(BUILD)/coverage/replay.o
	$(CLANG) -fprofile-instr-generate $^ -o $@

coverage: $(BUILD)/coverage/replay | $(TARGETS:%=$(CORPUS)/%)
	@rm -f $(BUILD)/coverage/*.profraw
	@for t in $(TARGETS); do \
		find $(CORPUS)/$$t -type f | LLVM_PROFILE_FILE=$(BUILD)/coverage/$$t.profraw $< $$t > /dev/null || exit 1; \
	done
	@$(LLVM_PROFDATA) merge -sparse $(BUILD)/coverage/*.profraw -o $(BUILD)/coverage/corpus.profdata
	@$(LLVM_COV) show $< -instr-profile=$(BUILD)/coverage/corpus.profdata -format=html \
		-output-dir=$(BUILD)/coverage/html
	@$(LLVM_COV) report $< -instr-profile=$(BUILD)/coverage/corpus.profdata > $(BUILD)/coverage/report.txt
	@awk '$$1 == "TOTAL" { print "coverage: " $$10 " of lines, " $$13 " of branches, " $$7 " of functions" }' \
		$(BUILD)/coverage/report.txt
	@echo "per file: $(BUILD)/coverage/report.txt, lines: $(BUILD)/coverage/html/index.html"

# Rewrites the coverage table at the bottom of README.md from a fresh report.
readme-coverage: coverage
	@ci/readme-coverage.sh $(BUILD)/coverage/report.txt $($(COVERAGE_VARIANT)_SECP) README.md

# One static replay binary per architecture, and the digest of every corpus
# input on it. Digests are always regenerated since the corpus changes freely.
define ARCH_RULE
cross_$(1)_COMPILE = $$($(1)_CC) $$(COMMON_CFLAGS) $$($(1)_CFLAGS) -I$$(SECP) -I$$(SECP)/include \
                     -DDIFFSECP_VARIANT=$(1)

$(BUILD)/cross/$(1):
	mkdir -p $$@

$(BUILD)/cross/$(1)/flags: FORCE | $(BUILD)/cross/$(1)
	@echo '$$(cross_$(1)_COMPILE)' | cmp -s - $$@ || echo '$$(cross_$(1)_COMPILE)' > $$@

$(BUILD)/cross/$(1)/%.o: src/%.c $(BUILD)/cross/$(1)/flags
	$$(cross_$(1)_COMPILE) -MMD -MP -MT $$@ -MF $$(@:.o=.d) -c $$< -o $$@

$(BUILD)/cross/$(1)/replay$$($(1)_EXE): $(BUILD)/cross/$(1)/variant.o $(BUILD)/cross/$(1)/replay.o
	$$($(1)_CC) -static $$^ -o $$@

$(BUILD)/cross/$(1)/digests: $(BUILD)/cross/$(1)/replay$$($(1)_EXE) FORCE | $(TARGETS:%=$(CORPUS)/%)
	@for t in $(TARGETS); do \
		find $(CORPUS)/$$$$t -type f | LC_ALL=C sort | $$($(1)_RUN) $$< $$$$t || exit 1; \
	done > $$@.tmp
	@mv $$@.tmp $$@

-include $(BUILD)/cross/$(1)/variant.d $(BUILD)/cross/$(1)/replay.d
endef
$(foreach a,$(ARCHES) cross_selftest,$(eval $(call ARCH_RULE,$(a))))

CROSS_REF := $(BUILD)/cross/$(CROSS_REFERENCE)/digests

cross: cross-selftest $(ARCHES:%=$(BUILD)/cross/%/digests)
	@status=0; \
	for a in $(wordlist 2,$(words $(ARCHES)),$(ARCHES)); do \
		d=$(BUILD)/cross/$$a/digests; \
		if cmp -s $(CROSS_REF) $$d; then \
			echo "ok   $$a: $$(wc -l < $$d) inputs match $(CROSS_REFERENCE)"; \
		else \
			echo "DIVERGE $$a (< $(CROSS_REFERENCE), > $$a):"; diff $(CROSS_REF) $$d | head -n 20; status=1; \
		fi; \
	done; \
	exit $$status

# Proves the digests expose a divergence: fails if they miss a transcript byte,
# a target or its corpus drops out of the replay, or per-architecture flags stop
# reaching the compiler.
cross-selftest: $(CROSS_REF) $(BUILD)/cross/cross_selftest/digests
	@diff $^ > $(BUILD)/cross/selftest.diff; \
	for t in $(TARGETS); do \
		if ! grep -q "^> $$t " $(BUILD)/cross/selftest.diff; then \
			echo "FAIL cross-selftest: divergence in $$t not reported"; exit 1; \
		fi; \
	done; \
	echo "ok   cross-selftest: $$(grep -c '^>' $(BUILD)/cross/selftest.diff) inputs diverge from $(CROSS_REFERENCE)"

# `make docker-cross` and `make docker-cross-selftest` run their goal in a
# container with the cross toolchains, qemu-user and wine. The corpus is seeded
# on the host first, so the image needs no libFuzzer.
DOCKER_GOALS := cross cross-selftest

cross-image:
	$(DOCKER) build -t $(CROSS_IMAGE) ci

# HOME lives in the build tree because wine only creates its prefix in a
# directory the user owns, and keeping it there skips wine's setup next time.
$(DOCKER_GOALS:%=docker-%): docker-%: cross-image | $(TARGETS:%=$(CORPUS)/%)
	mkdir -p $(BUILD)/docker/home
	$(DOCKER) run --rm -u $$(id -u):$$(id -g) -e HOME=/src/$(BUILD)/docker/home -e WINEDEBUG=-all \
		-v $(CURDIR):/src -w /src $(CROSS_IMAGE) \
		make -j$$(nproc) BUILD=$(BUILD)/docker CORPUS=$(CORPUS) $*

$(BUILD) $(BUILD)/variants $(BUILD)/selftest $(BUILD)/coverage:
	mkdir -p $@

clean:
	rm -rf $(BUILD)

-include $(SELFTEST_OBJS:.o=.d) $(BUILD)/coverage/variant.d $(BUILD)/coverage/replay.d
