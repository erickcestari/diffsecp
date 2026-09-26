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
PYTHON      ?= python3
SMOKE_RUNS  ?= 1000
# Seconds per target for `make fuzz`, and extra libFuzzer flags such as -fork=N.
FUZZ_TIME   ?= 600
FUZZ_ARGS   ?=
# Dictionaries of boundary values (p, n, n/2, hard inversion inputs...) the
# fuzzer rarely builds on its own: each target gets common.dict plus its own
# <target>.dict. Empty to fuzz without.
FUZZ_DICT   ?= dict
# Targets fuzzed with libFuzzer's value profile, which scores how close each
# compare's operands are. It finds value bugs in the arithmetic targets, whose
# coverage it leaves unchanged, but bloats the corpus and costs coverage elsewhere.
FUZZ_VALUE_PROFILE ?= field scalar
# `make fuzz ORACLE_ARCHES='arm ppc64'` also runs a fraction ORACLE_RATE of the
# inputs on those architectures' replay builds in ORACLE_DIR, from `make
# cross-replays` (or `make docker-cross-replays` with
# ORACLE_DIR=$(BUILD)/docker/cross).
ORACLE_ARCHES ?=
ORACLE_DIR    ?= $(BUILD)/cross
ORACLE_RATE   ?= 0.01
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
MUTANT_OBJS   := $(MUTANT_BUILDS:%=$(BUILD)/variants/%.o)
MUTANTS_H     := $(BUILD)/mutants/mutants.h
FUZZERS       := $(TARGETS:%=$(BUILD)/fuzz_%)
FUZZ_COMPILE   = $(FUZZ_CC) $(COMMON_CFLAGS) -O1 -fsanitize=fuzzer,address,undefined \
                 -fno-sanitize-recover=all
# Merging and minimizing need the flag too, or they drop what value profile found.
value_profile  = $(if $(filter $(1),$(FUZZ_VALUE_PROFILE)),-use_value_profile=1)
# The oracle's environment for target $(1) (src/oracle.h): one replay process per
# architecture in ORACLE_ARCHES, under its emulator. Input files go in
# $(BUILD)/oracle, relative so wine resolves them too.
oracle_env     = $(if $(ORACLE_ARCHES),DIFFSECP_ORACLE_DIR=$(BUILD)/oracle DIFFSECP_ORACLE_RATE=$(ORACLE_RATE) \
                 DIFFSECP_ORACLE='$(foreach a,$(ORACLE_ARCHES),$(a)=$(strip $($(a)_RUN) $(ORACLE_DIR)/$(a)/replay$($(a)_EXE)) $(1);)')
VARIANTS_H          := \#define DIFFSECP_VARIANTS(X) $(foreach v,$(VARIANTS),X($(v)))
SELFTEST_VARIANTS_H := \#define DIFFSECP_VARIANTS(X) $(foreach v,$(VARIANTS) selftest,X($(v)))
MUTANT_BUILDS_H     := \#define DIFFSECP_MUTANT_BUILDS(X) $(foreach v,$(MUTANT_BUILDS),X($(v)))

.PHONY: all check $(TARGETS:%=check-%) selftest $(TARGETS:%=selftest-%) \
        fuzz $(TARGETS:%=fuzz-%) merge $(TARGETS:%=merge-%) minimize $(TARGETS:%=minimize-%) \
        mutation-score oracle-selftest coverage readme-coverage cross cross-selftest cross-replays \
        cross-image docker-cross docker-cross-selftest docker-cross-replays clean FORCE
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
$(foreach v,$(VARIANTS) selftest $(MUTANT_BUILDS),$(eval $(call VARIANT_RULE,$(v))))

# The mutant schemata's libsecp tree, and mutants.h naming its mutants for
# src/fuzz.c. gen.py rewrites only files whose content changes.
$(MUTANTS_H): FORCE | $(BUILD)
	@$(PYTHON) mutants/gen.py $(SECP) $(BUILD)/mutants

$(MUTANT_OBJS): $(MUTANTS_H)

$(BUILD)/variants.h: FORCE | $(BUILD)
	@printf '%s\n' '$(VARIANTS_H)' '$(MUTANT_BUILDS_H)' | cmp -s - $@ || \
		printf '%s\n' '$(VARIANTS_H)' '$(MUTANT_BUILDS_H)' > $@

$(BUILD)/selftest/variants.h: FORCE | $(BUILD)/selftest
	@printf '%s\n' '$(SELFTEST_VARIANTS_H)' '$(MUTANT_BUILDS_H)' | cmp -s - $@ || \
		printf '%s\n' '$(SELFTEST_VARIANTS_H)' '$(MUTANT_BUILDS_H)' > $@

$(BUILD)/fuzz.flags: FORCE | $(BUILD)
	@echo '$(FUZZ_COMPILE)' | cmp -s - $@ || echo '$(FUZZ_COMPILE)' > $@

$(BUILD)/fuzz_%: src/fuzz.c src/diffsecp.h $(BUILD)/variants.h $(MUTANTS_H) $(BUILD)/fuzz.flags \
                 $(VARIANT_OBJS) $(MUTANT_OBJS)
	$(FUZZ_COMPILE) -I$(BUILD) -I$(BUILD)/mutants -DDIFFSECP_TARGET=$* $< $(VARIANT_OBJS) $(MUTANT_OBJS) -o $@

$(BUILD)/selftest/fuzz_%: src/fuzz.c src/diffsecp.h $(BUILD)/selftest/variants.h $(MUTANTS_H) $(BUILD)/fuzz.flags \
                          $(SELFTEST_OBJS) $(MUTANT_OBJS)
	$(FUZZ_COMPILE) -I$(BUILD)/selftest -I$(BUILD)/mutants -DDIFFSECP_TARGET=$* $< $(SELFTEST_OBJS) $(MUTANT_OBJS) -o $@

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
# ORACLE_ARCHES also compares inputs with other architectures.
fuzz: $(TARGETS:%=fuzz-%)

$(TARGETS:%=fuzz-%): fuzz-%: $(BUILD)/fuzz_% | $(CORPUS)/%
	@log=$(BUILD)/$@.log; mkdir -p $(BUILD)/new/$* $(BUILD)/crashes; \
	$(if $(FUZZ_DICT),cat $(FUZZ_DICT)/common.dict $(wildcard $(FUZZ_DICT)/$*.dict) > $(BUILD)/$*.dict;) \
	if ! $(call oracle_env,$*) $< -max_total_time=$(FUZZ_TIME) -artifact_prefix=$(BUILD)/crashes/$*- \
	     $(if $(FUZZ_DICT),-dict=$(BUILD)/$*.dict) $(call value_profile,$*) \
	     $(FUZZ_ARGS) $(BUILD)/new/$* $(CORPUS)/$* > $$log 2>&1; then \
		tail -n 40 $$log; echo "FAIL $*: see $$log and $(BUILD)/crashes"; exit 1; \
	fi; \
	echo "ok   $*: $$(ls $(BUILD)/new/$* | wc -l) new inputs, $$(grep -E '^#[0-9]+' $$log | tail -n 1)"

# Adds the new inputs that raise coverage to the corpus. Merging runs each input
# again and skips any that crash, so a divergence never lands in the corpus.
merge: $(TARGETS:%=merge-%)

$(TARGETS:%=merge-%): merge-%: $(BUILD)/fuzz_% | $(CORPUS)/%
	@log=$(BUILD)/$@.log; before=$$(ls $(CORPUS)/$* | wc -l); mkdir -p $(BUILD)/new/$*; \
	$< -merge=1 $(call value_profile,$*) $(CORPUS)/$* $(BUILD)/new/$* > $$log 2>&1 || { cat $$log; exit 1; }; \
	echo "ok   $*: $$(( $$(ls $(CORPUS)/$* | wc -l) - before )) inputs added"

# Rebuilds each corpus from scratch with only the inputs its coverage needs, for
# when a target or libsecp changed what the old inputs reach.
minimize: $(TARGETS:%=minimize-%)

$(TARGETS:%=minimize-%): minimize-%: $(BUILD)/fuzz_% | $(CORPUS)/%
	@log=$(BUILD)/$@.log; tmp=$(BUILD)/minimize/$*; before=$$(ls $(CORPUS)/$* | wc -l); \
	rm -rf $$tmp && mkdir -p $$tmp; \
	$< -merge=1 $(call value_profile,$*) $$tmp $(CORPUS)/$* > $$log 2>&1 || { cat $$log; exit 1; }; \
	rm -rf $(CORPUS)/$* && mv $$tmp $(CORPUS)/$*; \
	echo "ok   $*: $$before -> $$(ls $(CORPUS)/$* | wc -l) inputs"

# Which mutants in mutants/mutants.txt the corpus exposes, over every target: a
# mutant is killed once any target's transcript shows it. Lists the rest as
# masked (triggered, but no transcript showed it) or missed (never triggered),
# and keeps the summary line for the README.
mutation-score: $(FUZZERS) | $(TARGETS:%=$(CORPUS)/%)
	@for t in $(TARGETS); do \
		DIFFSECP_MUTANTS=report $(BUILD)/fuzz_$$t -runs=0 $(CORPUS)/$$t 2> $(BUILD)/mutation-score-$$t.log || \
			{ cat $(BUILD)/mutation-score-$$t.log; exit 1; }; \
	done > $(BUILD)/mutation-score.txt
	@awk -v summary=$(BUILD)/mutation-score.summary \
	     '{ rank = $$3 == "killed" ? 2 : $$3 == "masked" ? 1 : 0; \
	        if (!($$2 in best) || rank > best[$$2]) { best[$$2] = rank; status[$$2] = $$3 } \
	        name[$$2] = substr($$0, index($$0, $$4)) } \
	      END { for (k = 0; k in best; k++) { n++; count[status[k]]++; \
	                if (status[k] != "killed") print status[k] ": " name[k] } \
	            printf "Mutation score: %d of %d mutants killed, %d masked, %d missed.\n", \
	                   count["killed"], n, count["masked"], count["missed"] > summary }' \
		$(BUILD)/mutation-score.txt
	@cat $(BUILD)/mutation-score.summary

# Proves the oracle reports a divergence: the reference architecture's replay
# with one transcript byte flipped, cross_selftest, must differ on the corpus.
# It runs natively, so no emulator is needed.
oracle-selftest: ORACLE_ARCHES := cross_selftest
oracle-selftest: ORACLE_RATE := 1
oracle-selftest: $(BUILD)/fuzz_field $(ORACLE_DIR)/cross_selftest/replay$(cross_selftest_EXE) | $(CORPUS)/field
	@log=$(BUILD)/$@.log; new=$(BUILD)/$@.new; rm -rf $$new && mkdir -p $$new; \
	if $(call oracle_env,field) $< -runs=$(SMOKE_RUNS) -seed=1 -artifact_prefix=$(BUILD)/$@- \
	   $$new $(CORPUS)/field > $$log 2>&1 || ! grep -q 'reference and cross_selftest' $$log; then \
		tail -n 20 $$log; echo "FAIL $@: divergence from cross_selftest not reported"; exit 1; \
	fi; \
	echo "ok   $@: $$(grep -m 1 'diverges' $$log)"

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
readme-coverage: coverage mutation-score
	@ci/readme-coverage.sh $(BUILD)/coverage/report.txt $($(COVERAGE_VARIANT)_SECP) README.md \
		$(BUILD)/mutation-score.summary

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

# Only the replay binaries, for the oracle of `make fuzz`.
cross-replays: $(foreach a,$(ARCHES) cross_selftest,$(BUILD)/cross/$(a)/replay$($(a)_EXE))

# `make docker-cross`, `make docker-cross-selftest` and `make docker-cross-replays`
# run their goal in a container with the cross toolchains, qemu-user and wine.
# The corpus is seeded on the host first, so the image needs no libFuzzer.
DOCKER_GOALS := cross cross-selftest cross-replays

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

-include $(SELFTEST_OBJS:.o=.d) $(MUTANT_OBJS:.o=.d) $(BUILD)/coverage/variant.d $(BUILD)/coverage/replay.d
