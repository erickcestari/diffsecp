# Builds every variant in variants.mk, then one libFuzzer binary per target that
# links all variants side by side. `make cross` replays the corpus on the
# architectures in arches.mk instead.

SECP        ?= external/secp256k1
BUILD       ?= build
CORPUS      ?= corpus
FUZZ_CC     ?= clang
OBJCOPY     ?= objcopy
SMOKE_RUNS  ?= 4000
DOCKER      ?= docker
CROSS_IMAGE ?= diffsecp-cross

TARGETS := ecdsa schnorrsig field scalar group keys ellswift recovery

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

VARIANT_OBJS  := $(VARIANTS:%=$(BUILD)/variants/%.o)
SELFTEST_OBJS := $(VARIANT_OBJS) $(BUILD)/variants/selftest.o
FUZZERS       := $(TARGETS:%=$(BUILD)/fuzz_%)
FUZZ_COMPILE   = $(FUZZ_CC) $(COMMON_CFLAGS) -O1 -fsanitize=fuzzer,address,undefined \
                 -fno-sanitize-recover=all
VARIANTS_H          := \#define DIFFSECP_VARIANTS(X) $(foreach v,$(VARIANTS),X($(v)))
SELFTEST_VARIANTS_H := \#define DIFFSECP_VARIANTS(X) $(foreach v,$(VARIANTS) selftest,X($(v)))

.PHONY: all check $(TARGETS:%=check-%) selftest $(TARGETS:%=selftest-%) \
        cross cross-image docker-cross clean FORCE
.DELETE_ON_ERROR:

all: $(FUZZERS)

# *.flags files hold the exact compile command and are rewritten only when it
# changes, so overriding a compiler or flags on the command line rebuilds.
#
# Localizing libsecp's symbols (secp256k1_*, and ecdsa_* from contrib) leaves
# diffsecp_variant_<name> as the only global definition. A new libsecp global
# outside these patterns shows up as a duplicate symbol at link time.
define VARIANT_RULE
$(1)_COMPILE = $$($(1)_CC) $$(COMMON_CFLAGS) $$($(1)_CFLAGS) -I$$(SECP) -I$$(SECP)/include \
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
# New inputs go to the build tree so the committed corpus stays untouched.
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
$(foreach a,$(ARCHES),$(eval $(call ARCH_RULE,$(a))))

CROSS_REF := $(BUILD)/cross/$(firstword $(ARCHES))/digests

cross: $(ARCHES:%=$(BUILD)/cross/%/digests)
	@status=0; \
	for a in $(wordlist 2,$(words $(ARCHES)),$(ARCHES)); do \
		d=$(BUILD)/cross/$$a/digests; \
		if cmp -s $(CROSS_REF) $$d; then \
			echo "ok   $$a: $$(wc -l < $$d) inputs match $(firstword $(ARCHES))"; \
		else \
			echo "DIVERGE $$a (< $(firstword $(ARCHES)), > $$a):"; diff $(CROSS_REF) $$d | head -n 20; status=1; \
		fi; \
	done; \
	exit $$status

# Runs `make cross` in a container with the cross toolchains, qemu-user and
# wine. The corpus is seeded on the host first, so the image needs no clang.
cross-image:
	$(DOCKER) build -t $(CROSS_IMAGE) ci

# HOME lives in the build tree because wine only creates its prefix in a
# directory the user owns, and keeping it there skips wine's setup next time.
docker-cross: cross-image | $(TARGETS:%=$(CORPUS)/%)
	mkdir -p $(BUILD)/docker/home
	$(DOCKER) run --rm -u $$(id -u):$$(id -g) -e HOME=/src/$(BUILD)/docker/home -e WINEDEBUG=-all \
		-v $(CURDIR):/src -w /src $(CROSS_IMAGE) \
		make -j$$(nproc) BUILD=$(BUILD)/docker CORPUS=$(CORPUS) cross

$(BUILD) $(BUILD)/variants $(BUILD)/selftest:
	mkdir -p $@

clean:
	rm -rf $(BUILD)

-include $(SELFTEST_OBJS:.o=.d)
