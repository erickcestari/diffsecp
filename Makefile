# Builds every variant in variants.mk, then one libFuzzer binary per target that
# links all variants side by side.

SECP       ?= external/secp256k1
BUILD      ?= build
FUZZ_CC    ?= clang
OBJCOPY    ?= objcopy
SMOKE_RUNS ?= 4000

TARGETS := ecdsa schnorrsig field scalar

include variants.mk

WARNINGS := -Wall -Wextra -Wpedantic -Wshadow -Wstrict-prototypes -Wundef -Wcast-align \
            -Wno-unused-function -Wno-overlength-strings
COMMON_CFLAGS := -std=c11 -g $(WARNINGS)

VARIANT_OBJS := $(VARIANTS:%=$(BUILD)/variants/%.o)
FUZZERS      := $(TARGETS:%=$(BUILD)/fuzz_%)
FUZZ_COMPILE  = $(FUZZ_CC) $(COMMON_CFLAGS) -O1 -fsanitize=fuzzer,address,undefined \
                -fno-sanitize-recover=all -I$(BUILD)
VARIANTS_H   := \#define DIFFSECP_VARIANTS(X) $(foreach v,$(VARIANTS),X($(v)))

.PHONY: all check $(TARGETS:%=check-%) clean FORCE
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
$(foreach v,$(VARIANTS),$(eval $(call VARIANT_RULE,$(v))))

$(BUILD)/variants.h: FORCE | $(BUILD)
	@echo '$(VARIANTS_H)' | cmp -s - $@ || echo '$(VARIANTS_H)' > $@

$(BUILD)/fuzz.flags: FORCE | $(BUILD)
	@echo '$(FUZZ_COMPILE)' | cmp -s - $@ || echo '$(FUZZ_COMPILE)' > $@

$(BUILD)/fuzz_%: src/fuzz.c src/diffsecp.h $(BUILD)/variants.h $(BUILD)/fuzz.flags $(VARIANT_OBJS)
	$(FUZZ_COMPILE) -DDIFFSECP_TARGET=$* $< $(VARIANT_OBJS) -o $@

# Short run of every target from an empty corpus: catches build breakage,
# harness contract violations and shallow divergences. The signature targets
# reach ~96% of their 20k-run coverage by 4k runs. Parallelizes with make -j.
check: $(TARGETS:%=check-%)

$(TARGETS:%=check-%): check-%: $(BUILD)/fuzz_%
	@log=$(BUILD)/$@.log; \
	if ! $< -runs=$(SMOKE_RUNS) -seed=1 > $$log 2>&1; then \
		cat $$log; echo "FAIL $*"; exit 1; \
	fi; \
	echo "ok   $*: $$(tail -n 1 $$log)"

$(BUILD) $(BUILD)/variants:
	mkdir -p $@

clean:
	rm -rf $(BUILD)

-include $(VARIANT_OBJS:.o=.d)
