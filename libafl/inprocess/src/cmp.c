/* SanitizerCoverage compare callbacks, in place of libafl_targets' sancov_cmplog
 * and sancov_value_profile. That value profile keeps only each compare's best
 * Hamming similarity. This one keeps libFuzzer's features: every Hamming
 * distance and every leading-zero distance of the operands per compare, so
 * x == C, x == C + 1 and x == C - 1 are each new coverage. That is what found
 * the boundary mutants in scalar. Operands still go to LibAFL's CmpLog map
 * while its tracing stage runs. */

#include <stddef.h>
#include <stdint.h>

/* libafl_targets' default LIBAFL_CMPLOG_MAP_W. */
#define CMPLOG_MAP_W 65536
/* libFuzzer's modulus for its value profile bitmap, a prime below its size. */
#define VALUE_PROFILE_MOD 65371

extern uint8_t libafl_cmplog_enabled;
void __libafl_targets_cmplog_instructions(uintptr_t k, uint8_t size, uint64_t arg1, uint64_t arg2);

uint8_t diffsecp_value_profile[65536];
const size_t diffsecp_value_profile_size = sizeof(diffsecp_value_profile);

static inline void trace(uintptr_t pc, uint8_t size, uint64_t a, uint64_t b) {
    uint64_t hamming = (uint64_t)__builtin_popcountll(a ^ b);
    uint64_t distance = a == b ? 0 : (uint64_t)__builtin_clzll(a - b) + 1;

    diffsecp_value_profile[(pc * 128 + hamming) % VALUE_PROFILE_MOD] = 1;
    diffsecp_value_profile[(pc * 128 + 64 + distance) % VALUE_PROFILE_MOD] = 1;
    if (libafl_cmplog_enabled) {
        __libafl_targets_cmplog_instructions(((pc >> 4) ^ (pc << 8)) & (CMPLOG_MAP_W - 1), size, a, b);
    }
}

#define CALLER ((uintptr_t)__builtin_return_address(0))

void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { trace(CALLER, 1, a, b); }
void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { trace(CALLER, 2, a, b); }
void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { trace(CALLER, 4, a, b); }
void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { trace(CALLER, 8, a, b); }
void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { trace(CALLER, 1, a, b); }
void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { trace(CALLER, 2, a, b); }
void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { trace(CALLER, 4, a, b); }
void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { trace(CALLER, 8, a, b); }

/* cases[0] is the number of cases, cases[1] their width in bits. */
void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases) {
    uintptr_t pc = CALLER;
    uint64_t i;

    for (i = 0; i < cases[0]; i++) {
        trace(pc + i, (uint8_t)(cases[1] / 8), val, cases[i + 2]);
    }
}

/* -fsanitize=fuzzer-no-link also traces indirect calls, which this fuzzer ignores. */
void __sanitizer_cov_trace_pc_indir(uintptr_t callee) { (void)callee; }
