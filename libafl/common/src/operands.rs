//! Mutation of the input's operands as 256-bit numbers. src/fuzz.c records where
//! the reference build read each operand of at least 32 bytes, and the mutator
//! rewrites those bytes with the values where arithmetic goes wrong (the
//! dictionaries' 32-byte tokens, such as p, n and (n-1)/2) and their neighbours,
//! and with the limb boundaries of every field and scalar implementation. Havoc
//! rarely builds either: its arithmetic stops at 4-byte words, so it never
//! carries across an operand.

use std::{borrow::Cow, collections::HashSet, marker::PhantomData};

use libafl::{
    Error, HasMetadata, HasNamedMetadata,
    corpus::{CorpusId, HasCurrentCorpusId},
    executors::Executor,
    inputs::{BytesInput, HasMutatorBytes, ResizableMutator},
    mutators::{MutationResult, Mutator, Tokens},
    stages::{Restartable, RetryCountRestartHelper, Stage},
    state::{HasCorpus, HasCurrentTestcase, HasMaxSize, HasRand},
};
use libafl_bolts::{Named, impl_serdeany, rands::Rand};
use serde::{Deserialize, Serialize};

const U256: usize = 32;

/// Limb widths in bits of the 5x52 and 10x26 fields and the 4x64 and 8x32
/// scalars. Carries between limbs happen at these boundaries.
const LIMB_BITS: [usize; 4] = [52, 26, 64, 32];

#[repr(C)]
#[derive(Clone, Copy)]
struct Read {
    offset: u32,
    len: u32,
}

unsafe extern "C" {
    // Filled by src/fuzz.c on every run.
    static diffsecp_reads: [Read; 0];
    static diffsecp_nreads: usize;
}

/// The 32-byte operands of a testcase, attached by [`OperandsStage`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Operands {
    /// Offsets of the operands' 32-byte chunks. A longer read is cut from its end,
    /// so a 33-byte compressed key yields its x coordinate.
    chunks: Vec<usize>,
}
impl_serdeany!(Operands);

impl Operands {
    /// The operands the reference build read in the last run, leaving out those
    /// that would end past `max_size`, where the harness rejects the input.
    fn from_last_run(max_size: usize) -> Self {
        let reads = unsafe {
            std::slice::from_raw_parts((&raw const diffsecp_reads).cast::<Read>(), diffsecp_nreads)
        };
        let mut seen = HashSet::new();
        let mut chunks = Vec::new();
        for read in reads {
            let end = (read.offset + read.len) as usize;
            for i in 1..=read.len as usize / U256 {
                if end - (i - 1) * U256 <= max_size && seen.insert(end - i * U256) {
                    chunks.push(end - i * U256);
                }
            }
        }
        Self { chunks }
    }
}

/// Adds k to a 256-bit big-endian number, wrapping.
fn add(x: &mut [u8; U256], k: i64) {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        *limb = u64::from_be_bytes(x[U256 - 8 * (i + 1)..U256 - 8 * i].try_into().unwrap());
    }
    let mut carry = k.unsigned_abs();
    for limb in &mut limbs {
        let (v, overflow) = if k < 0 {
            limb.overflowing_sub(carry)
        } else {
            limb.overflowing_add(carry)
        };
        *limb = v;
        carry = u64::from(overflow);
    }
    for (i, limb) in limbs.iter().enumerate() {
        x[U256 - 8 * (i + 1)..U256 - 8 * i].copy_from_slice(&limb.to_be_bytes());
    }
}

/// Sets bits [lo, hi) of a 256-bit big-endian number, counted from the least
/// significant, to ones or zeros.
fn fill_bits(x: &mut [u8; U256], lo: usize, hi: usize, ones: bool) {
    for bit in lo..hi {
        let (byte, mask) = (U256 - 1 - bit / 8, 1u8 << (bit % 8));
        if ones {
            x[byte] |= mask;
        } else {
            x[byte] &= !mask;
        }
    }
}

/// The dictionaries' 32-byte tokens: the boundary values dict/gen.py derives.
fn boundary_values<S: HasMetadata>(state: &S) -> Vec<[u8; U256]> {
    state.metadata::<Tokens>().map_or_else(
        |_| Vec::new(),
        |tokens| {
            tokens
                .tokens()
                .iter()
                .filter_map(|t| t.as_slice().try_into().ok())
                .collect()
        },
    )
}

/// Records each testcase's operands the first time it is scheduled, for
/// [`U256Mutator`]. It costs one run per testcase.
pub struct OperandsStage<E, EM, S, Z> {
    enabled: bool,
    phantom: PhantomData<(E, EM, S, Z)>,
}

impl<E, EM, S, Z> OperandsStage<E, EM, S, Z> {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            phantom: PhantomData,
        }
    }
}

const OPERANDS_STAGE: &str = "operands";

impl<E, EM, S, Z> Stage<E, EM, S, Z> for OperandsStage<E, EM, S, Z>
where
    E: Executor<EM, BytesInput, S, Z>,
    S: HasCorpus<BytesInput> + HasCurrentTestcase<BytesInput> + HasMaxSize,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if !self.enabled || state.current_testcase()?.has_metadata::<Operands>() {
            return Ok(());
        }
        let input = state.current_input_cloned()?;
        executor.run_target(fuzzer, state, manager, &input)?;
        let operands = Operands::from_last_run(state.max_size());
        state.current_testcase_mut()?.add_metadata(operands);
        Ok(())
    }
}

impl<E, EM, S, Z> Restartable<S> for OperandsStage<E, EM, S, Z>
where
    S: HasMetadata + HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::should_restart(state, OPERANDS_STAGE, 3)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, OPERANDS_STAGE)
    }
}

/// Rewrites one operand of the current testcase as a 256-bit number: adds or
/// subtracts a few units with carries, sets it to a boundary value plus or
/// minus a few, or fills one limb of some implementation with ones or zeros.
pub struct U256Mutator {
    name: Cow<'static, str>,
    enabled: bool,
}

impl U256Mutator {
    pub fn new(enabled: bool) -> Self {
        Self {
            name: Cow::Borrowed("U256Mutator"),
            enabled,
        }
    }
}

impl Named for U256Mutator {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<S> Mutator<BytesInput, S> for U256Mutator
where
    S: HasCorpus<BytesInput> + HasCurrentTestcase<BytesInput> + HasMetadata + HasRand,
{
    fn mutate(&mut self, state: &mut S, input: &mut BytesInput) -> Result<MutationResult, Error> {
        if !self.enabled {
            return Ok(MutationResult::Skipped);
        }
        let chunks = match state.current_testcase()?.metadata::<Operands>() {
            Ok(operands) if !operands.chunks.is_empty() => operands.chunks.clone(),
            _ => return Ok(MutationResult::Skipped),
        };
        let chunk = *state.rand_mut().choose(&chunks).unwrap();
        if input.mutator_bytes().len() < chunk + U256 {
            input.resize(chunk + U256, 0);
        }
        let mut v: [u8; U256] = input.mutator_bytes()[chunk..chunk + U256]
            .try_into()
            .unwrap();

        match state.rand_mut().below_or_zero(3) {
            0 => {
                let k = state.rand_mut().between(1, 16) as i64;
                add(
                    &mut v,
                    if state.rand_mut().coinflip(0.5) {
                        k
                    } else {
                        -k
                    },
                );
            }
            1 => {
                let values = boundary_values(state);
                let Some(value) = state.rand_mut().choose(&values).copied() else {
                    return Ok(MutationResult::Skipped);
                };
                v = value;
                add(&mut v, state.rand_mut().between(0, 4) as i64 - 2);
            }
            _ => {
                let width = *state.rand_mut().choose(&LIMB_BITS).unwrap();
                let lo = width * state.rand_mut().below_or_zero(256_usize.div_ceil(width));
                let ones = state.rand_mut().coinflip(0.5);
                fill_bits(&mut v, lo, (lo + width).min(256), ones);
            }
        }
        input.mutator_bytes_mut()[chunk..chunk + U256].copy_from_slice(&v);
        Ok(MutationResult::Mutated)
    }

    fn post_exec(&mut self, _state: &mut S, _new_corpus_id: Option<CorpusId>) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(x: &[u8; U256]) -> String {
        x.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn add_carries_across_all_limbs() {
        let mut x = [0xff; U256];
        add(&mut x, 1);
        assert_eq!(x, [0; U256]);
        add(&mut x, -1);
        assert_eq!(x, [0xff; U256]);
        let mut y = [0; U256];
        y[23] = 1; // 2^64
        add(&mut y, -2);
        assert_eq!(hex(&y), format!("{}{}", "0".repeat(48), "fffffffffffffffe"));
    }

    #[test]
    fn fill_bits_counts_from_the_least_significant_bit() {
        let mut x = [0; U256];
        fill_bits(&mut x, 52, 104, true);
        // Limb 1 of the 5x52 field: bits 52..104, hex digits 13..26 from the right.
        assert_eq!(
            hex(&x),
            format!("{}{}{}", "0".repeat(38), "f".repeat(13), "0".repeat(13))
        );
    }
}
