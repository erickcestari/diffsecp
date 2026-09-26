//! Per-input comparison with other architectures. Each oracle is a `replay
//! TARGET` process, a static build of another architecture under qemu-user or
//! wine, kept running for the whole fuzzing run. It reads input paths on stdin
//! and prints each transcript's digest, which must equal the digest of the
//! reference transcript every x86 build agreed on. `make cross` compares the
//! same digests, but only for the committed corpus.

use std::{
    cell::Cell,
    fs,
    io::{self, BufRead, BufReader, Write},
    marker::PhantomData,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    rc::Rc,
};

use libafl::{
    Error, HasMetadata, HasNamedMetadata,
    corpus::HasCurrentCorpusId,
    executors::Executor,
    inputs::BytesInput,
    stages::{Restartable, RetryCountRestartHelper, Stage},
    state::{HasCorpus, HasCurrentTestcase},
};
use libafl_bolts::impl_serdeany;
use serde::{Deserialize, Serialize};

struct Arch {
    name: String,
    // Kept so the process lives as long as the oracle.
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

pub struct Oracle {
    archs: Vec<Arch>,
    input: PathBuf,
}

/// An architecture whose answer isn't the reference digest: another digest, or
/// no answer because its process exited, as when the build crashes.
pub struct Divergence {
    pub arch: String,
    pub expected: String,
    pub answer: String,
}

impl Oracle {
    /// Starts one process per `NAME=COMMAND`, the command split at spaces.
    /// Inputs are written under `dir`, which must be relative for wine.
    pub fn spawn(specs: &[String], dir: &Path) -> Result<Self, Error> {
        // A write to a process that exited would otherwise kill the fuzzer.
        unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
        let dir = dir.join(std::process::id().to_string());
        fs::create_dir_all(&dir)?;
        let mut archs = Vec::new();
        for spec in specs {
            let (name, command) = spec.split_once('=').ok_or_else(|| {
                Error::illegal_argument(format!("--oracle {spec}: expected NAME=COMMAND"))
            })?;
            let mut words = command.split_whitespace();
            let program = words.next().ok_or_else(|| {
                Error::illegal_argument(format!("--oracle {spec}: empty command"))
            })?;
            let mut child = Command::new(program)
                .args(words)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .map_err(|e| Error::illegal_argument(format!("oracle {name}: {command}: {e}")))?;
            archs.push(Arch {
                name: name.to_string(),
                stdin: child.stdin.take().unwrap(),
                stdout: BufReader::new(child.stdout.take().unwrap()),
                _child: child,
            });
        }
        Ok(Self {
            archs,
            input: dir.join("input"),
        })
    }

    /// Runs `input` on every architecture, which all read the same file.
    /// Returns the first whose answer isn't `reference`.
    pub fn check(&mut self, input: &[u8], reference: u64) -> io::Result<Option<Divergence>> {
        fs::write(&self.input, input)?;
        let path = self.input.to_str().unwrap();
        let expected = format!("{reference:016x}");
        let mut sent = Vec::with_capacity(self.archs.len());
        for arch in &mut self.archs {
            sent.push(
                writeln!(arch.stdin, "{path}")
                    .and_then(|()| arch.stdin.flush())
                    .is_ok(),
            );
        }
        let mut first = None;
        for (arch, sent) in self.archs.iter_mut().zip(sent) {
            // Read every answer, even after a divergence, to keep the lines paired.
            let mut line = String::new();
            let answer = if sent && arch.stdout.read_line(&mut line).unwrap_or(0) > 0 {
                line.trim().to_string()
            } else {
                "no answer: the process exited".to_string()
            };
            if first.is_none() && answer.split_whitespace().nth(1) != Some(expected.as_str()) {
                first = Some(Divergence {
                    arch: arch.name.clone(),
                    expected: expected.clone(),
                    answer,
                });
            }
        }
        Ok(first)
    }
}

/// Marks a testcase [`OracleStage`] already sent to the oracle.
#[derive(Debug, Serialize, Deserialize)]
pub struct OracleChecked;
impl_serdeany!(OracleChecked);

/// Runs each testcase once with `force` set, so the harness sends it to the
/// oracle: every input the fuzzer keeps is compared, whatever the sampling rate.
pub struct OracleStage<E, EM, S, Z> {
    force: Option<Rc<Cell<bool>>>,
    phantom: PhantomData<(E, EM, S, Z)>,
}

impl<E, EM, S, Z> OracleStage<E, EM, S, Z> {
    /// With `None` there is no oracle, and the stage does nothing.
    pub fn new(force: Option<Rc<Cell<bool>>>) -> Self {
        Self {
            force,
            phantom: PhantomData,
        }
    }
}

const ORACLE_STAGE: &str = "oracle";

impl<E, EM, S, Z> Stage<E, EM, S, Z> for OracleStage<E, EM, S, Z>
where
    E: Executor<EM, BytesInput, S, Z>,
    S: HasCorpus<BytesInput> + HasCurrentTestcase<BytesInput>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let Some(force) = &self.force else {
            return Ok(());
        };
        if state.current_testcase()?.has_metadata::<OracleChecked>() {
            return Ok(());
        }
        // Marked before running, so a divergence doesn't make a restart repeat it.
        state.current_testcase_mut()?.add_metadata(OracleChecked);
        let input = state.current_input_cloned()?;
        force.set(true);
        let result = executor.run_target(fuzzer, state, manager, &input);
        force.set(false);
        result.map(|_| ())
    }
}

impl<E, EM, S, Z> Restartable<S> for OracleStage<E, EM, S, Z>
where
    S: HasMetadata + HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, Error> {
        RetryCountRestartHelper::should_restart(state, ORACLE_STAGE, 3)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), Error> {
        RetryCountRestartHelper::clear_progress(state, ORACLE_STAGE)
    }
}
