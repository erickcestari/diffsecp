//! Fuzzes one diffsecp target on another architecture under QEMU, steered by
//! coverage of the machine code that architecture's compiler emitted. Each input
//! runs in the guest, src/guest.c built for that architecture, and natively in
//! the reference, the same file built for the host and linked in by build.rs. A
//! transcript that differs, or a guest that doesn't return, is a divergence.

use std::{
    ffi::CStr,
    fs,
    net::TcpListener,
    os::raw::c_char,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

use clap::Parser;
use common::operands::{OperandsStage, U256Mutator};
use libafl::{
    Error, HasMetadata,
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{EventConfig, Launcher, LlmpRestartingEventManager, ProgressReporter, SendExiting},
    executors::{ExitKind, ShadowExecutor},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Evaluator, ExecuteInputResult, Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes, Input},
    monitors::MultiMonitor,
    mutators::{HavocScheduledMutator, I2SRandReplace, Tokens, havoc_mutations, tokens_mutations},
    observers::{CanTrack, HitcountsMapObserver, TimeObserver, VariableMapObserver},
    schedulers::{
        IndexesLenTimeMinimizerScheduler, StdWeightedScheduler, powersched::PowerSchedule,
    },
    stages::{CalibrationStage, ShadowTracingStage, StdMutationalStage, StdPowerMutationalStage},
    state::{HasCorpus, HasMaxSize, StdState},
};
use libafl_bolts::{
    ToSlice,
    core_affinity::Cores,
    ownedref::OwnedMutSlice,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{Merge, tuple_list},
};
use libafl_qemu::{
    ArchExtras, Emulator, GuestAddr, GuestReg, Qemu, QemuExecutor, QemuExitReason, Regs,
    elf::EasyElf,
    modules::{StdEdgeCoverageModule, cmplog::CmpLogModule, cmplog::CmpLogObserver},
};
use libafl_targets::{EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND, edges_map_mut_ptr};

// src/guest.c built for the host: the reference.
unsafe extern "C" {
    static mut diffsecp_guest_target: u32;
    static mut diffsecp_guest_in_len: u32;
    static mut diffsecp_guest_in: [u8; 0];
    static diffsecp_guest_in_max: u32;
    static diffsecp_guest_out_len: u32;
    static diffsecp_guest_out: [u8; 0];
    static diffsecp_guest_targets: [*const c_char; 0];
    static diffsecp_guest_ntargets: u32;
    fn diffsecp_guest_init();
    fn diffsecp_guest_run();
}

#[derive(Debug, Parser)]
#[command(about = "LibAFL fuzzer for one diffsecp target on another architecture, under QEMU")]
struct Opt {
    /// The guest: src/guest.c built statically for the architecture this fuzzer emulates.
    #[arg(long)]
    guest: PathBuf,
    /// The target to fuzz, such as field.
    #[arg(long)]
    target: String,
    /// Seed inputs, such as corpus/<target>.
    #[arg(long)]
    seeds: Vec<PathBuf>,
    /// Where inputs that raise guest coverage go.
    #[arg(long)]
    queue: PathBuf,
    /// Where reproducers go.
    #[arg(long)]
    crashes: PathBuf,
    /// Prefix of reproducer names.
    #[arg(long, default_value = "")]
    prefix: String,
    /// Dictionaries in libFuzzer's format.
    #[arg(long)]
    dict: Vec<PathBuf>,
    /// Cores to fuzz on, such as 0-3,6.
    #[arg(long, default_value = "0")]
    cores: String,
    /// Seconds to fuzz for; unset fuzzes until interrupted.
    #[arg(long)]
    time: Option<u64>,
    /// Seconds an input may run before it counts as a hang.
    #[arg(long, default_value_t = 60)]
    timeout: u64,
    /// Mutate 256-bit operands with carries, boundary values and limb edges.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    u256: bool,
    /// Instead of fuzzing, copy into this directory each input of --merge-from
    /// that reaches guest edges the seeds and the directory itself don't.
    #[arg(long, requires = "merge_from")]
    merge_into: Option<PathBuf>,
    /// The inputs --merge-into picks from, such as a fuzzing run's queue.
    #[arg(long)]
    merge_from: Option<PathBuf>,
}

/// The files in dir, sorted so a merge keeps the same inputs every time.
fn files(dir: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut paths = fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<Vec<_>, _>>()?;
    paths.retain(|p| p.is_file());
    paths.sort();
    Ok(paths)
}

/// The target's position in DIFFSECP_TARGETS, which guest and reference share.
fn target_index(name: &str) -> Result<u32, Error> {
    let names = unsafe {
        std::slice::from_raw_parts(
            (&raw const diffsecp_guest_targets).cast::<*const c_char>(),
            diffsecp_guest_ntargets as usize,
        )
    };
    names
        .iter()
        .position(|&n| unsafe { CStr::from_ptr(n) }.to_bytes() == name.as_bytes())
        .map(|i| i as u32)
        .ok_or_else(|| Error::illegal_argument(format!("unknown target {name}")))
}

/// Runs input through the reference, which also records its operands for
/// [`U256Mutator`].
fn reference(target: u32, input: &[u8]) -> &'static [u8] {
    unsafe {
        diffsecp_guest_target = target;
        diffsecp_guest_in_len = input.len() as u32;
        std::ptr::copy_nonoverlapping(
            input.as_ptr(),
            (&raw mut diffsecp_guest_in).cast::<u8>(),
            input.len(),
        );
        diffsecp_guest_run();
        std::slice::from_raw_parts(
            (&raw const diffsecp_guest_out).cast::<u8>(),
            diffsecp_guest_out_len as usize,
        )
    }
}

/// The guest stopped at its first call to diffsecp_guest_run. Each run
/// restores that call's stack pointer and return address and runs it again.
struct Guest {
    qemu: Qemu,
    run: GuestAddr,
    stack: GuestReg,
    /// The return address, with the Thumb bit on arm so the return stays in
    /// Thumb code, and without it as the breakpoint where the run stops.
    ret: GuestAddr,
    ret_break: GuestAddr,
    target: GuestAddr,
    in_len: GuestAddr,
    input: GuestAddr,
    out_len: GuestAddr,
    out: GuestAddr,
}

impl Guest {
    fn attach(qemu: Qemu) -> Result<Self, Error> {
        let mut buf = Vec::new();
        let elf = EasyElf::from_file(qemu.binary_path(), &mut buf)?;
        let symbol = |name: &str| {
            elf.resolve_symbol(name, qemu.load_addr())
                .ok_or_else(|| Error::key_not_found(format!("{name} not in the guest")))
        };
        let run = symbol("diffsecp_guest_run")?;
        qemu.entry_break(run);
        let ret = qemu
            .read_return_address()
            .map_err(|e| Error::unknown(format!("guest return address: {e:?}")))?;
        let stack = qemu
            .read_reg(Regs::Sp)
            .map_err(|e| Error::unknown(format!("guest stack pointer: {e:?}")))?;
        // set_breakpoint clears the Thumb bit only when the host is arm.
        let ret_break = if cfg!(feature = "arm") { ret & !1 } else { ret };
        qemu.set_breakpoint(ret_break);
        Ok(Self {
            qemu,
            run,
            stack,
            ret,
            ret_break,
            target: symbol("diffsecp_guest_target")?,
            in_len: symbol("diffsecp_guest_in_len")?,
            input: symbol("diffsecp_guest_in")?,
            out_len: symbol("diffsecp_guest_out_len")?,
            out: symbol("diffsecp_guest_out")?,
        })
    }

    /// The guest's transcript of input, or why the guest didn't return.
    fn run(&self, target: u32, input: &[u8]) -> Result<Vec<u8>, String> {
        let q = self.qemu;
        let fail = |what: &str, e: &dyn std::fmt::Debug| format!("{what}: {e:?}");
        q.write_mem(self.target, &target.to_le_bytes())
            .map_err(|e| fail("target", &e))?;
        q.write_mem(self.in_len, &(input.len() as u32).to_le_bytes())
            .map_err(|e| fail("input length", &e))?;
        q.write_mem(self.input, input)
            .map_err(|e| fail("input", &e))?;
        q.write_reg(Regs::Pc, self.run as GuestReg)
            .map_err(|e| fail("pc", &e))?;
        q.write_reg(Regs::Sp, self.stack)
            .map_err(|e| fail("sp", &e))?;
        q.write_return_address(self.ret)
            .map_err(|e| fail("return address", &e))?;
        match unsafe { q.run() } {
            Ok(QemuExitReason::Breakpoint(addr)) if addr == self.ret_break => {}
            other => return Err(format!("the guest stopped with {other:?}")),
        }
        let mut len = [0u8; 4];
        q.read_mem(self.out_len, &mut len)
            .map_err(|e| fail("transcript length", &e))?;
        q.read_mem_vec(self.out, u32::from_le_bytes(len) as usize)
            .map_err(|e| fail("transcript", &e))
    }
}

/// Reports where the transcripts part, as src/fuzz.c does between x86 builds.
fn report(target: &str, arch: &str, expected: &[u8], actual: &[u8]) {
    let at = expected
        .iter()
        .zip(actual)
        .take_while(|(a, b)| a == b)
        .count();
    let window = |t: &[u8]| {
        let (lo, hi) = (at.saturating_sub(16), (at + 48).min(t.len()));
        t[lo..hi]
            .iter()
            .enumerate()
            .map(|(i, b)| format!("{}{b:02x}", if lo + i == at { " >" } else { " " }))
            .collect::<String>()
    };
    eprintln!(
        "diffsecp: target {target} diverges between the reference and {arch} at byte {at} (lengths {}, {})",
        expected.len(),
        actual.len()
    );
    eprintln!("  {:<16}{}", "reference", window(expected));
    eprintln!("  {arch:<16}{}", window(actual));
}

/// A port no other broker listens on. Launcher joins whichever broker already
/// listens on its port, so two fuzzers run at once must never share one.
fn free_port() -> Result<u16, Error> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

type State =
    StdState<InMemoryOnDiskCorpus<BytesInput>, BytesInput, StdRand, OnDiskCorpus<BytesInput>>;
type Mgr = LlmpRestartingEventManager<
    (),
    BytesInput,
    State,
    <StdShMemProvider as ShMemProvider>::ShMem,
    StdShMemProvider,
>;

fn main() {
    let opt = Opt::parse();
    if let Err(e) = fuzz(&opt) {
        eprintln!("libafl: {e}");
        std::process::exit(1);
    }
}

fn fuzz(opt: &Opt) -> Result<(), Error> {
    let cores = Cores::from_cmdline(&opt.cores)?;
    // Computed before forking, so clients restarted after a crash keep it.
    let deadline = opt.time.map(|s| SystemTime::now() + Duration::from_secs(s));
    let target = target_index(&opt.target)?;

    let mut run_client = |state: Option<State>, mut mgr: Mgr, _client| {
        let result = client(opt, target, deadline, state, &mut mgr);
        // Also on errors, so the launcher neither restarts this client nor waits for it.
        mgr.send_exiting()?;
        result
    };

    match Launcher::builder()
        .shmem_provider(StdShMemProvider::new()?)
        .configuration(EventConfig::from_name("diffsecp_qemu"))
        .monitor(MultiMonitor::new(|s| println!("{s}")))
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(free_port()?)
        .build()
        .launch()
    {
        Ok(()) | Err(Error::ShuttingDown) => Ok(()),
        Err(e) => Err(e),
    }
}

/// One fuzzing process, started again with the saved state after each crash.
fn client(
    opt: &Opt,
    target: u32,
    deadline: Option<SystemTime>,
    state: Option<State>,
    mgr: &mut Mgr,
) -> Result<(), Error> {
    // Also checked here: a client that crashes while loading seeds restarts
    // without reaching the fuzzing loop.
    if deadline.is_some_and(|d| SystemTime::now() >= d) {
        return Ok(());
    }
    unsafe { diffsecp_guest_init() };

    let mut edges_observer = unsafe {
        HitcountsMapObserver::new(VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
            &raw mut MAX_EDGES_FOUND,
        ))
        .track_indices()
    };
    let modules = tuple_list!(
        StdEdgeCoverageModule::builder()
            .map_observer(edges_observer.as_mut())
            .build()?,
        CmpLogModule::default()
    );
    let program = std::env::args().next().unwrap_or_default();
    let emulator = Emulator::empty()
        .qemu_parameters(vec![program, opt.guest.to_string_lossy().into_owned()])
        .modules(modules)
        .build()?;
    let guest = Guest::attach(emulator.qemu())?;
    let arch = opt
        .guest
        .parent()
        .and_then(|d| d.file_name())
        .map_or_else(|| "guest".to_string(), |d| d.to_string_lossy().into_owned());

    let time_observer = TimeObserver::new("time");
    let cmplog_observer = CmpLogObserver::new("cmplog", true);

    let edges_feedback = MaxMapFeedback::new(&edges_observer);
    let calibration = CalibrationStage::new(&edges_feedback);
    let mut feedback = feedback_or!(edges_feedback, TimeFeedback::new(&time_observer));
    let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    let mut state = match state {
        Some(state) => state,
        None => StdState::new(
            StdRand::new(),
            // Without metadata or lock files, the directories hold only inputs.
            InMemoryOnDiskCorpus::with_meta_format_and_prefix(&opt.queue, None, None, false)?,
            OnDiskCorpus::with_meta_format_and_prefix(
                &opt.crashes,
                None,
                Some(opt.prefix.clone()),
                false,
            )?,
            &mut feedback,
            &mut objective,
        )?,
    };
    state.set_max_size(unsafe { diffsecp_guest_in_max } as usize);
    if !state.has_metadata::<Tokens>() {
        state.add_metadata(Tokens::new().add_from_files(&opt.dict)?);
    }

    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        StdWeightedScheduler::with_schedule(
            &mut state,
            &edges_observer,
            Some(PowerSchedule::fast()),
        ),
    );
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    let mut harness =
        |_emulator: &mut Emulator<_, _, _, _, _, _, _>, _state: &mut State, input: &BytesInput| {
            // Past the deadline, the rest of the current stage runs nothing.
            if deadline.is_some_and(|d| SystemTime::now() >= d) {
                return ExitKind::Ok;
            }
            let bytes = input.target_bytes();
            let expected = reference(target, &bytes.to_slice());
            match guest.run(target, &bytes.to_slice()) {
                Ok(actual) if actual == expected => ExitKind::Ok,
                Ok(actual) => {
                    report(&opt.target, &arch, expected, &actual);
                    ExitKind::Crash
                }
                Err(why) => {
                    eprintln!("diffsecp: target {} diverges on {arch}: {why}", opt.target);
                    ExitKind::Crash
                }
            }
        };
    let executor = QemuExecutor::new(
        emulator,
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        mgr,
        Duration::from_secs(opt.timeout),
    )?;
    let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

    let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
        I2SRandReplace::new()
    )));
    let u256 = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(U256Mutator::new(
        opt.u256
    ))));
    let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> = StdPowerMutationalStage::new(
        HavocScheduledMutator::new(havoc_mutations().merge(tokens_mutations())),
    );
    let mut stages = tuple_list!(
        calibration,
        ShadowTracingStage::new(),
        i2s,
        OperandsStage::new(opt.u256),
        u256,
        power
    );

    if let (Some(into), Some(from)) = (&opt.merge_into, &opt.merge_from) {
        // What `make merge` does for x86 coverage, for this guest's.
        fs::create_dir_all(into)?;
        for dir in opt.seeds.iter().chain([into]) {
            for path in files(dir)? {
                fuzzer.evaluate_input(
                    &mut state,
                    &mut executor,
                    mgr,
                    &BytesInput::from_file(&path)?,
                )?;
            }
        }
        let mut kept = 0;
        for path in files(from)? {
            let input = BytesInput::from_file(&path)?;
            if let (ExecuteInputResult::Corpus, _) =
                fuzzer.evaluate_input(&mut state, &mut executor, mgr, &input)?
            {
                fs::copy(&path, into.join(path.file_name().unwrap()))?;
                kept += 1;
            }
        }
        println!("merge: kept {kept} inputs in {}", into.display());
        return Ok(());
    }

    if state.must_load_initial_inputs() {
        state.load_initial_inputs(&mut fuzzer, &mut executor, mgr, &opt.seeds)?;
    }
    // As libFuzzer does when it keeps no seed.
    if state.corpus().count() == 0 {
        fuzzer.add_input(&mut state, &mut executor, mgr, BytesInput::new(Vec::new()))?;
    }

    // fuzz_loop, with the deadline checked after each testcase's stages.
    while deadline.is_none_or(|d| SystemTime::now() < d) {
        mgr.maybe_report_progress(&mut state, Duration::from_secs(15))?;
        fuzzer.fuzz_one(&mut stages, &mut executor, &mut state, mgr)?;
    }
    Ok(())
}
