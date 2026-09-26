//! LibAFL fuzzer for one diffsecp target. The Makefile links it with src/fuzz.c
//! and the variant objects into build/libafl_<target>, so it drives the same
//! LLVMFuzzerTestOneInput as the libFuzzer build: a divergence aborts, and
//! LibAFL saves the input as a reproducer.

use std::{
    net::TcpListener,
    path::PathBuf,
    time::{Duration, SystemTime},
};

use clap::Parser;
use libafl::{
    Error, HasMetadata,
    corpus::{Corpus, InMemoryOnDiskCorpus, OnDiskCorpus},
    events::{EventConfig, Launcher, LlmpRestartingEventManager, ProgressReporter, SendExiting},
    executors::{ExitKind, ShadowExecutor, inprocess::InProcessExecutor},
    feedback_and_fast, feedback_or, feedback_or_fast,
    feedbacks::{ConstFeedback, CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Evaluator, Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::MultiMonitor,
    mutators::{HavocScheduledMutator, I2SRandReplace, Tokens, havoc_mutations, tokens_mutations},
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{
        IndexesLenTimeMinimizerScheduler, StdWeightedScheduler, powersched::PowerSchedule,
    },
    stages::{CalibrationStage, ShadowTracingStage, StdMutationalStage, StdPowerMutationalStage},
    state::{HasCorpus, HasMaxSize, StdState},
};
use libafl_bolts::{
    ToSlice,
    core_affinity::Cores,
    rands::StdRand,
    shmem::{ShMemProvider, StdShMemProvider},
    tuples::{Merge, tuple_list},
};
use libafl_targets::{
    CmpLogObserver, extra_counters, libfuzzer_initialize, libfuzzer_test_one_input,
};

mod operands;
use operands::{OperandsStage, U256Mutator};

unsafe extern "C" {
    static diffsecp_input_max: usize;
    // Filled on every run by src/cmp.c.
    static mut diffsecp_value_profile: [u8; 0];
    static diffsecp_value_profile_size: usize;
    // Filled on every run by the mutant schemata in src/fuzz.c.
    static mut diffsecp_mutant_infected: [u8; 0];
    static mut diffsecp_mutant_killed: [u8; 0];
    static diffsecp_mutant_count: usize;
}

#[derive(Debug, Parser)]
#[command(about = "LibAFL fuzzer for one diffsecp target")]
struct Opt {
    /// Seed inputs, such as corpus/<target>.
    #[arg(long)]
    seeds: Vec<PathBuf>,
    /// Where inputs that raise coverage go, such as build/new/<target>.
    #[arg(long)]
    queue: PathBuf,
    /// Where reproducers go.
    #[arg(long)]
    crashes: PathBuf,
    /// Prefix of reproducer names, such as "<target>-".
    #[arg(long, default_value = "")]
    prefix: String,
    /// Dictionaries in libFuzzer's format.
    #[arg(long)]
    dict: Vec<PathBuf>,
    /// Keep inputs that bring a compare's operands closer.
    #[arg(long)]
    value_profile: bool,
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
}

/// A port no other broker listens on. Launcher joins whichever broker already
/// listens on its port, so two targets fuzzed at once must never share one.
fn free_port() -> Result<u16, Error> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?.port())
}

/// Called by the `main` in libafl_targets.
#[unsafe(no_mangle)]
pub extern "C" fn libafl_main() {
    let opt = Opt::parse();
    if let Err(e) = fuzz(&opt) {
        eprintln!("libafl: {e}");
        std::process::exit(1);
    }
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

fn fuzz(opt: &Opt) -> Result<(), Error> {
    let cores = Cores::from_cmdline(&opt.cores)?;
    // Computed before forking, so clients restarted after a crash keep it.
    let deadline = opt.time.map(|s| SystemTime::now() + Duration::from_secs(s));

    let mut run_client = |state: Option<State>, mut mgr: Mgr, _client| {
        let result = client(opt, deadline, state, &mut mgr);
        // Also on errors, so the launcher neither restarts this client nor waits for it.
        mgr.send_exiting()?;
        result
    };

    match Launcher::builder()
        .shmem_provider(StdShMemProvider::new()?)
        .configuration(EventConfig::from_name("diffsecp"))
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
    deadline: Option<SystemTime>,
    state: Option<State>,
    mgr: &mut Mgr,
) -> Result<(), Error> {
    // Also checked here: a client that crashes while loading seeds restarts
    // without reaching the fuzzing loop.
    if deadline.is_some_and(|d| SystemTime::now() >= d) {
        return Ok(());
    }

    // Every instrumented object registers the whole linked counters section,
    // so the variants share one map.
    let mut counters = unsafe { extra_counters() };
    if counters.len() != 1 {
        return Err(Error::illegal_state(format!(
            "expected one counters map, got {}",
            counters.len()
        )));
    }
    let edges_observer =
        HitcountsMapObserver::new(StdMapObserver::from_mut_slice("edges", counters.remove(0)))
            .track_indices();
    let value_profile_observer = unsafe {
        StdMapObserver::from_mut_ptr(
            "value_profile",
            (&raw mut diffsecp_value_profile).cast::<u8>(),
            diffsecp_value_profile_size,
        )
    };
    let infected_observer = unsafe {
        StdMapObserver::from_mut_ptr(
            "mutants_infected",
            (&raw mut diffsecp_mutant_infected).cast::<u8>(),
            diffsecp_mutant_count,
        )
    };
    let killed_observer = unsafe {
        StdMapObserver::from_mut_ptr(
            "mutants_killed",
            (&raw mut diffsecp_mutant_killed).cast::<u8>(),
            diffsecp_mutant_count,
        )
    };
    let time_observer = TimeObserver::new("time");
    let cmplog_observer = CmpLogObserver::new("cmplog", true);

    let edges_feedback = MaxMapFeedback::new(&edges_observer);
    let calibration = CalibrationStage::new(&edges_feedback);
    let mut feedback = feedback_or!(
        edges_feedback,
        MaxMapFeedback::new(&infected_observer),
        MaxMapFeedback::new(&killed_observer),
        feedback_and_fast!(
            ConstFeedback::new(opt.value_profile),
            MaxMapFeedback::new(&value_profile_observer)
        ),
        TimeFeedback::new(&time_observer)
    );
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
    state.set_max_size(unsafe { diffsecp_input_max });
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

    // Runs every variant's init.
    let args: Vec<String> = std::env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        return Err(Error::illegal_state("LLVMFuzzerInitialize failed"));
    }
    let mut harness = |input: &BytesInput| {
        // Past the deadline, the rest of the current stage runs nothing: one stage
        // of a slow target takes minutes.
        if deadline.is_none_or(|d| SystemTime::now() < d) {
            unsafe { libfuzzer_test_one_input(&input.target_bytes().to_slice()) };
        }
        ExitKind::Ok
    };
    let executor = InProcessExecutor::builder()
        .harness(&mut harness)
        .observers(tuple_list!(
            edges_observer,
            value_profile_observer,
            infected_observer,
            killed_observer,
            time_observer
        ))
        .timeout(Duration::from_secs(opt.timeout))
        .fuzzer(&mut fuzzer)
        .state(&mut state)
        .event_mgr(mgr)
        .build()?;
    let mut executor = ShadowExecutor::new(executor, tuple_list!(cmplog_observer));

    let i2s = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(
        I2SRandReplace::new()
    )));
    let power: StdPowerMutationalStage<_, _, BytesInput, _, _, _> = StdPowerMutationalStage::new(
        HavocScheduledMutator::new(havoc_mutations().merge(tokens_mutations())),
    );
    let u256 = StdMutationalStage::new(HavocScheduledMutator::new(tuple_list!(U256Mutator::new(
        opt.u256
    ))));
    let mut stages = tuple_list!(
        calibration,
        ShadowTracingStage::new(),
        i2s,
        OperandsStage::new(opt.u256),
        u256,
        power
    );

    if state.must_load_initial_inputs() {
        state.load_initial_inputs(&mut fuzzer, &mut executor, mgr, &opt.seeds)?;
    }
    // As libFuzzer does when it keeps no seed, such as when every seed diverges.
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
