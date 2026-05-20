use tokio::task::{self, JoinSet};

use crate::abi;
use crate::config::{Backend, Config, IsolationMode};
use crate::error::SectestError;
use crate::guests::GuestCase;
use crate::policy::Policy;
use crate::runner::{CaseReport, run_case};
use crate::supervisor::{SupervisorOptions, run_case_supervised};
use crate::telemetry::{Gate, ImportEvent, MemorySnapshot, Telemetry};

#[derive(Debug, Clone)]
struct CaseTask {
    index: usize,
    case: GuestCase,
    backend: Backend,
    isolation: IsolationMode,
    policy: Policy,
    policy_path: Option<String>,
    corpus_dir: Option<String>,
    allow_unmetered: bool,
}

pub async fn collect_reports_async(
    config: &Config,
    cases: &[GuestCase],
    policy: &Policy,
) -> Vec<CaseReport> {
    let total = config.repeat.saturating_mul(cases.len());
    let mut tasks = JoinSet::new();
    let mut index = 0usize;

    for _ in 0..config.repeat {
        for case in cases {
            let task = CaseTask {
                index,
                case: case.clone(),
                backend: config.backend,
                isolation: config.isolation,
                policy: policy.clone(),
                policy_path: config.policy_path.clone(),
                corpus_dir: config.corpus_dir.clone(),
                allow_unmetered: config.allow_unmetered,
            };
            tasks.spawn(run_case_task(task));
            index += 1;
        }
    }

    let mut reports = Vec::with_capacity(total);
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(report) => reports.push(report),
            Err(err) => reports.push(join_error_report(err)),
        }
    }

    reports.sort_by_key(|(index, _)| *index);
    reports.into_iter().map(|(_, report)| report).collect()
}

async fn run_case_task(task: CaseTask) -> (usize, CaseReport) {
    let fallback_case = task.case.clone();
    let backend = task.backend;
    let index = task.index;

    let report = task::spawn_blocking(move || run_case_task_blocking(task))
        .await
        .map_err(SectestError::from)
        .unwrap_or_else(|err| async_worker_error_report(&fallback_case, backend, err.to_string()));

    (index, report)
}

fn run_case_task_blocking(task: CaseTask) -> CaseReport {
    match task.isolation {
        IsolationMode::InProcess => run_case(&task.case, task.backend, task.policy),
        IsolationMode::Process => run_case_supervised(
            &task.case,
            task.backend,
            task.policy,
            SupervisorOptions {
                policy_path: task.policy_path.as_deref(),
                corpus_dir: task.corpus_dir.as_deref(),
                allow_unmetered: task.allow_unmetered,
            },
        ),
    }
}

fn join_error_report(err: task::JoinError) -> (usize, CaseReport) {
    let err = SectestError::from(err);
    (
        usize::MAX,
        CaseReport {
            name: "async_join_error".into(),
            description: "Tokio worker failed before a case report was produced".into(),
            category: "runtime".into(),
            severity: "high".into(),
            control: "async execution boundary reports scheduler failures".into(),
            stage: "runtime scheduling".into(),
            ttp: "host-worker-failure".into(),
            detection: "join error is converted into a structured report".into(),
            source_path: String::new(),
            backend: Backend::Cranelift,
            expected_code: abi::ERR_INTERNAL,
            actual_code: Some(abi::ERR_INTERNAL),
            host_error: Some(err.to_string()),
            compile_us: 0,
            instantiate_us: 0,
            run_us: 0,
            wasm_bytes: 0,
            memory_before: MemorySnapshot::default(),
            memory_after: MemorySnapshot::default(),
            telemetry: Telemetry {
                events: vec![ImportEvent {
                    import: "host.async.join",
                    ptr: None,
                    len: None,
                    align: None,
                    memory_size: None,
                    result_code: abi::ERR_INTERNAL,
                    detail: err.to_string(),
                    elapsed_us: 0,
                    gates: vec![Gate::fail("async.join")],
                }],
                ticks_seen: 0,
            },
        },
    )
}

fn async_worker_error_report(case: &GuestCase, backend: Backend, err: String) -> CaseReport {
    CaseReport {
        name: case.name.clone(),
        description: case.description.clone(),
        category: case.category.clone(),
        severity: case.severity.clone(),
        control: case.control.clone(),
        stage: case.stage.clone(),
        ttp: case.ttp.clone(),
        detection: case.detection.clone(),
        source_path: case.source_path.clone(),
        backend,
        expected_code: case.expected_code,
        actual_code: Some(abi::ERR_INTERNAL),
        host_error: Some(format!("async worker failed: {err}")),
        compile_us: 0,
        instantiate_us: 0,
        run_us: 0,
        wasm_bytes: 0,
        memory_before: MemorySnapshot::default(),
        memory_after: MemorySnapshot::default(),
        telemetry: Telemetry {
            events: vec![ImportEvent {
                import: "host.async.spawn_blocking",
                ptr: None,
                len: None,
                align: None,
                memory_size: None,
                result_code: abi::ERR_INTERNAL,
                detail: format!("spawn_blocking failed: {err}"),
                elapsed_us: 0,
                gates: vec![Gate::fail("async.spawn_blocking")],
            }],
            ticks_seen: 0,
        },
    }
}
