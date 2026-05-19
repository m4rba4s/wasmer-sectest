use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::abi;
use crate::config::Backend;
use crate::guests::{CaseKind, GuestCase};
use crate::policy::Policy;
use crate::runner::CaseReport;
use crate::telemetry::{Gate, ImportEvent, MemorySnapshot, Telemetry};

const WORKER_PREFIX: &str = "WASMER_DEMO_WORKER_V1";
const MAX_DETAIL_CHARS: usize = 512;

#[derive(Debug, Clone, Copy)]
pub struct SupervisorOptions<'a> {
    pub policy_path: Option<&'a str>,
    pub corpus_dir: Option<&'a str>,
    pub allow_unmetered: bool,
}

#[derive(Debug)]
struct WorkerSummary {
    actual_code: Option<i32>,
    compile_us: u128,
    instantiate_us: u128,
    run_us: u128,
    wasm_bytes: usize,
    ticks_seen: u32,
    events_logged: usize,
    last_import: String,
    last_result_code: i32,
    last_detail: String,
    host_error: Option<String>,
}

pub fn run_case_supervised(
    case: &GuestCase,
    backend: Backend,
    policy: Policy,
    options: SupervisorOptions<'_>,
) -> CaseReport {
    let timeout = Duration::from_millis(policy.supervisor_timeout_ms);
    let start = Instant::now();
    let mut command = match std::env::current_exe() {
        Ok(path) => Command::new(path),
        Err(err) => {
            return supervisor_error_report(case, backend, format!("current_exe failed: {err}"));
        }
    };

    command
        .arg("--worker-case")
        .arg(&case.name)
        .arg("--backend")
        .arg(backend.name())
        .arg("--no-color")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(path) = options.policy_path {
        command.arg("--policy").arg(path);
    }
    if let Some(dir) = options.corpus_dir {
        command.arg("--corpus").arg(dir);
    }
    if options.allow_unmetered {
        command.arg("--allow-unmetered");
    }
    if case.kind == CaseKind::StaticAudit {
        command.arg("--allow-unmetered");
        command.arg("--worker-execute-static-audit");
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(err) => {
            return supervisor_error_report(case, backend, format!("worker spawn failed: {err}"));
        }
    };
    let pid = child.id();

    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                let elapsed_us = start.elapsed().as_micros();
                let output = match child.wait_with_output() {
                    Ok(output) => output,
                    Err(err) => {
                        return supervisor_error_report(
                            case,
                            backend,
                            format!("worker output collection failed: {err}"),
                        );
                    }
                };
                return supervised_completion_report(case, backend, output, elapsed_us);
            }
            Ok(None) if start.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait_with_output();
                return timeout_report(case, backend, policy.supervisor_timeout_ms, pid, start);
            }
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Err(err) => {
                return supervisor_error_report(
                    case,
                    backend,
                    format!("worker wait failed: {err}"),
                );
            }
        }
    }
}

pub fn encode_worker_report(report: &CaseReport) -> String {
    let last = report.telemetry.events.last();
    let actual = report
        .actual_code
        .map(|code| code.to_string())
        .unwrap_or_default();
    let host_error = report.host_error.as_deref().unwrap_or_default();
    let last_import = last.map(|event| event.import).unwrap_or_default();
    let last_result = last
        .map(|event| event.result_code)
        .unwrap_or(abi::ERR_INTERNAL);
    let last_detail = last.map(|event| event.detail.as_str()).unwrap_or_default();

    [
        WORKER_PREFIX.to_string(),
        actual,
        report.compile_us.to_string(),
        report.instantiate_us.to_string(),
        report.run_us.to_string(),
        report.wasm_bytes.to_string(),
        report.telemetry.ticks_seen.to_string(),
        report.telemetry.events.len().to_string(),
        escape_field(last_import),
        last_result.to_string(),
        escape_field(last_detail),
        escape_field(host_error),
    ]
    .join("\t")
}

fn supervised_completion_report(
    case: &GuestCase,
    backend: Backend,
    output: std::process::Output,
    elapsed_us: u128,
) -> CaseReport {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let Some(summary) = parse_worker_summary(&stdout) else {
        return supervisor_error_report(
            case,
            backend,
            format!(
                "worker protocol missing status={} stderr={}",
                output.status,
                truncate(&stderr, MAX_DETAIL_CHARS)
            ),
        );
    };

    let result = summary.actual_code.unwrap_or(abi::ERR_INTERNAL);
    let mut gates = vec![
        Gate::pass("supervisor.spawn"),
        Gate::pass("supervisor.timeout"),
        Gate::pass("supervisor.exit"),
        Gate::pass("supervisor.protocol"),
    ];
    if summary.host_error.is_some() || summary.actual_code.is_none() {
        gates.push(Gate::fail("worker.host_error"));
    }

    let detail = format!(
        "worker exited status={} elapsed={}us child_actual={} child_events={} child_ticks={} child_boundary={} child_result={} child_detail={}",
        output.status,
        elapsed_us,
        summary
            .actual_code
            .map(abi::code_name)
            .unwrap_or("HOST_ERROR"),
        summary.events_logged,
        summary.ticks_seen,
        summary.last_import,
        abi::code_name(summary.last_result_code),
        truncate(&summary.last_detail, MAX_DETAIL_CHARS)
    );

    CaseReport {
        name: case.name.clone(),
        description: case.description.clone(),
        category: case.category.clone(),
        severity: case.severity.clone(),
        control: case.control.clone(),
        source_path: case.source_path.clone(),
        backend,
        expected_code: case.expected_code,
        actual_code: summary.actual_code,
        host_error: summary.host_error,
        compile_us: summary.compile_us,
        instantiate_us: summary.instantiate_us,
        run_us: summary.run_us,
        wasm_bytes: summary.wasm_bytes,
        memory_before: MemorySnapshot::default(),
        memory_after: MemorySnapshot::default(),
        telemetry: Telemetry {
            events: vec![ImportEvent {
                import: "host.supervisor.process",
                ptr: None,
                len: None,
                align: None,
                memory_size: None,
                result_code: result,
                detail,
                elapsed_us,
                gates,
            }],
            ticks_seen: summary.ticks_seen,
        },
    }
}

fn timeout_report(
    case: &GuestCase,
    backend: Backend,
    timeout_ms: u64,
    pid: u32,
    start: Instant,
) -> CaseReport {
    let elapsed_us = start.elapsed().as_micros();
    let detail =
        format!("worker pid={pid} exceeded {timeout_ms}ms supervisor timeout and was killed");

    CaseReport {
        name: case.name.clone(),
        description: case.description.clone(),
        category: case.category.clone(),
        severity: case.severity.clone(),
        control: case.control.clone(),
        source_path: case.source_path.clone(),
        backend,
        expected_code: case.expected_code,
        actual_code: Some(abi::ERR_TIMEOUT),
        host_error: None,
        compile_us: 0,
        instantiate_us: 0,
        run_us: elapsed_us,
        wasm_bytes: 0,
        memory_before: MemorySnapshot::default(),
        memory_after: MemorySnapshot::default(),
        telemetry: Telemetry {
            events: vec![ImportEvent {
                import: "host.supervisor.process",
                ptr: None,
                len: None,
                align: None,
                memory_size: None,
                result_code: abi::ERR_TIMEOUT,
                detail,
                elapsed_us,
                gates: vec![
                    Gate::pass("supervisor.spawn"),
                    Gate::fail("supervisor.timeout"),
                    Gate::pass("supervisor.kill"),
                ],
            }],
            ticks_seen: 0,
        },
    }
}

fn supervisor_error_report(case: &GuestCase, backend: Backend, host_error: String) -> CaseReport {
    CaseReport {
        name: case.name.clone(),
        description: case.description.clone(),
        category: case.category.clone(),
        severity: case.severity.clone(),
        control: case.control.clone(),
        source_path: case.source_path.clone(),
        backend,
        expected_code: case.expected_code,
        actual_code: Some(abi::ERR_INTERNAL),
        host_error: Some(host_error.clone()),
        compile_us: 0,
        instantiate_us: 0,
        run_us: 0,
        wasm_bytes: 0,
        memory_before: MemorySnapshot::default(),
        memory_after: MemorySnapshot::default(),
        telemetry: Telemetry {
            events: vec![ImportEvent {
                import: "host.supervisor.process",
                ptr: None,
                len: None,
                align: None,
                memory_size: None,
                result_code: abi::ERR_INTERNAL,
                detail: host_error,
                elapsed_us: 0,
                gates: vec![Gate::fail("supervisor.error")],
            }],
            ticks_seen: 0,
        },
    }
}

fn parse_worker_summary(stdout: &str) -> Option<WorkerSummary> {
    let line = stdout
        .lines()
        .find(|line| line.starts_with(WORKER_PREFIX))?;
    let mut fields = line.split('\t');
    if fields.next()? != WORKER_PREFIX {
        return None;
    }
    let actual_raw = fields.next()?;
    let actual_code = if actual_raw.is_empty() {
        None
    } else {
        Some(actual_raw.parse().ok()?)
    };
    let compile_us = fields.next()?.parse().ok()?;
    let instantiate_us = fields.next()?.parse().ok()?;
    let run_us = fields.next()?.parse().ok()?;
    let wasm_bytes = fields.next()?.parse().ok()?;
    let ticks_seen = fields.next()?.parse().ok()?;
    let events_logged = fields.next()?.parse().ok()?;
    let last_import = unescape_field(fields.next()?)?;
    let last_result_code = fields.next()?.parse().ok()?;
    let last_detail = unescape_field(fields.next()?)?;
    let host_error_raw = unescape_field(fields.next()?)?;
    let host_error = if host_error_raw.is_empty() {
        None
    } else {
        Some(host_error_raw)
    };

    Some(WorkerSummary {
        actual_code,
        compile_us,
        instantiate_us,
        run_us,
        wasm_bytes,
        ticks_seen,
        events_logged,
        last_import,
        last_result_code,
        last_detail,
        host_error,
    })
}

fn escape_field(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            ch => out.push(ch),
        }
    }
    out
}

fn unescape_field(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next()? {
            '\\' => out.push('\\'),
            't' => out.push('\t'),
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            _ => return None,
        }
    }
    Some(out)
}

fn truncate(value: &str, max_chars: usize) -> String {
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    let mut out = value
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    out.push_str("...");
    out
}
