use std::time::Instant;

use wasmer::{
    AsStoreRef, Engine, Function, FunctionEnv, FunctionEnvMut, Instance, Memory, Module, Store,
    TypedFunction, imports,
    sys::{Cranelift, Singlepass},
};

use crate::abi::{self, AbiError};
use crate::config::Backend;
use crate::guests::{CaseKind, GuestCase};
use crate::memory::{self, GuestBytes, GuestBytesMut};
use crate::policy::Policy;
use crate::telemetry::{Gate, ImportEvent, MemorySnapshot, Telemetry};

const HOST_WRITE_MARKER: &[u8; 4] = b"WSEC";

/// Security audit of the Wasm module before instantiation.
/// This is a "Static Analysis" gate.
fn audit_module(module: &Module, policy: &Policy) -> Result<(), AuditDenial> {
    for import in module.imports().memories() {
        let ty = import.ty();
        if ty.minimum.0 > policy.max_memory_pages {
            return Err(AuditDenial::memory_pages("imported", ty.minimum.0, policy));
        }
    }
    for export in module.exports().memories() {
        let ty = export.ty();
        if ty.minimum.0 > policy.max_memory_pages {
            return Err(AuditDenial::memory_pages("exported", ty.minimum.0, policy));
        }
    }
    if policy.require_tick_import
        && !module
            .imports()
            .functions()
            .any(|import| import.module() == "host" && import.name() == "tick")
    {
        return Err(AuditDenial {
            result_code: abi::ERR_BUDGET,
            detail:
                "module does not import host.tick; refusing in-process run without CPU budget hook"
                    .into(),
            gates: vec![
                Gate::pass("module.memory_min_pages"),
                Gate::fail("module.tick_import"),
            ],
        });
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct AuditDenial {
    result_code: i32,
    detail: String,
    gates: Vec<Gate>,
}

impl AuditDenial {
    fn memory_pages(direction: &str, requested: u32, policy: &Policy) -> Self {
        Self {
            result_code: abi::ERR_TOO_LARGE,
            detail: format!(
                "{direction} minimum memory {requested} pages exceeds policy max_memory_pages {}",
                policy.max_memory_pages
            ),
            gates: vec![Gate::fail("module.memory_min_pages")],
        }
    }
}

#[derive(Debug, Clone)]
pub struct CaseReport {
    pub name: String,
    pub description: String,
    pub category: String,
    pub severity: String,
    pub control: String,
    pub stage: String,
    pub ttp: String,
    pub detection: String,
    pub source_path: String,
    pub backend: Backend,
    pub expected_code: i32,
    pub actual_code: Option<i32>,
    pub host_error: Option<String>,
    pub compile_us: u128,
    pub instantiate_us: u128,
    pub run_us: u128,
    pub wasm_bytes: usize,
    pub memory_before: MemorySnapshot,
    pub memory_after: MemorySnapshot,
    pub telemetry: Telemetry,
}

impl CaseReport {
    pub fn passed(&self) -> bool {
        self.host_error.is_none() && self.actual_code == Some(self.expected_code)
    }
}

#[derive(Debug, Clone)]
struct HostState {
    memory: Option<Memory>,
    policy: Policy,
    telemetry: Telemetry,
    fuel_remaining: u32,
}

impl HostState {
    fn new(policy: Policy) -> Self {
        Self {
            fuel_remaining: policy.initial_fuel,
            memory: None,
            policy,
            telemetry: Telemetry::default(),
        }
    }
}

pub fn run_case(case: &GuestCase, backend: Backend, policy: Policy) -> CaseReport {
    run_case_with_static_mode(case, backend, policy, false)
}

pub fn run_case_executing_static_fixture(
    case: &GuestCase,
    backend: Backend,
    policy: Policy,
) -> CaseReport {
    run_case_with_static_mode(case, backend, policy, true)
}

fn run_case_with_static_mode(
    case: &GuestCase,
    backend: Backend,
    policy: Policy,
    execute_static_fixture: bool,
) -> CaseReport {
    match run_case_inner(case, backend, policy, execute_static_fixture) {
        Ok(report) => report,
        Err(report) => *report,
    }
}

fn run_case_inner(
    case: &GuestCase,
    backend: Backend,
    policy: Policy,
    execute_static_fixture: bool,
) -> Result<CaseReport, Box<CaseReport>> {
    let mut store = make_store(backend, &policy);
    let wasm = match case.source.wasm_bytes() {
        Ok(wasm) => wasm,
        Err(err) => {
            return Err(Box::new(error_report(case, backend, err)));
        }
    };

    let compile_start = Instant::now();
    let module = match Module::new(&store, &wasm) {
        Ok(module) => module,
        Err(err) => {
            return Err(Box::new(error_report(
                case,
                backend,
                format!("Wasmer compile failed: {err}"),
            )));
        }
    };
    let compile_us = compile_start.elapsed().as_micros();

    if case.kind == CaseKind::StaticAudit && !execute_static_fixture {
        return Ok(audit_denial_report(
            case,
            backend,
            wasm.len(),
            compile_us,
            0,
            AuditDenial {
                result_code: abi::ERR_TIMEOUT,
                detail: "static audit fixture is intentionally not executed in-process".into(),
                gates: vec![
                    Gate::pass("module.memory_min_pages"),
                    Gate::fail("module.tick_import"),
                    Gate::pass("runner.no_execute"),
                ],
            },
        ));
    }

    let audit_start = Instant::now();
    if let Err(denial) = audit_module(&module, &policy) {
        return Ok(audit_denial_report(
            case,
            backend,
            wasm.len(),
            compile_us,
            audit_start.elapsed().as_micros(),
            denial,
        ));
    }

    let env = FunctionEnv::new(&mut store, HostState::new(policy));
    let import_object = imports! {
        "host" => {
            "accept_packet" => Function::new_typed_with_env(&mut store, &env, host_accept_packet),
            "read_cap" => Function::new_typed_with_env(&mut store, &env, host_read_cap),
            "alloc_cap" => Function::new_typed_with_env(&mut store, &env, host_alloc_cap),
            "write_marker" => Function::new_typed_with_env(&mut store, &env, host_write_marker),
            "tick" => Function::new_typed_with_env(&mut store, &env, host_tick),
        },
    };

    let instantiate_start = Instant::now();
    let instance = match Instance::new(&mut store, &module, &import_object) {
        Ok(instance) => instance,
        Err(err) => {
            return Err(Box::new(error_report(
                case,
                backend,
                format!("Wasmer instantiate failed: {err}"),
            )));
        }
    };
    let instantiate_us = instantiate_start.elapsed().as_micros();

    let memory = match instance.exports.get_memory("memory") {
        Ok(memory) => memory.clone(),
        Err(err) => {
            return Err(Box::new(error_report(
                case,
                backend,
                format!("missing memory export: {err}"),
            )));
        }
    };
    env.as_mut(&mut store).memory = Some(memory.clone());

    let memory_before = snapshot_memory(&memory, &store);
    if case.kind == CaseKind::GrowthProbe {
        run_growth_probe(&instance, &mut store, &env, &memory);
    }

    let run: TypedFunction<(), i32> = match instance.exports.get_typed_function(&store, "run") {
        Ok(run) => run,
        Err(err) => {
            return Err(Box::new(error_report(
                case,
                backend,
                format!("missing run export: {err}"),
            )));
        }
    };

    let run_start = Instant::now();
    let actual_code = match run.call(&mut store) {
        Ok(code) => Some(code),
        Err(err) => {
            return Err(Box::new(error_report(
                case,
                backend,
                format!("guest trapped during run: {err}"),
            )));
        }
    };
    let run_us = run_start.elapsed().as_micros();

    let memory_after = snapshot_memory(&memory, &store);
    let telemetry = env.as_ref(&store).telemetry.clone();

    Ok(CaseReport {
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
        actual_code,
        host_error: None,
        compile_us,
        instantiate_us,
        run_us,
        wasm_bytes: wasm.len(),
        memory_before,
        memory_after,
        telemetry,
    })
}

fn make_store(backend: Backend, _policy: &Policy) -> Store {
    match backend {
        Backend::Cranelift => {
            let compiler = Cranelift::new();
            let engine: Engine = compiler.into();
            Store::new(engine)
        }
        Backend::Singlepass => {
            let compiler = Singlepass::new();
            let engine: Engine = compiler.into();
            Store::new(engine)
        }
    }
}

fn error_report(case: &GuestCase, backend: Backend, host_error: String) -> CaseReport {
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
        actual_code: None,
        host_error: Some(host_error),
        compile_us: 0,
        instantiate_us: 0,
        run_us: 0,
        wasm_bytes: 0,
        memory_before: MemorySnapshot::default(),
        memory_after: MemorySnapshot::default(),
        telemetry: Telemetry::default(),
    }
}

fn audit_denial_report(
    case: &GuestCase,
    backend: Backend,
    wasm_bytes: usize,
    compile_us: u128,
    audit_us: u128,
    denial: AuditDenial,
) -> CaseReport {
    let result_code = denial.result_code;
    let telemetry = Telemetry {
        events: vec![ImportEvent {
            import: "host.audit.module",
            ptr: None,
            len: None,
            align: None,
            memory_size: None,
            result_code,
            detail: denial.detail,
            elapsed_us: audit_us,
            gates: denial.gates,
        }],
        ticks_seen: 0,
    };

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
        actual_code: Some(result_code),
        host_error: None,
        compile_us,
        instantiate_us: 0,
        run_us: 0,
        wasm_bytes,
        memory_before: MemorySnapshot::default(),
        memory_after: MemorySnapshot::default(),
        telemetry,
    }
}

fn run_growth_probe(
    instance: &Instance,
    store: &mut Store,
    env: &FunctionEnv<HostState>,
    memory: &Memory,
) {
    let before = snapshot_memory(memory, store);
    let start = Instant::now();
    let grow_raw = match instance
        .exports
        .get_typed_function::<(), i32>(&*store, "grow_only")
    {
        Ok(grow) => grow.call(store).unwrap_or(abi::ERR_INTERNAL),
        Err(_) => abi::ERR_INTERNAL,
    };
    let after = snapshot_memory(memory, store);
    let result = if grow_raw >= 0 {
        abi::OK
    } else {
        abi::ERR_INTERNAL
    };
    let detail = format!(
        "pre-run grow_only raw_return={} pages {}->{} bytes {}->{}; old MemoryView intentionally dropped before call",
        grow_raw, before.pages, after.pages, before.bytes, after.bytes
    );
    env.as_mut(store).telemetry.push(ImportEvent {
        import: "host.runner.grow_probe",
        ptr: None,
        len: None,
        align: None,
        memory_size: Some(after.bytes),
        result_code: result,
        detail,
        elapsed_us: start.elapsed().as_micros(),
        gates: vec![Gate::pass("drop_stale_view"), Gate::pass("reacquire_view")],
    });
}

fn snapshot_memory(memory: &Memory, store: &impl AsStoreRef) -> MemorySnapshot {
    let view = memory.view(store);
    MemorySnapshot {
        pages: view.size().0,
        bytes: view.data_size(),
        data_ptr: view.data_ptr() as usize,
    }
}

fn host_accept_packet(mut env: FunctionEnvMut<HostState>, ptr: u32, len: u32, align: u32) -> i32 {
    let start = Instant::now();
    let (state, store) = env.data_and_store_mut();
    let (result, memory_size, gates, detail) = match memory::with_guest_bytes(
        state.memory.as_ref(),
        &store,
        ptr,
        len,
        align,
        state.policy.max_packet_len,
        validate_packet_from_guest,
    ) {
        Ok(outcome) => outcome,
        Err((err, memory_size, gates)) => (
            err.code(),
            memory_size,
            gates,
            format!("range rejected: {err}"),
        ),
    };

    state.telemetry.push(ImportEvent {
        import: "host.accept_packet",
        ptr: Some(ptr),
        len: Some(len),
        align: Some(align),
        memory_size,
        result_code: result,
        detail,
        elapsed_us: start.elapsed().as_micros(),
        gates,
    });
    result
}

fn host_read_cap(mut env: FunctionEnvMut<HostState>, ptr: u32, len: u32) -> i32 {
    let start = Instant::now();
    let (state, store) = env.data_and_store_mut();
    let (result, memory_size, gates, detail) = match memory::with_guest_bytes(
        state.memory.as_ref(),
        &store,
        ptr,
        len,
        1,
        state.policy.max_cap_string_len,
        |guest| validate_capability_from_guest(guest, &state.policy),
    ) {
        Ok(outcome) => outcome,
        Err((err, memory_size, gates)) => (
            err.code(),
            memory_size,
            gates,
            format!("range rejected: {err}"),
        ),
    };

    state.telemetry.push(ImportEvent {
        import: "host.read_cap",
        ptr: Some(ptr),
        len: Some(len),
        align: Some(1),
        memory_size,
        result_code: result,
        detail,
        elapsed_us: start.elapsed().as_micros(),
        gates,
    });
    result
}

fn validate_packet_from_guest(
    GuestBytes {
        bytes,
        range,
        memory_size,
        mut gates,
    }: GuestBytes<'_>,
) -> (i32, Option<u64>, Vec<Gate>, String) {
    match abi::parse_packet(bytes) {
        Ok(packet) => {
            gates.push(Gate::pass("packet.header"));
            gates.push(Gate::pass("packet.checksum"));
            (
                abi::OK,
                Some(memory_size),
                gates,
                format!(
                    "packet ptr=0x{:08x} end=0x{:08x} version={} flags=0x{:04x} body_len={} checksum=0x{:08x}",
                    range.ptr,
                    range.end,
                    packet.version,
                    packet.flags,
                    packet.body_len,
                    packet.checksum
                ),
            )
        }
        Err(err) => {
            gates.push(Gate::fail(err.gate()));
            (
                err.code(),
                Some(memory_size),
                gates,
                format!("packet rejected: {err}"),
            )
        }
    }
}

fn validate_capability_from_guest(
    GuestBytes {
        bytes,
        range,
        memory_size,
        mut gates,
    }: GuestBytes<'_>,
    policy: &Policy,
) -> (i32, Option<u64>, Vec<Gate>, String) {
    match std::str::from_utf8(bytes) {
        Ok(path) if policy.is_path_allowed(path) => {
            gates.push(Gate::pass("utf8"));
            gates.push(Gate::pass("capability"));
            (
                abi::OK,
                Some(memory_size),
                gates,
                format!(
                    "path capability allowed ptr=0x{:08x} end=0x{:08x} path={path}",
                    range.ptr, range.end
                ),
            )
        }
        Ok(path) => {
            let err = AbiError::CapabilityDenied(path.to_owned());
            gates.push(Gate::pass("utf8"));
            gates.push(Gate::fail(err.gate()));
            (
                err.code(),
                Some(memory_size),
                gates,
                format!("path rejected: {err}"),
            )
        }
        Err(_) => {
            let err = AbiError::InvalidUtf8;
            gates.push(Gate::fail(err.gate()));
            (
                err.code(),
                Some(memory_size),
                gates,
                format!("string rejected: {err}"),
            )
        }
    }
}

fn host_write_marker(mut env: FunctionEnvMut<HostState>, ptr: u32, len: u32, align: u32) -> i32 {
    let start = Instant::now();
    let (state, store) = env.data_and_store_mut();
    let (result, memory_size, gates, detail) = match memory::with_guest_bytes_mut(
        state.memory.as_ref(),
        &store,
        ptr,
        len,
        align,
        HOST_WRITE_MARKER.len() as u32,
        write_marker_to_guest,
    ) {
        Ok(outcome) => outcome,
        Err((err, memory_size, gates)) => (
            err.code(),
            memory_size,
            gates,
            format!("range rejected: {err}"),
        ),
    };

    state.telemetry.push(ImportEvent {
        import: "host.write_marker",
        ptr: Some(ptr),
        len: Some(len),
        align: Some(align),
        memory_size,
        result_code: result,
        detail,
        elapsed_us: start.elapsed().as_micros(),
        gates,
    });
    result
}

fn write_marker_to_guest(
    GuestBytesMut {
        bytes,
        range,
        memory_size,
        mut gates,
    }: GuestBytesMut<'_>,
) -> (i32, Option<u64>, Vec<Gate>, String) {
    if bytes.len() != HOST_WRITE_MARKER.len() {
        gates.push(Gate::fail("marker.len"));
        return (
            abi::ERR_HEADER,
            Some(memory_size),
            gates,
            format!(
                "marker write rejected: len={} required={}",
                bytes.len(),
                HOST_WRITE_MARKER.len()
            ),
        );
    }

    bytes.copy_from_slice(HOST_WRITE_MARKER);
    gates.push(Gate::pass("marker.write"));
    (
        abi::OK,
        Some(memory_size),
        gates,
        format!(
            "marker written directly into guest memory ptr=0x{:08x} end=0x{:08x}",
            range.ptr, range.end
        ),
    )
}

fn host_alloc_cap(mut env: FunctionEnvMut<HostState>, requested: u32) -> i32 {
    let start = Instant::now();
    let state = env.data_mut();
    let (result, gates, detail) = if requested > state.policy.max_alloc {
        let err = AbiError::AllocationTooLarge {
            requested,
            max: state.policy.max_alloc,
        };
        (
            err.code(),
            vec![Gate::fail(err.gate())],
            format!("allocation rejected before Vec reserve: {err}"),
        )
    } else {
        (
            abi::OK,
            vec![Gate::pass("alloc.cap")],
            format!(
                "allocation request {requested} within cap {}",
                state.policy.max_alloc
            ),
        )
    };

    state.telemetry.push(ImportEvent {
        import: "host.alloc_cap",
        ptr: None,
        len: Some(requested),
        align: None,
        memory_size: None,
        result_code: result,
        detail,
        elapsed_us: start.elapsed().as_micros(),
        gates,
    });
    result
}

fn host_tick(mut env: FunctionEnvMut<HostState>) -> i32 {
    let start = Instant::now();
    let state = env.data_mut();
    state.telemetry.ticks_seen = state.telemetry.ticks_seen.saturating_add(1);

    let (result, gates, detail) = if state.fuel_remaining == 0 {
        let err = AbiError::BudgetExhausted;
        (
            err.code(),
            vec![Gate::fail(err.gate())],
            format!(
                "fuel exhausted after {} guest ticks",
                state.telemetry.ticks_seen
            ),
        )
    } else {
        state.fuel_remaining -= 1;
        (
            abi::OK,
            vec![Gate::pass("fuel")],
            format!(
                "fuel tick={} remaining={}",
                state.telemetry.ticks_seen, state.fuel_remaining
            ),
        )
    };

    if should_record_tick(state.telemetry.ticks_seen, result) {
        state.telemetry.push(ImportEvent {
            import: "host.tick",
            ptr: None,
            len: None,
            align: None,
            memory_size: None,
            result_code: result,
            detail,
            elapsed_us: start.elapsed().as_micros(),
            gates,
        });
    }

    result
}

fn should_record_tick(tick: u32, result: i32) -> bool {
    result != abi::OK || tick <= 5 || tick.is_multiple_of(64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guests::all_cases;

    #[test]
    fn hostile_guest_corpus_matches_expected_results() {
        let reports = all_cases()
            .iter()
            .map(|case| run_case(case, Backend::Cranelift, Policy::default()))
            .collect::<Vec<_>>();

        for report in &reports {
            assert!(
                report.passed(),
                "{} expected {} got {:?} host_error={:?}",
                report.name,
                abi::code_name(report.expected_code),
                report.actual_code.map(abi::code_name),
                report.host_error
            );
        }
    }
}
