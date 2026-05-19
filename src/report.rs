use std::process::Command;

use crate::abi;
use crate::ansi;
use crate::policy::Policy;
use crate::runner::CaseReport;
use crate::telemetry::{Gate, ImportEvent};

pub fn print_case_list(cases: &[crate::guests::GuestCase]) {
    for case in cases {
        println!(
            "{:<22} {:<10} {:<8} {:<24} expected {:<16} {}",
            case.name,
            case.category,
            case.severity,
            case.ttp,
            abi::code_name(case.expected_code),
            case.description
        );
    }
}

pub fn print_reports(reports: &[CaseReport], policy: &Policy, color: bool) {
    print_header(reports, policy, color);
    for report in reports {
        print_case(report, color);
    }
    print_summary(reports, color);
}

pub fn print_interview_report(reports: &[CaseReport], policy: &Policy, color: bool) {
    print_header(reports, policy, color);
    println!("mode: interview narrative");
    println!("threat model: malicious guest controls linear memory and import arguments");
    println!("adversary emulation: deterministic APT-style TTP chain without weaponized behavior");
    println!();

    for report in reports {
        print_interview_case(report, color);
    }
    print_summary(reports, color);
}

pub fn print_summary_report(reports: &[CaseReport], policy: &Policy, color: bool) {
    print_header(reports, policy, color);
    let passed = reports.iter().filter(|report| report.passed()).count();
    let failed = reports.len().saturating_sub(passed);
    let total_compile_us: u128 = reports.iter().map(|report| report.compile_us).sum();
    let total_instantiate_us: u128 = reports.iter().map(|report| report.instantiate_us).sum();
    let total_run_us: u128 = reports.iter().map(|report| report.run_us).sum();
    let total_imports: usize = reports
        .iter()
        .map(|report| report.telemetry.events.len())
        .sum();
    let total_ticks: u32 = reports
        .iter()
        .map(|report| report.telemetry.ticks_seen)
        .sum();

    println!(
        "aggregate compile={}us instantiate={}us run={}us imports_logged={} ticks_seen={}",
        total_compile_us, total_instantiate_us, total_run_us, total_imports, total_ticks
    );

    for report in reports.iter().filter(|report| !report.passed()) {
        print_case(report, color);
    }

    let color_code = if failed == 0 { ansi::GREEN } else { ansi::RED };
    println!(
        "{}",
        paint(
            color,
            color_code,
            format!(
                "summary: {passed}/{} passed, {failed} failed",
                reports.len()
            )
        )
    );
}

pub fn render_json_report(reports: &[CaseReport], policy: &Policy) -> String {
    let passed = reports.iter().filter(|report| report.passed()).count();
    let failed = reports.len().saturating_sub(passed);
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"tool\": \"wasmer-hostile-guest-security-harness\",\n");
    out.push_str("  \"runtime_crate\": \"wasmer=6.1.0\",\n");
    out.push_str(&format!(
        "  \"policy\": {{\"max_packet_len\": {}, \"max_cap_string_len\": {}, \"max_alloc\": {}, \"fuel\": {}, \"max_memory_pages\": {}, \"require_tick_import\": {}, \"supervisor_timeout_ms\": {}}},\n",
        policy.max_packet_len,
        policy.max_cap_string_len,
        policy.max_alloc,
        policy.initial_fuel,
        policy.max_memory_pages,
        policy.require_tick_import,
        policy.supervisor_timeout_ms
    ));
    out.push_str(&format!(
        "  \"summary\": {{\"total\": {}, \"passed\": {}, \"failed\": {}}},\n",
        reports.len(),
        passed,
        failed
    ));
    out.push_str("  \"cases\": [\n");
    for (index, report) in reports.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        out.push_str(&render_json_case(report));
    }
    out.push_str("\n  ]\n");
    out.push_str("}\n");
    out
}

pub fn render_markdown_report(reports: &[CaseReport], policy: &Policy) -> String {
    let passed = reports.iter().filter(|report| report.passed()).count();
    let failed = reports.len().saturating_sub(passed);
    let mut out = String::new();
    out.push_str("# Wasmer Hostile-Guest Security Harness\n\n");
    out.push_str("## Summary\n\n");
    out.push_str(&format!(
        "- Runtime crate: `wasmer=6.1.0`\n- Cases: `{}`\n- Passed: `{}`\n- Failed: `{}`\n- Policy: max_packet={} max_cap_string={} max_alloc={} fuel={} max_memory_pages={} require_tick_import={} supervisor_timeout_ms={}\n\n",
        reports.len(),
        passed,
        failed,
        policy.max_packet_len,
        policy.max_cap_string_len,
        policy.max_alloc,
        policy.initial_fuel,
        policy.max_memory_pages,
        policy.require_tick_import,
        policy.supervisor_timeout_ms
    ));
    out.push_str("## Cases\n\n");
    out.push_str("| Case | Stage | TTP | Category | Severity | Expected | Actual | Result |\n");
    out.push_str("|---|---|---|---|---:|---|---|---|\n");
    for report in reports {
        let actual = report
            .actual_code
            .map(abi::code_name)
            .unwrap_or("HOST_ERROR");
        let result = if report.passed() { "PASS" } else { "FAIL" };
        out.push_str(&format!(
            "| `{}` | {} | `{}` | {} | {} | `{}` | `{}` | {} |\n",
            report.name,
            report.stage,
            report.ttp,
            report.category,
            report.severity,
            abi::code_name(report.expected_code),
            actual,
            result
        ));
    }
    out.push_str("\n## Evidence\n\n");
    for report in reports {
        out.push_str(&format!("### `{}`\n\n", report.name));
        out.push_str(&format!(
            "- Attack: {}\n- Stage: {}\n- TTP: `{}`\n- Detection: {}\n- Control: {}\n- Runtime: compile={}us instantiate={}us run={}us\n",
            report.description,
            report.stage,
            report.ttp,
            report.detection,
            report.control,
            report.compile_us,
            report.instantiate_us,
            report.run_us
        ));
        if let Some(event) = report.telemetry.events.last() {
            out.push_str(&format!(
                "- Boundary: `{}` => `{}` `{}`\n- Gates: `{}`\n- Evidence: {}\n",
                event.import,
                event.decision(),
                abi::code_name(event.result_code),
                gates_plain(&event.gates),
                event.detail
            ));
        }
        out.push('\n');
    }
    out
}

pub fn render_sarif_report(reports: &[CaseReport], policy: &Policy) -> String {
    let passed = reports.iter().filter(|report| report.passed()).count();
    let failed = reports.len().saturating_sub(passed);
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"$schema\": \"https://json.schemastore.org/sarif-2.1.0.json\",\n");
    out.push_str("  \"version\": \"2.1.0\",\n");
    out.push_str("  \"runs\": [\n");
    out.push_str("    {\n");
    out.push_str("      \"tool\": {\n");
    out.push_str("        \"driver\": {\n");
    out.push_str("          \"name\": \"wasmer-hostile-guest-security-harness\",\n");
    out.push_str("          \"informationUri\": \"https://github.com/wasmerio/wasmer\",\n");
    out.push_str("          \"semanticVersion\": \"0.1.0\",\n");
    out.push_str("          \"rules\": [\n");
    for (index, report) in reports.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        out.push_str(&render_sarif_rule(report));
    }
    out.push_str("\n          ]\n");
    out.push_str("        }\n");
    out.push_str("      },\n");
    out.push_str(&format!(
        "      \"invocations\": [{{\"executionSuccessful\": {}, \"properties\": {{\"totalCases\": {}, \"passedCases\": {}, \"failedCases\": {}, \"maxPacketLen\": {}, \"maxCapStringLen\": {}, \"maxAlloc\": {}, \"fuel\": {}, \"maxMemoryPages\": {}, \"requireTickImport\": {}, \"supervisorTimeoutMs\": {}}}}}],\n",
        failed == 0,
        reports.len(),
        passed,
        failed,
        policy.max_packet_len,
        policy.max_cap_string_len,
        policy.max_alloc,
        policy.initial_fuel,
        policy.max_memory_pages,
        policy.require_tick_import,
        policy.supervisor_timeout_ms
    ));
    out.push_str("      \"results\": [");
    let failures = reports
        .iter()
        .filter(|report| !report.passed())
        .collect::<Vec<_>>();
    if !failures.is_empty() {
        out.push('\n');
    }
    for (index, report) in failures.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        out.push_str(&render_sarif_result(report));
    }
    if !failures.is_empty() {
        out.push('\n');
        out.push_str("      ");
    }
    out.push_str("]\n");
    out.push_str("    }\n");
    out.push_str("  ]\n");
    out.push_str("}\n");
    out
}

pub fn render_text_report(reports: &[CaseReport], policy: &Policy) -> String {
    let passed = reports.iter().filter(|report| report.passed()).count();
    let failed = reports.len().saturating_sub(passed);
    let mut out = String::new();
    out.push_str("Wasmer hostile-guest security harness\n");
    out.push_str(&format!(
        "runtime crate wasmer=6.1.0 | cases={} | policy max_packet={} max_cap_string={} max_alloc={} fuel={} max_memory_pages={} require_tick_import={} supervisor_timeout_ms={}\n\n",
        reports.len(),
        policy.max_packet_len,
        policy.max_cap_string_len,
        policy.max_alloc,
        policy.initial_fuel,
        policy.max_memory_pages,
        policy.require_tick_import,
        policy.supervisor_timeout_ms
    ));
    for report in reports {
        let actual = report
            .actual_code
            .map(abi::code_name)
            .unwrap_or("HOST_ERROR");
        let status = if report.passed() { "PASS" } else { "FAIL" };
        out.push_str(&format!(
            "[{}] {:<22} {:<10} {:<8} expected {:<16} got {:<16} {}\n",
            status,
            report.name,
            report.category,
            report.severity,
            abi::code_name(report.expected_code),
            actual,
            report.description
        ));
        out.push_str(&format!(
            "  emulation: stage={} ttp={}\n",
            report.stage, report.ttp
        ));
        out.push_str(&format!("  control: {}\n", report.control));
        out.push_str(&format!("  detection: {}\n", report.detection));
        if let Some(event) = report.telemetry.events.last() {
            out.push_str(&format!(
                "  boundary: {} => {} {} gates={} evidence={}\n",
                event.import,
                event.decision(),
                abi::code_name(event.result_code),
                gates_plain(&event.gates),
                event.detail
            ));
        }
    }
    out.push_str(&format!(
        "\nsummary: {passed}/{} passed, {failed} failed\n",
        reports.len()
    ));
    out
}

fn print_interview_case(report: &CaseReport, color: bool) {
    let status = if report.passed() {
        paint(color, ansi::GREEN, "PASS")
    } else {
        paint(color, ansi::RED, "FAIL")
    };
    let actual = report
        .actual_code
        .map(abi::code_name)
        .unwrap_or("HOST_ERROR");
    let event = report.telemetry.events.last();

    println!(
        "[{}] {} -> expected {} got {}",
        status,
        report.name,
        abi::code_name(report.expected_code),
        actual
    );
    println!("  attack: {}", report.description);
    println!(
        "  class: category={} severity={}",
        report.category, report.severity
    );
    println!("  emulation: stage={} ttp={}", report.stage, report.ttp);
    println!("  control: {}", report.control);
    println!("  detection: {}", report.detection);
    println!(
        "  runtime: compile={}us instantiate={}us run={}us memory_pages {}->{}",
        report.compile_us,
        report.instantiate_us,
        report.run_us,
        report.memory_before.pages,
        report.memory_after.pages
    );

    if let Some(event) = event {
        println!(
            "  host boundary: {} => {} {}",
            event.import,
            event.decision(),
            abi::code_name(event.result_code)
        );
        println!("  gates: {}", gates(&event.gates, color));
        println!("  evidence: {}", event.detail);
    }

    if let Some(error) = &report.host_error {
        println!("  host_error: {error}");
    }
    println!();
}

fn print_header(reports: &[CaseReport], policy: &Policy, color: bool) {
    let backend = reports
        .first()
        .map(|report| report.backend.name())
        .unwrap_or("cranelift");
    println!(
        "{}",
        paint(color, ansi::BOLD, "Wasmer hostile-guest security harness")
    );
    println!(
        "runtime crate wasmer=6.1.0 | {} | backend={} | cases={}",
        command_version("wasmer", &["--version"])
            .unwrap_or_else(|| "wasmer cli unavailable".into()),
        backend,
        reports.len()
    );
    println!(
        "{}",
        command_version("rustc", &["--version"])
            .unwrap_or_else(|| "rustc version unavailable".into())
    );
    println!(
        "policy max_packet={} max_cap_string={} max_alloc={} fuel={} max_memory_pages={} require_tick_import={} supervisor_timeout_ms={} allowed_paths={:?}",
        policy.max_packet_len,
        policy.max_cap_string_len,
        policy.max_alloc,
        policy.initial_fuel,
        policy.max_memory_pages,
        policy.require_tick_import,
        policy.supervisor_timeout_ms,
        policy.allowed_paths()
    );
    println!();
}

fn print_case(report: &CaseReport, color: bool) {
    let badge = if report.passed() {
        paint(color, ansi::GREEN, "PASS")
    } else {
        paint(color, ansi::RED, "FAIL")
    };
    let expected = abi::code_name(report.expected_code);
    let actual = report
        .actual_code
        .map(abi::code_name)
        .unwrap_or("HOST_ERROR");

    println!(
        "[{}] {:<22} {:<10} {:<8} expected {:<16} got {:<16} {}",
        badge, report.name, report.category, report.severity, expected, actual, report.description
    );
    println!("  emulation: stage={} ttp={}", report.stage, report.ttp);
    println!("  control: {}", report.control);
    println!("  detection: {}", report.detection);

    if let Some(error) = &report.host_error {
        println!("  host_error: {error}");
    }

    println!(
        "  timing compile={}us instantiate={}us run={}us | wasm={}B",
        report.compile_us, report.instantiate_us, report.run_us, report.wasm_bytes
    );
    println!(
        "  memory pages {} -> {} ({:+}) | bytes {} -> {} | ptr 0x{:x} -> 0x{:x}",
        report.memory_before.pages,
        report.memory_after.pages,
        report.memory_before.delta_pages(report.memory_after),
        report.memory_before.bytes,
        report.memory_after.bytes,
        report.memory_before.data_ptr,
        report.memory_after.data_ptr
    );
    println!(
        "  imports logged={} ticks_seen={}",
        report.telemetry.events.len(),
        report.telemetry.ticks_seen
    );

    for event in &report.telemetry.events {
        print_event(event, color);
    }
    println!();
}

fn print_event(event: &ImportEvent, color: bool) {
    let decision_color = if event.result_code == abi::OK {
        ansi::GREEN
    } else {
        ansi::RED
    };
    let ptr = event
        .ptr
        .map(|value| format!("ptr=0x{value:08x}"))
        .unwrap_or_else(|| "ptr=-".into());
    let len = event
        .len
        .map(|value| format!("len={value}"))
        .unwrap_or_else(|| "len=-".into());
    let align = event
        .align
        .map(|value| format!("align={value}"))
        .unwrap_or_else(|| "align=-".into());
    let mem = event
        .memory_size
        .map(|value| format!("mem={value}"))
        .unwrap_or_else(|| "mem=-".into());

    println!(
        "    {} {} {} {} {} => {} {} ({}) in {}us",
        event.import,
        ptr,
        len,
        align,
        mem,
        paint(color, decision_color, event.decision()),
        abi::code_name(event.result_code),
        gates(&event.gates, color),
        event.elapsed_us
    );
    println!("      {}", event.detail);
}

fn gates(gates: &[Gate], color: bool) -> String {
    gates
        .iter()
        .map(|gate| {
            let status = if gate.passed {
                paint(color, ansi::GREEN, "ok")
            } else {
                paint(color, ansi::RED, "fail")
            };
            format!("{}:{status}", gate.name)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn gates_plain(gates: &[Gate]) -> String {
    gates
        .iter()
        .map(|gate| {
            let status = if gate.passed { "ok" } else { "fail" };
            format!("{}:{status}", gate.name)
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_json_case(report: &CaseReport) -> String {
    let actual = report
        .actual_code
        .map(abi::code_name)
        .unwrap_or("HOST_ERROR");
    let mut out = String::new();
    out.push_str("    {\n");
    out.push_str(&format!(
        "      \"name\": \"{}\",\n",
        json_escape(&report.name)
    ));
    out.push_str(&format!(
        "      \"category\": \"{}\",\n",
        json_escape(&report.category)
    ));
    out.push_str(&format!(
        "      \"severity\": \"{}\",\n",
        json_escape(&report.severity)
    ));
    out.push_str(&format!(
        "      \"stage\": \"{}\",\n",
        json_escape(&report.stage)
    ));
    out.push_str(&format!(
        "      \"ttp\": \"{}\",\n",
        json_escape(&report.ttp)
    ));
    out.push_str(&format!(
        "      \"description\": \"{}\",\n",
        json_escape(&report.description)
    ));
    out.push_str(&format!(
        "      \"control\": \"{}\",\n",
        json_escape(&report.control)
    ));
    out.push_str(&format!(
        "      \"detection\": \"{}\",\n",
        json_escape(&report.detection)
    ));
    out.push_str(&format!(
        "      \"expected\": \"{}\",\n",
        abi::code_name(report.expected_code)
    ));
    out.push_str(&format!("      \"actual\": \"{}\",\n", actual));
    out.push_str(&format!("      \"passed\": {},\n", report.passed()));
    out.push_str(&format!(
        "      \"timing_us\": {{\"compile\": {}, \"instantiate\": {}, \"run\": {}}},\n",
        report.compile_us, report.instantiate_us, report.run_us
    ));
    out.push_str("      \"events\": [");
    for (index, event) in report.telemetry.events.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!(
            "{{\"import\": \"{}\", \"decision\": \"{}\", \"result\": \"{}\", \"detail\": \"{}\", \"gates\": \"{}\"}}",
            json_escape(event.import),
            event.decision(),
            abi::code_name(event.result_code),
            json_escape(&event.detail),
            json_escape(&gates_plain(&event.gates))
        ));
    }
    out.push_str("]\n");
    out.push_str("    }");
    out
}

fn render_sarif_rule(report: &CaseReport) -> String {
    format!(
        "            {{\"id\": \"{}\", \"name\": \"{}\", \"shortDescription\": {{\"text\": \"{}\"}}, \"fullDescription\": {{\"text\": \"{}\"}}, \"properties\": {{\"category\": \"{}\", \"severity\": \"{}\", \"stage\": \"{}\", \"ttp\": \"{}\", \"expected\": \"{}\", \"control\": \"{}\", \"detection\": \"{}\"}}}}",
        sarif_rule_id(report),
        json_escape(&report.name),
        json_escape(&report.description),
        json_escape(&report.control),
        json_escape(&report.category),
        json_escape(&report.severity),
        json_escape(&report.stage),
        json_escape(&report.ttp),
        abi::code_name(report.expected_code),
        json_escape(&report.control),
        json_escape(&report.detection)
    )
}

fn render_sarif_result(report: &CaseReport) -> String {
    let actual = report
        .actual_code
        .map(abi::code_name)
        .unwrap_or("HOST_ERROR");
    let detail = report
        .host_error
        .as_deref()
        .or_else(|| {
            report
                .telemetry
                .events
                .last()
                .map(|event| event.detail.as_str())
        })
        .unwrap_or("no boundary telemetry captured");
    format!(
        "        {{\"ruleId\": \"{}\", \"level\": \"{}\", \"message\": {{\"text\": \"{} expected {} but got {}; {}\"}}, \"locations\": [{{\"physicalLocation\": {{\"artifactLocation\": {{\"uri\": \"{}\"}}, \"region\": {{\"startLine\": 1}}}}}}], \"properties\": {{\"category\": \"{}\", \"severity\": \"{}\", \"stage\": \"{}\", \"ttp\": \"{}\", \"expected\": \"{}\", \"actual\": \"{}\", \"control\": \"{}\", \"detection\": \"{}\"}}}}",
        sarif_rule_id(report),
        sarif_level(report),
        json_escape(&report.name),
        abi::code_name(report.expected_code),
        actual,
        json_escape(detail),
        json_escape(&report.source_path),
        json_escape(&report.category),
        json_escape(&report.severity),
        json_escape(&report.stage),
        json_escape(&report.ttp),
        abi::code_name(report.expected_code),
        actual,
        json_escape(&report.control),
        json_escape(&report.detection)
    )
}

fn sarif_rule_id(report: &CaseReport) -> String {
    format!("wasmer-harness/{}", report.name)
}

fn sarif_level(report: &CaseReport) -> &'static str {
    match report.severity.as_str() {
        "critical" | "high" => "error",
        "medium" => "warning",
        _ => "note",
    }
}

fn json_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out
}

fn print_summary(reports: &[CaseReport], color: bool) {
    let passed = reports.iter().filter(|report| report.passed()).count();
    let failed = reports.len().saturating_sub(passed);
    let color_code = if failed == 0 { ansi::GREEN } else { ansi::RED };
    println!(
        "{}",
        paint(
            color,
            color_code,
            format!(
                "summary: {passed}/{} passed, {failed} failed",
                reports.len()
            )
        )
    );
}

fn paint(color: bool, color_code: &str, text: impl AsRef<str>) -> String {
    if color {
        ansi::paint(color_code, text)
    } else {
        text.as_ref().to_string()
    }
}

fn command_version(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() {
        None
    } else {
        Some(stdout)
    }
}
