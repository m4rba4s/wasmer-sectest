use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use wasmer_demo::config::{Config, IsolationMode, OutputFormat};
use wasmer_demo::corpus::load_corpus;
use wasmer_demo::guests::{GuestCase, all_cases, find_case, interview_cases, profile_cases};
use wasmer_demo::policy::Policy;
use wasmer_demo::report::{
    print_case_list, print_interview_report, print_reports, print_summary_report,
    render_json_report, render_markdown_report, render_sarif_report, render_text_report,
};
use wasmer_demo::runner::{CaseReport, run_case, run_case_executing_static_fixture};
use wasmer_demo::session::{SessionStore, SessionSummary};
use wasmer_demo::supervisor::{SupervisorOptions, encode_worker_report, run_case_supervised};
use wasmer_demo::tui::{TuiOptions, run_security_dashboard};

fn main() {
    let config = Config::from_args();
    let policy = load_policy(&config);
    if let Some(name) = &config.worker_case {
        run_worker(&config, policy, name);
        return;
    }

    if config.menu {
        run_interactive_menu(&config, policy);
        return;
    }

    let interview_output = config.interview;
    let cases = if let Some(dir) = &config.corpus_dir {
        choose_external_cases(dir, config.case.as_deref())
    } else if let Some(name) = &config.case {
        match find_case(name) {
            Some(case) => vec![case],
            None => {
                eprintln!("unknown case '{name}'");
                eprintln!("available cases:");
                print_case_list(&all_cases());
                std::process::exit(2);
            }
        }
    } else if interview_output {
        interview_cases()
    } else {
        profile_cases(config.profile)
    };

    if config.list {
        print_case_list(&cases);
        return;
    }

    if let Some(dir) = &config.emit_wasm_dir {
        emit_wasm(&cases, dir);
        return;
    }

    if config.tui {
        if config.isolation == IsolationMode::Process {
            eprintln!("--tui does not support --isolate process; use CLI/report mode instead");
            std::process::exit(2);
        }
        let reports = run_security_dashboard(
            &cases,
            config.backend,
            policy.clone(),
            TuiOptions {
                delay: Duration::from_millis(config.tui_delay_ms),
                color: !config.no_color,
            },
        );
        if reports.iter().any(|report| !report.passed()) {
            std::process::exit(1);
        }
        return;
    }

    let reports = collect_reports(&config, &cases, &policy);

    emit_report(&config, &reports, &policy, interview_output);
    if reports.iter().any(|report| !report.passed()) {
        std::process::exit(1);
    }
}

fn collect_reports(config: &Config, cases: &[GuestCase], policy: &Policy) -> Vec<CaseReport> {
    let mut reports = Vec::new();
    for _ in 0..config.repeat {
        for case in cases {
            reports.push(run_selected_case(config, case, policy.clone()));
        }
    }
    reports
}

fn run_selected_case(
    config: &Config,
    case: &GuestCase,
    policy: Policy,
) -> wasmer_demo::runner::CaseReport {
    match config.isolation {
        IsolationMode::InProcess => run_case(case, config.backend, policy),
        IsolationMode::Process => run_case_supervised(
            case,
            config.backend,
            policy,
            SupervisorOptions {
                policy_path: config.policy_path.as_deref(),
                corpus_dir: config.corpus_dir.as_deref(),
                allow_unmetered: config.allow_unmetered,
            },
        ),
    }
}

fn run_worker(config: &Config, policy: Policy, name: &str) {
    let case = if let Some(dir) = &config.corpus_dir {
        choose_external_cases(dir, Some(name))
            .into_iter()
            .next()
            .expect("selected external case exists")
    } else {
        match find_case(name) {
            Some(case) => case,
            None => {
                eprintln!("unknown worker case '{name}'");
                std::process::exit(2);
            }
        }
    };

    let report = if config.worker_execute_static {
        run_case_executing_static_fixture(&case, config.backend, policy)
    } else {
        run_case(&case, config.backend, policy)
    };
    println!("{}", encode_worker_report(&report));
}

fn choose_external_cases(dir: &str, selected: Option<&str>) -> Vec<GuestCase> {
    let cases = match load_corpus(dir) {
        Ok(cases) => cases,
        Err(err) => {
            eprintln!("failed to load corpus: {err}");
            std::process::exit(2);
        }
    };

    if let Some(name) = selected {
        if let Some(case) = cases.iter().find(|case| case.name == name) {
            return vec![case.clone()];
        }
        eprintln!("unknown external corpus case '{name}'");
        eprintln!("available cases:");
        print_case_list(&cases);
        std::process::exit(2);
    }

    cases
}

fn load_policy(config: &Config) -> Policy {
    let mut policy = if let Some(path) = &config.policy_path {
        match Policy::from_file(path) {
            Ok(policy) => policy,
            Err(err) => {
                eprintln!("failed to load policy: {err}");
                std::process::exit(2);
            }
        }
    } else {
        Policy::default()
    };

    if config.allow_unmetered {
        policy.require_tick_import = false;
    }
    if let Some(timeout_ms) = config.timeout_ms {
        policy.supervisor_timeout_ms = timeout_ms;
    }
    if config.worker_execute_static {
        policy.require_tick_import = false;
    }

    policy
}

fn emit_report(
    config: &Config,
    reports: &[wasmer_demo::runner::CaseReport],
    policy: &Policy,
    interview_output: bool,
) {
    match config.output_format {
        OutputFormat::Text if config.report_path.is_none() => {
            if config.summary_only {
                print_summary_report(reports, policy, !config.no_color);
            } else if interview_output {
                print_interview_report(reports, policy, !config.no_color);
            } else {
                print_reports(reports, policy, !config.no_color);
            }
        }
        OutputFormat::Text => write_or_print_report(config, render_text_report(reports, policy)),
        OutputFormat::Json => write_or_print_report(config, render_json_report(reports, policy)),
        OutputFormat::Markdown => {
            write_or_print_report(config, render_markdown_report(reports, policy))
        }
        OutputFormat::Sarif => write_or_print_report(config, render_sarif_report(reports, policy)),
    }
}

fn write_or_print_report(config: &Config, rendered: String) {
    if let Some(path) = &config.report_path {
        if let Err(err) = std::fs::write(path, rendered) {
            eprintln!("failed to write report {path}: {err}");
            std::process::exit(1);
        }
        println!("report written: {path}");
    } else {
        print!("{rendered}");
    }
}

fn run_interactive_menu(config: &Config, policy: Policy) {
    let sessions = SessionStore::default();
    loop {
        print_main_menu(config, &policy, &sessions);
        let Some(input) = prompt("select> ") else {
            println!();
            return;
        };

        let keep_running = match input.as_str() {
            "1" | "tui" => {
                let mut action = config.clone();
                action.profile = wasmer_demo::config::Profile::Interview;
                action.interview = true;
                menu_interview_tui(&action, &policy, &sessions)
            }
            "2" | "interview" => {
                let mut action = config.clone();
                action.profile = wasmer_demo::config::Profile::Interview;
                action.interview = true;
                menu_run_cases(
                    &action,
                    &policy,
                    &sessions,
                    interview_cases(),
                    true,
                    "interview narrative",
                )
            }
            "3" | "all" => {
                let mut action = config.clone();
                action.summary_only = true;
                menu_run_cases(
                    &action,
                    &policy,
                    &sessions,
                    profile_cases(wasmer_demo::config::Profile::All),
                    false,
                    "full corpus summary",
                )
            }
            "4" | "supervisor" => {
                let mut action = config.clone();
                action.isolation = IsolationMode::Process;
                action.timeout_ms = Some(100);
                let mut action_policy = policy.clone();
                action_policy.supervisor_timeout_ms = 100;
                menu_run_cases(
                    &action,
                    &action_policy,
                    &sessions,
                    find_case("non_cooperative_loop").into_iter().collect(),
                    false,
                    "process supervisor timeout proof",
                )
            }
            "5" | "singlepass" => {
                let mut action = config.clone();
                action.backend = wasmer_demo::config::Backend::Singlepass;
                action.summary_only = true;
                menu_run_cases(
                    &action,
                    &policy,
                    &sessions,
                    profile_cases(wasmer_demo::config::Profile::All),
                    false,
                    "singlepass backend summary",
                )
            }
            "6" | "external" => menu_external_corpus(config, &policy, &sessions),
            "7" | "reports" => menu_generate_reports(config, &policy, &sessions),
            "8" | "case" => menu_single_case(config, &policy, &sessions),
            "9" | "list" => {
                print_case_list(&all_cases());
                wait_for_menu()
            }
            "10" | "explain" => menu_explain_case(config, &policy, &sessions),
            "11" | "history" => menu_session_history(&sessions),
            "12" | "latest" => menu_latest_session(&sessions),
            "13" | "bundle" | "export" => menu_export_bundle(config, &policy, &sessions),
            "q" | "quit" | "exit" => {
                println!("closing.");
                return;
            }
            "" => true,
            other => {
                println!("unknown menu option '{other}'");
                true
            }
        };

        if !keep_running {
            println!("closing.");
            return;
        }
    }
}

fn print_main_menu(config: &Config, policy: &Policy, sessions: &SessionStore) {
    println!();
    println!("Wasmer hostile-guest security harness");
    println!(
        "backend={} isolation={} timeout={}ms",
        config.backend.name(),
        config.isolation.name(),
        policy.supervisor_timeout_ms
    );
    println!("  1  live interview cockpit");
    println!("  2  interview narrative");
    println!("  3  full corpus summary");
    println!("  4  supervisor timeout proof");
    println!("  5  singlepass backend summary");
    println!("  6  external corpus example");
    println!("  7  generate reports");
    println!("  8  run one case");
    println!("  9  list cases");
    println!(" 10  explain one case");
    println!(" 11  session history");
    println!(" 12  view latest session");
    println!(" 13  export interview bundle");
    println!("  q  quit");
    println!("session store: {}", sessions.dir().display());
}

fn menu_interview_tui(config: &Config, policy: &Policy, sessions: &SessionStore) -> bool {
    let reports = run_security_dashboard(
        &interview_cases(),
        config.backend,
        policy.clone(),
        TuiOptions {
            delay: Duration::from_millis(config.tui_delay_ms),
            color: !config.no_color,
        },
    );
    if reports.iter().any(|report| !report.passed()) {
        println!("one or more interview cases failed");
    }
    record_session(sessions, "live interview cockpit", config, policy, &reports);
    wait_for_menu()
}

fn menu_run_cases(
    config: &Config,
    policy: &Policy,
    sessions: &SessionStore,
    cases: Vec<GuestCase>,
    interview_output: bool,
    label: &str,
) -> bool {
    if cases.is_empty() {
        println!("{label}: no cases selected");
        return true;
    }

    println!();
    println!("running {label}...");
    let reports = collect_reports(config, &cases, policy);
    emit_report(config, &reports, policy, interview_output);
    if reports.iter().any(|report| !report.passed()) {
        println!("{label}: failed");
    }
    record_session(sessions, label, config, policy, &reports);
    wait_for_menu()
}

fn menu_external_corpus(config: &Config, policy: &Policy, sessions: &SessionStore) -> bool {
    match load_corpus("examples/external-corpus") {
        Ok(cases) => menu_run_cases(
            config,
            policy,
            sessions,
            cases,
            false,
            "external corpus example",
        ),
        Err(err) => {
            println!("failed to load external corpus: {err}");
            wait_for_menu()
        }
    }
}

fn menu_generate_reports(config: &Config, policy: &Policy, sessions: &SessionStore) -> bool {
    println!();
    println!("generating reports...");

    let mut markdown_config = config.clone();
    markdown_config.output_format = OutputFormat::Markdown;
    markdown_config.report_path = Some("target/interview-report.md".into());
    markdown_config.no_color = true;
    let interview = interview_cases();
    let interview_reports = collect_reports(&markdown_config, &interview, policy);
    emit_report(&markdown_config, &interview_reports, policy, false);
    record_session(
        sessions,
        "generated interview markdown report",
        &markdown_config,
        policy,
        &interview_reports,
    );

    let mut sarif_config = config.clone();
    sarif_config.output_format = OutputFormat::Sarif;
    sarif_config.report_path = Some("target/wasmer-harness.sarif".into());
    sarif_config.no_color = true;
    let all = profile_cases(wasmer_demo::config::Profile::All);
    let all_reports = collect_reports(&sarif_config, &all, policy);
    emit_report(&sarif_config, &all_reports, policy, false);
    record_session(
        sessions,
        "generated full corpus sarif report",
        &sarif_config,
        policy,
        &all_reports,
    );

    wait_for_menu()
}

fn menu_single_case(config: &Config, policy: &Policy, sessions: &SessionStore) -> bool {
    let cases = all_cases();
    println!();
    println!("Case picker");
    for (index, case) in cases.iter().enumerate() {
        println!(
            "  {:>2} {:<22} {:<10} {:<8} {}",
            index + 1,
            case.name,
            case.category,
            case.severity,
            case.description
        );
    }
    println!("  b  back to main menu");
    println!("  q  quit");

    loop {
        let Some(input) = prompt("case> ") else {
            return false;
        };
        if matches!(input.as_str(), "b" | "back" | "") {
            return true;
        }
        if matches!(input.as_str(), "q" | "quit" | "exit") {
            return false;
        }

        let selected = if let Ok(number) = input.parse::<usize>() {
            cases.get(number.saturating_sub(1)).cloned()
        } else {
            find_case(&input)
        };

        if let Some(case) = selected {
            let label = format!("single case {}", case.name);
            return menu_run_cases(config, policy, sessions, vec![case], false, &label);
        }
        println!("unknown case '{input}'");
    }
}

fn menu_explain_case(config: &Config, policy: &Policy, sessions: &SessionStore) -> bool {
    let cases = all_cases();
    println!();
    println!("Explain case");
    for (index, case) in cases.iter().enumerate() {
        println!(
            "  {:>2} {:<22} {:<10} {:<8} {}",
            index + 1,
            case.name,
            case.category,
            case.severity,
            case.description
        );
    }
    println!("  b  back to main menu");
    println!("  q  quit");

    loop {
        let Some(input) = prompt("explain> ") else {
            return false;
        };
        if matches!(input.as_str(), "b" | "back" | "") {
            return true;
        }
        if matches!(input.as_str(), "q" | "quit" | "exit") {
            return false;
        }

        let selected = if let Ok(number) = input.parse::<usize>() {
            cases.get(number.saturating_sub(1)).cloned()
        } else {
            find_case(&input)
        };

        if let Some(case) = selected {
            let report = run_selected_case(config, &case, policy.clone());
            print_case_explanation(&report);
            record_session(
                sessions,
                &format!("explain {}", report.name),
                config,
                policy,
                std::slice::from_ref(&report),
            );
            return wait_for_menu();
        }
        println!("unknown case '{input}'");
    }
}

fn menu_session_history(sessions: &SessionStore) -> bool {
    println!();
    let recent = match sessions.list_recent(12) {
        Ok(recent) => recent,
        Err(err) => {
            println!("{err}");
            return wait_for_menu();
        }
    };

    if recent.is_empty() {
        println!("no recorded sessions yet");
        return wait_for_menu();
    }

    print_session_history(&recent);
    println!("  b  back to main menu");
    println!("  q  quit");

    loop {
        let Some(input) = prompt("session> ") else {
            return false;
        };
        if matches!(input.as_str(), "b" | "back" | "") {
            return true;
        }
        if matches!(input.as_str(), "q" | "quit" | "exit") {
            return false;
        }
        if let Ok(number) = input.parse::<usize>()
            && let Some(summary) = recent.get(number.saturating_sub(1))
        {
            print_session_preview(sessions, summary);
            return wait_for_menu();
        }
        println!("unknown session '{input}'");
    }
}

fn menu_latest_session(sessions: &SessionStore) -> bool {
    println!();
    match sessions.latest() {
        Ok(Some(summary)) => print_session_preview(sessions, &summary),
        Ok(None) => println!("no recorded sessions yet"),
        Err(err) => println!("{err}"),
    }
    wait_for_menu()
}

fn menu_export_bundle(config: &Config, policy: &Policy, sessions: &SessionStore) -> bool {
    println!();
    println!("exporting interview bundle...");
    let bundle_dir = Path::new("target/demo-bundle");
    if let Err(err) = fs::create_dir_all(bundle_dir) {
        println!("failed to create {}: {err}", bundle_dir.display());
        return wait_for_menu();
    }

    let mut action = config.clone();
    action.no_color = true;
    action.summary_only = true;

    let interview = interview_cases();
    let interview_reports = collect_reports(&action, &interview, policy);
    let all = profile_cases(wasmer_demo::config::Profile::All);
    let all_reports = collect_reports(&action, &all, policy);

    write_bundle_file(
        &bundle_dir.join("interview-report.md"),
        render_markdown_report(&interview_reports, policy),
    );
    write_bundle_file(
        &bundle_dir.join("telemetry.json"),
        render_json_report(&all_reports, policy),
    );
    write_bundle_file(
        &bundle_dir.join("wasmer-harness.sarif"),
        render_sarif_report(&all_reports, policy),
    );
    write_bundle_file(&bundle_dir.join("README.txt"), bundle_readme());
    copy_bundle_doc("docs/threat-model.md", &bundle_dir.join("threat-model.md"));
    copy_bundle_doc("docs/abi-contract.md", &bundle_dir.join("abi-contract.md"));
    copy_bundle_doc(
        "docs/interview-runbook.md",
        &bundle_dir.join("interview-runbook.md"),
    );

    record_session(
        sessions,
        "exported interview bundle",
        &action,
        policy,
        &all_reports,
    );
    println!("bundle written: {}", bundle_dir.display());
    wait_for_menu()
}

fn record_session(
    sessions: &SessionStore,
    label: &str,
    config: &Config,
    policy: &Policy,
    reports: &[CaseReport],
) {
    match sessions.record_run(label, config, policy, reports) {
        Ok(summary) => {
            println!(
                "session recorded: {} ({} passed, {} failed) -> {}",
                summary.label, summary.passed, summary.failed, summary.path
            );
        }
        Err(err) => println!("session recorder warning: {err}"),
    }
}

fn print_case_explanation(report: &CaseReport) {
    println!();
    println!("Case explanation: {}", report.name);
    println!("  category: {} / {}", report.category, report.severity);
    println!("  attack: {}", report.description);
    println!(
        "  expected boundary result: {}",
        abi_name(report.expected_code)
    );
    println!(
        "  actual boundary result: {}",
        report.actual_code.map(abi_name).unwrap_or("HOST_ERROR")
    );
    println!("  control: {}", report.control);
    println!("  production angle: {}", production_angle(report));
    println!(
        "  runtime: backend={} compile={}us instantiate={}us run={}us wasm={}B",
        report.backend.name(),
        report.compile_us,
        report.instantiate_us,
        report.run_us,
        report.wasm_bytes
    );
    println!(
        "  memory: pages {} -> {} ({:+}), bytes {} -> {}",
        report.memory_before.pages,
        report.memory_after.pages,
        report.memory_before.delta_pages(report.memory_after),
        report.memory_before.bytes,
        report.memory_after.bytes
    );

    if let Some(error) = &report.host_error {
        println!("  host error: {error}");
    }

    for event in &report.telemetry.events {
        println!();
        println!(
            "  import: {} -> {}",
            event.import,
            abi_name(event.result_code)
        );
        println!(
            "  args: ptr={} len={} align={} memory={}",
            fmt_ptr(event.ptr),
            fmt_value(event.len),
            fmt_value(event.align),
            event
                .memory_size
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into())
        );
        println!("  gates:");
        for gate in &event.gates {
            let status = if gate.passed { "ok" } else { "fail" };
            println!("    - {:<28} {}", gate.name, status);
        }
        println!("  evidence: {}", event.detail);
    }

    if report.telemetry.events.is_empty() {
        println!("  telemetry: no import events were logged");
    }
}

fn production_angle(report: &CaseReport) -> &'static str {
    match report.category.as_str() {
        "abi" => {
            "versioned host/guest contracts must reject malformed layouts before parsing payloads"
        }
        "memory" => {
            "every guest pointer range needs overflow-safe arithmetic and fresh MemoryView state"
        }
        "capability" => {
            "host resources should be exact capabilities, not ambient filesystem authority"
        }
        "resource" => "host-side CPU, memory, and allocation budgets need hard policy gates",
        "integrity" => {
            "structured payloads need integrity checks after the outer memory range is proven safe"
        }
        _ => "the host import boundary is treated as untrusted input, not trusted IPC",
    }
}

fn print_session_history(sessions: &[SessionSummary]) {
    println!("Recorded sessions");
    println!(
        "  {:>2} {:<18} {:<32} {:<10} {:<10} {:>7} {:>7}",
        "#", "id", "label", "backend", "isolate", "pass", "fail"
    );
    for (index, summary) in sessions.iter().enumerate() {
        println!(
            "  {:>2} {:<18} {:<32} {:<10} {:<10} {:>7} {:>7}",
            index + 1,
            truncate_id(&summary.id),
            truncate_text(&summary.label, 32),
            summary.backend,
            summary.isolation,
            summary.passed,
            summary.failed
        );
    }
}

fn print_session_preview(sessions: &SessionStore, summary: &SessionSummary) {
    println!(
        "session {}: {} | {} passed, {} failed | {}",
        summary.id, summary.label, summary.passed, summary.failed, summary.path
    );
    match sessions.read_session(summary) {
        Ok(contents) => {
            println!();
            for (index, line) in contents.lines().take(80).enumerate() {
                println!("{:>3}: {line}", index + 1);
            }
            if contents.lines().count() > 80 {
                println!("... truncated; full file: {}", summary.path);
            }
        }
        Err(err) => println!("{err}"),
    }
}

fn write_bundle_file(path: &Path, contents: String) {
    match fs::write(path, contents) {
        Ok(()) => println!("  wrote {}", path.display()),
        Err(err) => println!("  failed {}: {err}", path.display()),
    }
}

fn copy_bundle_doc(source: &str, destination: &Path) {
    match fs::read_to_string(source) {
        Ok(contents) => write_bundle_file(destination, contents),
        Err(err) => println!("  failed {source}: {err}"),
    }
}

fn bundle_readme() -> String {
    [
        "Wasmer hostile-guest security harness demo bundle",
        "",
        "Generated files:",
        "- interview-report.md: curated Markdown evidence for the interview path",
        "- telemetry.json: full corpus machine-readable telemetry",
        "- wasmer-harness.sarif: CI/security-dashboard regression signal",
        "- threat-model.md: boundary and attacker model",
        "- abi-contract.md: guest/host ABI contract",
        "- interview-runbook.md: live demo script",
        "",
        "Recommended live command:",
        "cargo run --release -- --menu",
        "",
    ]
    .join("\n")
}

fn abi_name(code: i32) -> &'static str {
    wasmer_demo::abi::code_name(code)
}

fn fmt_ptr(value: Option<u32>) -> String {
    value
        .map(|value| format!("0x{value:08x}"))
        .unwrap_or_else(|| "-".into())
}

fn fmt_value(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".into())
}

fn truncate_id(value: &str) -> String {
    if value.len() <= 18 {
        value.to_string()
    } else {
        value[value.len() - 18..].to_string()
    }
}

fn truncate_text(value: &str, max_chars: usize) -> String {
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

fn wait_for_menu() -> bool {
    println!();
    let Some(input) = prompt("[Enter] back to menu, q quit> ") else {
        return false;
    };
    !matches!(input.as_str(), "q" | "quit" | "exit")
}

fn prompt(label: &str) -> Option<String> {
    print!("{label}");
    let _ = io::stdout().flush();

    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(0) => None,
        Ok(_) => Some(input.trim().to_string()),
        Err(_) => None,
    }
}

fn emit_wasm(cases: &[wasmer_demo::guests::GuestCase], dir: &str) {
    let dir = std::path::Path::new(dir);
    if let Err(err) = std::fs::create_dir_all(dir) {
        eprintln!("failed to create {}: {err}", dir.display());
        std::process::exit(1);
    }

    for case in cases {
        let wasm = match case.source.wasm_bytes() {
            Ok(wasm) => wasm,
            Err(err) => {
                eprintln!("failed to parse {}: {err}", case.name);
                std::process::exit(1);
            }
        };
        let path = dir.join(format!("{}.wasm", case.name));
        if let Err(err) = std::fs::write(&path, wasm) {
            eprintln!("failed to write {}: {err}", path.display());
            std::process::exit(1);
        }
        println!("{}", path.display());
    }
}
