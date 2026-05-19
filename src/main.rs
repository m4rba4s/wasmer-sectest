use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::Path;
use std::time::Duration;

use wasmer_demo::config::{Config, IsolationMode, OutputFormat};
use wasmer_demo::corpus::load_corpus;
use wasmer_demo::guests::{
    GuestCase, all_cases, campaign_cases, find_case, interview_cases, profile_cases,
};
use wasmer_demo::policy::Policy;
use wasmer_demo::report::{
    print_case_list, print_interview_report, print_reports, print_summary_report,
    render_json_report, render_markdown_report, render_sarif_report, render_text_report,
};
use wasmer_demo::runner::{CaseReport, run_case, run_case_executing_static_fixture};
use wasmer_demo::session::{SessionStore, SessionSummary};
use wasmer_demo::supervisor::{SupervisorOptions, encode_worker_report, run_case_supervised};
use wasmer_demo::tui::{TuiOptions, run_security_dashboard};
use wasmer_demo::visual;

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
    let mut notice = None;
    loop {
        print_main_menu(config, &policy, &sessions, notice.take().as_deref());
        let Some(input) = prompt("select> ") else {
            println!();
            return;
        };
        let command = input.to_ascii_lowercase();

        let keep_running = match command.as_str() {
            "1" | "t" | "tui" | "live" => {
                let mut action = config.clone();
                action.profile = wasmer_demo::config::Profile::Interview;
                action.interview = true;
                menu_interview_tui(&action, &policy, &sessions)
            }
            "2" | "i" | "interview" => {
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
            "3" | "a" | "all" => {
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
            "4" | "ops" | "campaign" | "adversary" | "apt" => {
                let mut action = config.clone();
                action.profile = wasmer_demo::config::Profile::Campaign;
                action.interview = true;
                menu_run_cases(
                    &action,
                    &policy,
                    &sessions,
                    campaign_cases(),
                    true,
                    "adversary emulation campaign",
                )
            }
            "5" | "s" | "supervisor" | "timeout" => {
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
            "6" | "sp" | "singlepass" => {
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
            "7" | "x" | "external" | "corpus" => menu_external_corpus(config, &policy, &sessions),
            "8" | "rpt" | "reports" => menu_generate_reports(config, &policy, &sessions),
            "9" | "c" | "case" | "run" => menu_single_case(config, &policy, &sessions),
            "10" | "l" | "list" => {
                print_case_list(&all_cases());
                wait_for_menu()
            }
            "11" | "e" | "explain" => menu_explain_case(config, &policy, &sessions),
            "12" | "hist" | "history" => menu_session_history(config, &sessions),
            "13" | "latest" | "last" => menu_latest_session(config, &sessions),
            "14" | "bundle" | "export" => menu_export_bundle(config, &policy, &sessions),
            "15" | "g" | "graph" | "charts" => menu_graphs_dashboard(config, &policy, &sessions),
            "?" | "h" | "help" => {
                print_menu_help();
                wait_for_menu()
            }
            "" | "refresh" | "redraw" => true,
            "q" | "quit" | "exit" => {
                println!("closing.");
                return;
            }
            other => {
                notice = Some(format!(
                    "Unknown option '{other}'. Use 1-15, aliases like t/i/ops/c/e/l/g, ? for help, or q to quit."
                ));
                true
            }
        };

        if !keep_running {
            println!("closing.");
            return;
        }
    }
}

fn print_main_menu(
    config: &Config,
    policy: &Policy,
    sessions: &SessionStore,
    notice: Option<&str>,
) {
    clear_screen_if_interactive();
    println!();
    println!("Wasmer hostile-guest security harness");
    println!(
        "backend={} isolation={} timeout={}ms",
        config.backend.name(),
        config.isolation.name(),
        policy.supervisor_timeout_ms
    );
    if let Some(notice) = notice {
        println!("notice: {notice}");
    }
    println!("  1  [t]  live interview cockpit");
    println!("  2  [i]  interview narrative");
    println!("  3  [a]  full corpus summary");
    println!("  4  [ops] adversary emulation campaign");
    println!("  5  [s]  supervisor timeout proof");
    println!("  6  [sp] singlepass backend summary");
    println!("  7  [x]  external corpus example");
    println!("  8  [rpt] generate reports");
    println!("  9  [c]  run one case");
    println!(" 10  [l]  list cases");
    println!(" 11  [e]  explain one case");
    println!(" 12  [hist] session history");
    println!(" 13  [last] view latest session");
    println!(" 14  [export] export interview bundle");
    println!(" 15  [g]    charts dashboard");
    println!("  ?       help");
    println!("  q       quit");
    println!("session store: {}", sessions.dir().display());
}

fn print_menu_help() {
    println!();
    println!("Menu help");
    println!("  Use the number or the alias in brackets.");
    println!("  Press Enter to redraw the menu.");
    println!("  Case pickers accept a number, exact case name, or substring.");
    println!("  The ops/campaign mode is defensive adversary emulation, not weaponized code.");
    println!("  The charts dashboard shows recent session bars, corpus mix, and policy limits.");
    println!("  Invalid input never exits the program; use q/quit/exit explicitly.");
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

    let mut campaign_config = config.clone();
    campaign_config.output_format = OutputFormat::Markdown;
    campaign_config.report_path = Some("target/adversary-campaign.md".into());
    campaign_config.no_color = true;
    let campaign = campaign_cases();
    let campaign_reports = collect_reports(&campaign_config, &campaign, policy);
    emit_report(&campaign_config, &campaign_reports, policy, false);
    record_session(
        sessions,
        "generated adversary campaign markdown report",
        &campaign_config,
        policy,
        &campaign_reports,
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
    print_case_picker_help(&cases);

    loop {
        let Some(input) = prompt("case> ") else {
            return false;
        };
        let command = input.to_ascii_lowercase();
        if matches!(command.as_str(), "b" | "back" | "") {
            return true;
        }
        if matches!(command.as_str(), "q" | "quit" | "exit") {
            return false;
        }
        if matches!(command.as_str(), "l" | "list" | "?" | "help") {
            print_case_picker_help(&cases);
            continue;
        }

        let selected = select_case(&cases, &input);
        if let Some(case) = selected {
            let label = format!("single case {}", case.name);
            return menu_run_cases(config, policy, sessions, vec![case], false, &label);
        }
        println!("unknown case '{input}'. Type list, a number, a name, substring, back, or quit.");
    }
}

fn menu_explain_case(config: &Config, policy: &Policy, sessions: &SessionStore) -> bool {
    let cases = all_cases();
    println!();
    println!("Explain case");
    print_case_picker_help(&cases);

    loop {
        let Some(input) = prompt("explain> ") else {
            return false;
        };
        let command = input.to_ascii_lowercase();
        if matches!(command.as_str(), "b" | "back" | "") {
            return true;
        }
        if matches!(command.as_str(), "q" | "quit" | "exit") {
            return false;
        }
        if matches!(command.as_str(), "l" | "list" | "?" | "help") {
            print_case_picker_help(&cases);
            continue;
        }

        let selected = select_case(&cases, &input);
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
        println!("unknown case '{input}'. Type list, a number, a name, substring, back, or quit.");
    }
}

fn print_case_picker_help(cases: &[GuestCase]) {
    for (index, case) in cases.iter().enumerate() {
        println!(
            "  {:>2} {:<24} {:<12} {:<8} {}",
            index + 1,
            case.name,
            case.category,
            case.severity,
            case.description
        );
    }
    println!("  list/?  reprint this list");
    println!("  b       back to main menu");
    println!("  q       quit");
}

fn select_case(cases: &[GuestCase], input: &str) -> Option<GuestCase> {
    let input = input.trim();
    if let Ok(number) = input.parse::<usize>() {
        return cases.get(number.saturating_sub(1)).cloned();
    }
    find_case(input).or_else(|| {
        let needle = input.to_ascii_lowercase();
        cases
            .iter()
            .find(|case| case.name.to_ascii_lowercase().contains(&needle))
            .cloned()
    })
}

fn menu_session_history(config: &Config, sessions: &SessionStore) -> bool {
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

    print_session_charts(&recent, !config.no_color);
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

fn menu_latest_session(config: &Config, sessions: &SessionStore) -> bool {
    println!();
    match sessions.latest() {
        Ok(Some(summary)) => {
            let recent = sessions.list_recent(8).unwrap_or_default();
            if !recent.is_empty() {
                print_session_charts(&recent, !config.no_color);
            }
            print_session_preview(sessions, &summary)
        }
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

fn menu_graphs_dashboard(config: &Config, policy: &Policy, sessions: &SessionStore) -> bool {
    println!();
    println!("Charts dashboard");

    let recent = match sessions.list_recent(8) {
        Ok(recent) => recent,
        Err(err) => {
            println!("{err}");
            return wait_for_menu();
        }
    };

    let cases = all_cases();
    print_session_charts(&recent, !config.no_color);
    print_case_mix_chart(&cases, !config.no_color);
    print_stage_mix_chart(&cases, !config.no_color);
    print_policy_limits_chart(policy, !config.no_color);
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
    println!("  stage: {}", report.stage);
    println!("  ttp: {}", report.ttp);
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
    println!("  detection: {}", report.detection);
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

fn print_session_charts(sessions: &[SessionSummary], color: bool) {
    println!();
    println!("Session graphs");
    if sessions.is_empty() {
        println!("  no sessions to chart");
        return;
    }

    let max_runtime = sessions
        .iter()
        .map(|summary| summary.total_runtime_us)
        .max()
        .unwrap_or(1)
        .max(1);

    for summary in sessions {
        let runtime_ms = (summary.total_runtime_us as f64 / 1000.0).round() as usize;
        let runtime_bar = visual::bar_line(
            &truncate_text(&summary.label, 18),
            summary.total_runtime_us as usize,
            max_runtime as usize,
            24,
            color,
        );
        println!(
            "  {}  {runtime_ms:>5}ms  {:>2}/{:<2}",
            runtime_bar, summary.passed, summary.total
        );
    }

    let runtime_values = sessions
        .iter()
        .map(|summary| summary.total_runtime_us)
        .collect::<Vec<_>>();
    println!(
        "  runtime sparkline: {}",
        visual::sparkline(&runtime_values, 32, color)
    );
}

fn print_case_mix_chart(cases: &[GuestCase], color: bool) {
    println!();
    println!("Case mix by category");
    let counts = counts_by(cases.iter().map(|case| case.category.as_str()));
    for (label, value) in counts {
        println!("  {}", visual::bar_line(&label, value, 8, 24, color));
    }
    println!("Case mix by severity");
    let severities = counts_by(cases.iter().map(|case| case.severity.as_str()));
    for (label, value) in severities {
        println!("  {}", visual::bar_line(&label, value, 8, 24, color));
    }
}

fn print_stage_mix_chart(cases: &[GuestCase], color: bool) {
    println!();
    println!("Case mix by stage");
    let stages = counts_by(cases.iter().map(|case| case.stage.as_str()));
    for (label, value) in stages {
        println!("  {}", visual::bar_line(&label, value, 8, 24, color));
    }
    println!("Case mix by TTP");
    let ttps = counts_by(cases.iter().map(|case| case.ttp.as_str()));
    for (label, value) in ttps {
        println!("  {}", visual::bar_line(&label, value, 8, 24, color));
    }
}

fn print_policy_limits_chart(policy: &Policy, color: bool) {
    println!();
    println!("Policy limits");
    println!(
        "  {}",
        visual::bar_line("packet", policy.max_packet_len as usize, 4096, 24, color)
    );
    println!(
        "  {}",
        visual::bar_line(
            "cap_string",
            policy.max_cap_string_len as usize,
            256,
            24,
            color
        )
    );
    println!(
        "  {}",
        visual::bar_line("alloc", policy.max_alloc as usize, 65536, 24, color)
    );
    println!(
        "  {}",
        visual::bar_line("fuel", policy.initial_fuel as usize, 256, 24, color)
    );
    println!(
        "  {}",
        visual::bar_line(
            "memory_pages",
            policy.max_memory_pages as usize,
            16,
            24,
            color
        )
    );
}

fn counts_by<'a, I>(items: I) -> Vec<(String, usize)>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    for item in items {
        *counts.entry(item.to_string()).or_insert(0) += 1;
    }
    visual::sorted_desc_counts(counts.into_iter().collect())
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
    !matches!(input.to_ascii_lowercase().as_str(), "q" | "quit" | "exit")
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

fn clear_screen_if_interactive() {
    if io::stdout().is_terminal() {
        print!("\x1b[2J\x1b[H");
        let _ = io::stdout().flush();
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
