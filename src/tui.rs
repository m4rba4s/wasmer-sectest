use std::io::{self, Write};
use std::thread;
use std::time::{Duration, Instant};

use crate::abi;
use crate::ansi;
use crate::config::Backend;
use crate::guests::GuestCase;
use crate::policy::Policy;
use crate::runner::{CaseReport, run_case};
use crate::telemetry::{Gate, ImportEvent};

const BAR_WIDTH: usize = 44;
const MEMORY_WIDTH: usize = 58;
const CASE_NAME_WIDTH: usize = 24;
const DETAIL_WIDTH: usize = 108;

#[derive(Clone, Copy)]
pub struct TuiOptions {
    pub delay: Duration,
    pub color: bool,
}

pub fn run_security_dashboard(
    cases: &[GuestCase],
    backend: Backend,
    policy: Policy,
    options: TuiOptions,
) -> Vec<CaseReport> {
    let dashboard = SecurityDashboard::new(policy.clone(), backend, options);
    let mut reports = Vec::with_capacity(cases.len());

    dashboard.enter();
    for (index, case) in cases.iter().enumerate() {
        dashboard.draw(DrawFrame {
            cases,
            reports: &reports,
            current_index: index,
            current_case: Some(case),
            current_report: None,
            cursor: None,
            phase: "loading guest",
        });
        dashboard.pause();

        let report = run_case(case, backend, policy.clone());
        dashboard.draw(DrawFrame {
            cases,
            reports: &reports,
            current_index: index,
            current_case: Some(case),
            current_report: Some(&report),
            cursor: None,
            phase: "host boundary captured",
        });
        dashboard.pause();

        for (event_index, event) in report.telemetry.events.iter().enumerate() {
            let gate_count = event.gates.len().max(1);
            if options.delay == Duration::ZERO {
                dashboard.draw(DrawFrame {
                    cases,
                    reports: &reports,
                    current_index: index,
                    current_case: Some(case),
                    current_report: Some(&report),
                    cursor: Some(EventCursor {
                        event_index,
                        gate_count,
                    }),
                    phase: "replaying validation gates",
                });
            } else {
                for gate_count in 1..=gate_count {
                    dashboard.draw(DrawFrame {
                        cases,
                        reports: &reports,
                        current_index: index,
                        current_case: Some(case),
                        current_report: Some(&report),
                        cursor: Some(EventCursor {
                            event_index,
                            gate_count,
                        }),
                        phase: "replaying validation gates",
                    });
                    dashboard.pause_short();
                }
            }
        }

        reports.push(report);
        dashboard.draw(DrawFrame {
            cases,
            reports: &reports,
            current_index: index,
            current_case: Some(case),
            current_report: reports.last(),
            cursor: None,
            phase: "case sealed",
        });
        dashboard.pause();
    }

    dashboard.draw(DrawFrame {
        cases,
        reports: &reports,
        current_index: cases.len(),
        current_case: None,
        current_report: None,
        cursor: None,
        phase: "complete",
    });
    dashboard.exit();
    print_final_summary(&reports, &policy, options.color);
    reports
}

#[derive(Clone, Copy)]
struct EventCursor {
    event_index: usize,
    gate_count: usize,
}

struct DrawFrame<'a> {
    cases: &'a [GuestCase],
    reports: &'a [CaseReport],
    current_index: usize,
    current_case: Option<&'a GuestCase>,
    current_report: Option<&'a CaseReport>,
    cursor: Option<EventCursor>,
    phase: &'a str,
}

struct SecurityDashboard {
    policy: Policy,
    backend: Backend,
    options: TuiOptions,
    started: Instant,
}

impl SecurityDashboard {
    fn new(policy: Policy, backend: Backend, options: TuiOptions) -> Self {
        Self {
            policy,
            backend,
            options,
            started: Instant::now(),
        }
    }

    fn enter(&self) {
        print!("\x1b[2J\x1b[?25l");
        let _ = io::stdout().flush();
    }

    fn exit(&self) {
        println!("\x1b[?25h{}", ansi::RESET);
        let _ = io::stdout().flush();
    }

    fn pause(&self) {
        if self.options.delay > Duration::ZERO {
            thread::sleep(self.options.delay);
        }
    }

    fn pause_short(&self) {
        let delay = self.options.delay / 2;
        if delay > Duration::ZERO {
            thread::sleep(delay);
        }
    }

    fn draw(&self, frame: DrawFrame<'_>) {
        print!("\x1b[H");
        self.header(frame.cases, frame.reports, frame.phase);
        self.case_list(
            frame.cases,
            frame.reports,
            frame.current_index,
            frame.current_report,
        );
        self.current_panel(frame.current_case, frame.current_report, frame.cursor);
        self.aggregate_panel(frame.reports, frame.current_report);
        self.pad_tail();
        let _ = io::stdout().flush();
    }

    fn header(&self, cases: &[GuestCase], reports: &[CaseReport], phase: &str) {
        let completed = reports.len();
        let progress = if cases.is_empty() {
            1.0
        } else {
            completed as f64 / cases.len() as f64
        };
        let elapsed = self.started.elapsed().as_secs_f64();
        let passed = reports.iter().filter(|report| report.passed()).count();
        let failed = completed.saturating_sub(passed);

        println!(
            "{} {} {}",
            self.bold("Wasmer hostile-guest security cockpit"),
            self.badge(ansi::CYAN, "LIVE"),
            self.paint(ansi::GRAY, format!("phase={phase}"))
        );
        println!(
            "crate wasmer=6.1.0 | backend={} | cases={} | elapsed={elapsed:.1}s | passed={} failed={}",
            self.backend.name(),
            cases.len(),
            self.paint(ansi::GREEN, passed.to_string()),
            self.paint(
                if failed == 0 { ansi::GREEN } else { ansi::RED },
                failed.to_string()
            )
        );
        println!(
            "policy packet<={} cap_string<={} alloc<={} fuel={} memory_pages<={} tick_import={} timeout_ms={} allowed_paths={:?}",
            self.policy.max_packet_len,
            self.policy.max_cap_string_len,
            self.policy.max_alloc,
            self.policy.initial_fuel,
            self.policy.max_memory_pages,
            self.policy.require_tick_import,
            self.policy.supervisor_timeout_ms,
            self.policy.allowed_paths()
        );
        println!(
            "{}",
            progress_bar(
                "corpus",
                progress,
                BAR_WIDTH,
                completed,
                cases.len(),
                self.options.color
            )
        );
        println!("{}", self.rule("hostile corpus"));
    }

    fn case_list(
        &self,
        cases: &[GuestCase],
        reports: &[CaseReport],
        current_index: usize,
        current_report: Option<&CaseReport>,
    ) {
        for (index, case) in cases.iter().enumerate() {
            let status = if let Some(report) = reports.get(index) {
                if report.passed() {
                    self.paint(ansi::GREEN, "PASS")
                } else {
                    self.paint(ansi::RED, "FAIL")
                }
            } else if index == current_index {
                current_report
                    .map(|report| decision_badge(report, self.options.color))
                    .unwrap_or_else(|| self.paint(ansi::YELLOW, "RUN "))
            } else {
                self.paint(ansi::GRAY, "WAIT")
            };
            let pointer = if index == current_index { ">" } else { " " };
            println!(
                "{} {} {:<CASE_NAME_WIDTH$} {:<10} {:<8} {}",
                self.paint(ansi::GRAY, format!("{:02}", index + 1)),
                pointer,
                case.name,
                case.category,
                case.severity,
                status
            );
        }
    }

    fn current_panel(
        &self,
        current_case: Option<&GuestCase>,
        current_report: Option<&CaseReport>,
        cursor: Option<EventCursor>,
    ) {
        println!("{}", self.rule("current boundary"));
        let Some(case) = current_case else {
            println!(
                "{}",
                self.paint(ansi::GREEN, "all hostile guests completed")
            );
            return;
        };

        println!(
            "{} {} expected {}",
            self.bold(&case.name),
            self.paint(ansi::GRAY, format!("{} / {}", case.category, case.severity)),
            self.paint(ansi::CYAN, abi::code_name(case.expected_code))
        );
        println!("attack  {}", truncate(&case.description, DETAIL_WIDTH));
        println!(
            "ttp     {} / {}",
            truncate(&case.stage, 40),
            truncate(&case.ttp, 54)
        );
        println!("control {}", truncate(&case.control, DETAIL_WIDTH));
        println!("detect  {}", truncate(&case.detection, DETAIL_WIDTH));

        let Some(report) = current_report else {
            println!(
                "runtime compiling WAT -> Wasmer module -> instance -> guest run() under host imports"
            );
            println!(
                "boundary pending: every guest pointer, length, alignment, and capability string is hostile"
            );
            return;
        };

        println!(
            "runtime compile={}us instantiate={}us run={}us wasm={}B memory_pages {}->{} ({:+})",
            report.compile_us,
            report.instantiate_us,
            report.run_us,
            report.wasm_bytes,
            report.memory_before.pages,
            report.memory_after.pages,
            report.memory_before.delta_pages(report.memory_after)
        );

        if let Some(error) = &report.host_error {
            println!(
                "host_error {}",
                self.paint(ansi::RED, truncate(error, DETAIL_WIDTH))
            );
            return;
        }

        let event = selected_event(report, cursor).or_else(|| report.telemetry.events.last());
        if let Some(event) = event {
            let gate_limit = cursor
                .filter(|cursor| Some(cursor.event_index) == event_index(report, event))
                .map(|cursor| cursor.gate_count)
                .unwrap_or(event.gates.len());
            self.event_panel(event, gate_limit);
        } else {
            println!("host boundary no imports were logged");
        }
    }

    fn event_panel(&self, event: &ImportEvent, gate_limit: usize) {
        let decision_color = if event.result_code == abi::OK {
            ansi::GREEN
        } else {
            ansi::RED
        };
        println!(
            "import {} => {} {} in {}us",
            self.paint(ansi::WHITE, event.import),
            self.paint(decision_color, event.decision()),
            self.paint(decision_color, abi::code_name(event.result_code)),
            event.elapsed_us
        );
        println!(
            "args   ptr={} len={} align={} mem={}",
            fmt_hex(event.ptr),
            fmt_opt(event.len),
            fmt_opt(event.align),
            event
                .memory_size
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into())
        );
        println!("{}", render_memory_map(event, self.options.color));
        println!(
            "gates  {}",
            render_gate_pipeline(&event.gates, gate_limit, self.options.color)
        );
        println!("trace  {}", truncate(&event.detail, DETAIL_WIDTH));
    }

    fn aggregate_panel(&self, reports: &[CaseReport], current_report: Option<&CaseReport>) {
        println!("{}", self.rule("evidence rollup"));
        let mut rollup = Rollup::default();

        for report in reports {
            rollup.add(report);
        }

        if let Some(report) = current_report {
            let already_counted = reports.iter().any(|known| std::ptr::eq(known, report));
            if !already_counted {
                rollup.add(report);
            }
        }

        println!(
            "imports_logged={} allows={} denies={} ticks_seen={}",
            self.paint(ansi::CYAN, rollup.total_events.to_string()),
            self.paint(ansi::GREEN, rollup.allows.to_string()),
            self.paint(ansi::RED, rollup.denies.to_string()),
            self.paint(ansi::YELLOW, rollup.ticks.to_string())
        );
        println!(
            "time_us compile={} instantiate={} run={}",
            self.paint(ansi::CYAN, rollup.compile_us.to_string()),
            self.paint(ansi::MAGENTA, rollup.instantiate_us.to_string()),
            self.paint(ansi::GREEN, rollup.run_us.to_string())
        );
    }

    fn pad_tail(&self) {
        for _ in 0..4 {
            println!("\x1b[K");
        }
    }

    fn rule(&self, label: &str) -> String {
        format!(
            "{} {}",
            self.paint(ansi::GRAY, "-".repeat(18)),
            self.paint(ansi::WHITE, label)
        )
    }

    fn paint(&self, color: &str, text: impl AsRef<str>) -> String {
        paint(self.options.color, color, text)
    }

    fn bold(&self, text: impl AsRef<str>) -> String {
        if self.options.color {
            ansi::bold(text)
        } else {
            text.as_ref().to_string()
        }
    }

    fn badge(&self, color: &str, text: impl AsRef<str>) -> String {
        if self.options.color {
            ansi::badge(color, text)
        } else {
            format!("[ {} ]", text.as_ref())
        }
    }
}

#[derive(Default)]
struct Rollup {
    total_events: usize,
    allows: usize,
    denies: usize,
    ticks: u32,
    compile_us: u128,
    instantiate_us: u128,
    run_us: u128,
}

impl Rollup {
    fn add(&mut self, report: &CaseReport) {
        self.total_events += report.telemetry.events.len();
        self.denies += report
            .telemetry
            .events
            .iter()
            .filter(|event| event.result_code != abi::OK)
            .count();
        self.allows += report
            .telemetry
            .events
            .iter()
            .filter(|event| event.result_code == abi::OK)
            .count();
        self.ticks = self.ticks.saturating_add(report.telemetry.ticks_seen);
        self.compile_us += report.compile_us;
        self.instantiate_us += report.instantiate_us;
        self.run_us += report.run_us;
    }
}

fn selected_event(report: &CaseReport, cursor: Option<EventCursor>) -> Option<&ImportEvent> {
    cursor.and_then(|cursor| report.telemetry.events.get(cursor.event_index))
}

fn event_index(report: &CaseReport, event: &ImportEvent) -> Option<usize> {
    report
        .telemetry
        .events
        .iter()
        .position(|candidate| std::ptr::eq(candidate, event))
}

fn decision_badge(report: &CaseReport, color: bool) -> String {
    if report.passed() {
        paint(color, ansi::GREEN, "PASS")
    } else {
        paint(color, ansi::RED, "FAIL")
    }
}

fn render_gate_pipeline(gates: &[Gate], visible: usize, color: bool) -> String {
    if gates.is_empty() {
        return paint(color, ansi::GRAY, "no gates");
    }

    gates
        .iter()
        .enumerate()
        .map(|(index, gate)| {
            let visible = index < visible;
            let (color_code, mark) = if !visible {
                (ansi::GRAY, "....")
            } else if gate.passed {
                (ansi::GREEN, " ok ")
            } else {
                (ansi::RED, "fail")
            };
            paint(color, color_code, format!("[{mark} {}]", gate.name))
        })
        .collect::<Vec<_>>()
        .join(" -> ")
}

fn render_memory_map(event: &ImportEvent, color: bool) -> String {
    let Some(memory_size) = event.memory_size else {
        return format!(
            "mem    {}",
            paint(color, ansi::GRAY, "host-only import; no guest memory read")
        );
    };
    let mut cells = vec!['.'; MEMORY_WIDTH];
    if let (Some(ptr), Some(len)) = (event.ptr, event.len) {
        let start = map_offset(u64::from(ptr), memory_size, MEMORY_WIDTH);
        let end_value = u64::from(ptr).saturating_add(u64::from(len));
        let end = map_offset(end_value.min(memory_size), memory_size, MEMORY_WIDTH);
        let end = end.max(start.saturating_add(1)).min(MEMORY_WIDTH);
        for cell in cells.iter_mut().take(end).skip(start) {
            *cell = '#';
        }
    }

    let line = cells
        .into_iter()
        .map(|cell| match cell {
            '#' => paint(color, ansi::CYAN, "#"),
            _ => paint(color, ansi::GRAY, "."),
        })
        .collect::<String>();

    format!(
        "mem    0x00000000 [{}] 0x{:08x}",
        line,
        memory_size.min(u64::from(u32::MAX))
    )
}

fn map_offset(offset: u64, memory_size: u64, width: usize) -> usize {
    if memory_size == 0 || width == 0 {
        return 0;
    }
    let ratio = offset as f64 / memory_size as f64;
    ((width - 1) as f64 * ratio.clamp(0.0, 1.0)).round() as usize
}

fn progress_bar(
    label: &str,
    value: f64,
    width: usize,
    done: usize,
    total: usize,
    color: bool,
) -> String {
    let value = value.clamp(0.0, 1.0);
    let filled = (value * width as f64).round() as usize;
    let mut bar = String::new();
    for index in 0..width {
        if index < filled {
            bar.push_str(&paint(color, ansi::GREEN, "#"));
        } else {
            bar.push_str(&paint(color, ansi::GRAY, "."));
        }
    }
    format!(
        "{label:<7} [{bar}] {done:>2}/{total:<2} {:>5.1}%",
        value * 100.0
    )
}

fn fmt_hex(value: Option<u32>) -> String {
    value
        .map(|value| format!("0x{value:08x}"))
        .unwrap_or_else(|| "-".into())
}

fn fmt_opt(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".into())
}

fn truncate(value: impl AsRef<str>, max_chars: usize) -> String {
    let value = value.as_ref();
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

fn print_final_summary(reports: &[CaseReport], policy: &Policy, color: bool) {
    let passed = reports.iter().filter(|report| report.passed()).count();
    let failed = reports.len().saturating_sub(passed);
    let status_color = if failed == 0 { ansi::GREEN } else { ansi::RED };
    println!(
        "{}",
        paint(
            color,
            status_color,
            format!(
                "summary: {passed}/{} passed, {failed} failed",
                reports.len()
            )
        )
    );
    println!(
        "policy: packet<={} cap_string<={} alloc<={} fuel={} memory_pages<={} tick_import={} timeout_ms={}",
        policy.max_packet_len,
        policy.max_cap_string_len,
        policy.max_alloc,
        policy.initial_fuel,
        policy.max_memory_pages,
        policy.require_tick_import,
        policy.supervisor_timeout_ms
    );
}

fn paint(color: bool, color_code: &str, text: impl AsRef<str>) -> String {
    if color {
        ansi::paint(color_code, text)
    } else {
        text.as_ref().to_string()
    }
}
