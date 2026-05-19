use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::abi;
use crate::config::Config;
use crate::policy::Policy;
use crate::runner::CaseReport;

const DEFAULT_SESSION_DIR: &str = "target/security-sessions";

#[derive(Debug, Clone)]
pub struct SessionStore {
    dir: PathBuf,
    index_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub id: String,
    pub created_unix_ms: u128,
    pub label: String,
    pub backend: String,
    pub isolation: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub total_runtime_us: u128,
    pub path: String,
}

impl SessionStore {
    pub fn new(path: impl AsRef<Path>) -> Self {
        let dir = path.as_ref().to_path_buf();
        let index_path = dir.join("index.tsv");
        Self { dir, index_path }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn record_run(
        &self,
        label: &str,
        config: &Config,
        policy: &Policy,
        reports: &[CaseReport],
    ) -> Result<SessionSummary, String> {
        fs::create_dir_all(&self.dir)
            .map_err(|err| format!("failed to create {}: {err}", self.dir.display()))?;

        let created_unix_ms = unix_millis();
        let id = created_unix_ms.to_string();
        let file_name = format!("session-{id}-{}.json", slugify(label));
        let path = self.dir.join(file_name);
        let summary = make_summary(
            id,
            created_unix_ms,
            label.to_string(),
            config,
            reports,
            path.to_string_lossy().to_string(),
        );

        fs::write(
            &path,
            render_session_json(&summary, label, config, policy, reports),
        )
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;

        let mut index = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.index_path)
            .map_err(|err| format!("failed to open {}: {err}", self.index_path.display()))?;
        writeln!(
            index,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            summary.id,
            summary.created_unix_ms,
            clean_tsv(&summary.label),
            summary.backend,
            summary.isolation,
            summary.total,
            summary.passed,
            summary.failed,
            summary.total_runtime_us,
            clean_tsv(&summary.path)
        )
        .map_err(|err| format!("failed to update {}: {err}", self.index_path.display()))?;

        Ok(summary)
    }

    pub fn list_recent(&self, limit: usize) -> Result<Vec<SessionSummary>, String> {
        if !self.index_path.exists() {
            return Ok(Vec::new());
        }

        let contents = fs::read_to_string(&self.index_path)
            .map_err(|err| format!("failed to read {}: {err}", self.index_path.display()))?;
        let mut sessions = contents
            .lines()
            .filter_map(parse_index_line)
            .collect::<Vec<_>>();
        sessions.reverse();
        sessions.truncate(limit);
        Ok(sessions)
    }

    pub fn latest(&self) -> Result<Option<SessionSummary>, String> {
        Ok(self.list_recent(1)?.into_iter().next())
    }

    pub fn read_session(&self, summary: &SessionSummary) -> Result<String, String> {
        fs::read_to_string(&summary.path)
            .map_err(|err| format!("failed to read {}: {err}", summary.path))
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new(DEFAULT_SESSION_DIR)
    }
}

fn make_summary(
    id: String,
    created_unix_ms: u128,
    label: String,
    config: &Config,
    reports: &[CaseReport],
    path: String,
) -> SessionSummary {
    let passed = reports.iter().filter(|report| report.passed()).count();
    let failed = reports.len().saturating_sub(passed);
    let total_runtime_us = reports
        .iter()
        .map(|report| report.compile_us + report.instantiate_us + report.run_us)
        .sum();

    SessionSummary {
        id,
        created_unix_ms,
        label,
        backend: config.backend.name().to_string(),
        isolation: config.isolation.name().to_string(),
        total: reports.len(),
        passed,
        failed,
        total_runtime_us,
        path,
    }
}

fn render_session_json(
    summary: &SessionSummary,
    label: &str,
    config: &Config,
    policy: &Policy,
    reports: &[CaseReport],
) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str("  \"tool\": \"wasmer-hostile-guest-security-harness\",\n");
    out.push_str(&format!(
        "  \"session\": {{\"id\": \"{}\", \"label\": \"{}\", \"created_unix_ms\": {}}},\n",
        json_escape(&summary.id),
        json_escape(label),
        summary.created_unix_ms
    ));
    out.push_str(&format!(
        "  \"runtime\": {{\"crate\": \"wasmer=6.1.0\", \"wasmer_cli\": \"{}\", \"rustc\": \"{}\"}},\n",
        json_escape(&command_version("wasmer", &["--version"]).unwrap_or_else(|| "unavailable".into())),
        json_escape(&command_version("rustc", &["--version"]).unwrap_or_else(|| "unavailable".into()))
    ));
    out.push_str(&format!(
        "  \"execution\": {{\"backend\": \"{}\", \"isolation\": \"{}\", \"profile\": \"{}\", \"repeat\": {}, \"corpus_dir\": {}, \"policy_path\": {}}},\n",
        config.backend.name(),
        config.isolation.name(),
        config.profile.name(),
        config.repeat,
        json_opt(config.corpus_dir.as_deref()),
        json_opt(config.policy_path.as_deref())
    ));
    out.push_str(&format!(
        "  \"policy\": {{\"max_packet_len\": {}, \"max_cap_string_len\": {}, \"max_alloc\": {}, \"fuel\": {}, \"max_memory_pages\": {}, \"require_tick_import\": {}, \"supervisor_timeout_ms\": {}, \"allowed_paths\": [{}]}},\n",
        policy.max_packet_len,
        policy.max_cap_string_len,
        policy.max_alloc,
        policy.initial_fuel,
        policy.max_memory_pages,
        policy.require_tick_import,
        policy.supervisor_timeout_ms,
        policy
            .allowed_paths()
            .iter()
            .map(|path| format!("\"{}\"", json_escape(path)))
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str(&format!(
        "  \"summary\": {{\"total\": {}, \"passed\": {}, \"failed\": {}, \"total_runtime_us\": {}}},\n",
        summary.total, summary.passed, summary.failed, summary.total_runtime_us
    ));
    out.push_str("  \"cases\": [\n");
    for (index, report) in reports.iter().enumerate() {
        if index > 0 {
            out.push_str(",\n");
        }
        out.push_str(&render_case_json(report));
    }
    out.push_str("\n  ]\n");
    out.push_str("}\n");
    out
}

fn render_case_json(report: &CaseReport) -> String {
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
        "      \"source_path\": \"{}\",\n",
        json_escape(&report.source_path)
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
    out.push_str(&format!(
        "      \"memory\": {{\"before_pages\": {}, \"after_pages\": {}, \"before_bytes\": {}, \"after_bytes\": {}}},\n",
        report.memory_before.pages,
        report.memory_after.pages,
        report.memory_before.bytes,
        report.memory_after.bytes
    ));
    if let Some(error) = &report.host_error {
        out.push_str(&format!(
            "      \"host_error\": \"{}\",\n",
            json_escape(error)
        ));
    } else {
        out.push_str("      \"host_error\": null,\n");
    }
    out.push_str("      \"events\": [");
    for (index, event) in report.telemetry.events.iter().enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(&format!(
            "{{\"import\": \"{}\", \"decision\": \"{}\", \"result\": \"{}\", \"detail\": \"{}\", \"elapsed_us\": {}, \"gates\": [{}]}}",
            json_escape(event.import),
            event.decision(),
            abi::code_name(event.result_code),
            json_escape(&event.detail),
            event.elapsed_us,
            event
                .gates
                .iter()
                .map(|gate| format!(
                    "{{\"name\": \"{}\", \"passed\": {}}}",
                    json_escape(gate.name),
                    gate.passed
                ))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    out.push_str("]\n");
    out.push_str("    }");
    out
}

fn parse_index_line(line: &str) -> Option<SessionSummary> {
    let parts = line.split('\t').collect::<Vec<_>>();
    if parts.len() != 10 {
        return None;
    }

    Some(SessionSummary {
        id: parts[0].to_string(),
        created_unix_ms: parts[1].parse().ok()?,
        label: parts[2].to_string(),
        backend: parts[3].to_string(),
        isolation: parts[4].to_string(),
        total: parts[5].parse().ok()?,
        passed: parts[6].parse().ok()?,
        failed: parts[7].parse().ok()?,
        total_runtime_us: parts[8].parse().ok()?,
        path: parts[9].to_string(),
    })
}

fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn command_version(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn json_opt(value: Option<&str>) -> String {
    value
        .map(|value| format!("\"{}\"", json_escape(value)))
        .unwrap_or_else(|| "null".into())
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

fn clean_tsv(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ")
}

fn slugify(value: &str) -> String {
    let slug = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    let slug = slug
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if slug.is_empty() { "run".into() } else { slug }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugifies_labels_for_file_names() {
        assert_eq!(slugify("Interview Narrative"), "interview-narrative");
        assert_eq!(slugify("  "), "run");
    }

    #[test]
    fn parses_session_index_line() {
        let line = "123\t123\tfull corpus\tcranelift\tin-process\t24\t24\t0\t77\ttarget/security-sessions/session.json";
        let summary = parse_index_line(line).expect("index line parses");
        assert_eq!(summary.id, "123");
        assert_eq!(summary.label, "full corpus");
        assert_eq!(summary.total, 24);
        assert_eq!(summary.failed, 0);
    }
}
