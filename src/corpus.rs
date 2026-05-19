use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::abi;
use crate::guests::{CaseKind, GuestCase, GuestSource};

#[derive(Debug, Default)]
struct CaseMetadata {
    file: String,
    name: Option<String>,
    expected_code: Option<i32>,
    kind: Option<CaseKind>,
    category: Option<String>,
    severity: Option<String>,
    description: Option<String>,
    control: Option<String>,
    stage: Option<String>,
    ttp: Option<String>,
    detection: Option<String>,
}

pub fn load_corpus(dir: &str) -> Result<Vec<GuestCase>, String> {
    let root = Path::new(dir);
    if !root.is_dir() {
        return Err(format!("{dir} is not a directory"));
    }

    let mut metadata = load_manifest(root)?;
    let mut files = Vec::new();
    collect_guest_files(root, &mut files)?;
    files.sort();

    if files.is_empty() {
        return Err(format!("{dir} contains no .wat or .wasm files"));
    }

    let mut cases = Vec::with_capacity(files.len());
    for path in files {
        let rel = relative_key(root, &path);
        let meta = metadata.remove(&rel);
        cases.push(load_case(&path, &rel, meta)?);
    }

    if let Some(missing) = metadata.keys().next() {
        return Err(format!(
            "corpus.toml references {missing}, but the file was not found"
        ));
    }

    Ok(cases)
}

fn load_manifest(root: &Path) -> Result<HashMap<String, CaseMetadata>, String> {
    let path = root.join("corpus.toml");
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let contents = fs::read_to_string(&path)
        .map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    parse_manifest(&contents)
}

fn parse_manifest(contents: &str) -> Result<HashMap<String, CaseMetadata>, String> {
    let mut cases = Vec::new();
    let mut current: Option<CaseMetadata> = None;

    for (line_index, raw_line) in contents.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        if line == "[[case]]" {
            if let Some(case) = current.take() {
                cases.push(case);
            }
            current = Some(CaseMetadata::default());
            continue;
        }

        let Some(case) = current.as_mut() else {
            return Err(format!("line {line_number}: expected [[case]] before key"));
        };
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {line_number}: expected key = value"));
        };
        let key = key.trim();
        let value = parse_quoted_or_bare(value.trim(), line_number)?;

        match key {
            "file" => case.file = normalize_manifest_path(&value),
            "name" => case.name = Some(value),
            "expected" => {
                case.expected_code = Some(abi::parse_code_name(&value).ok_or_else(|| {
                    format!("line {line_number}: unsupported expected code '{value}'")
                })?);
            }
            "kind" => {
                case.kind = Some(match value.as_str() {
                    "run" | "run_export" => CaseKind::RunExport,
                    "growth_probe" => CaseKind::GrowthProbe,
                    "static_audit" => CaseKind::StaticAudit,
                    _ => return Err(format!("line {line_number}: unsupported kind '{value}'")),
                });
            }
            "category" => case.category = Some(value),
            "severity" => case.severity = Some(value),
            "description" => case.description = Some(value),
            "control" => case.control = Some(value),
            "stage" => case.stage = Some(value),
            "ttp" => case.ttp = Some(value),
            "detection" => case.detection = Some(value),
            other => return Err(format!("line {line_number}: unsupported key '{other}'")),
        }
    }

    if let Some(case) = current.take() {
        cases.push(case);
    }

    let mut by_file = HashMap::new();
    for case in cases {
        if case.file.is_empty() {
            return Err("corpus.toml case is missing file".into());
        }
        if by_file.insert(case.file.clone(), case).is_some() {
            return Err("corpus.toml contains duplicate file entries".into());
        }
    }

    Ok(by_file)
}

fn collect_guest_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in
        fs::read_dir(dir).map_err(|err| format!("failed to read {}: {err}", dir.display()))?
    {
        let entry = entry.map_err(|err| format!("failed to read directory entry: {err}"))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| format!("failed to inspect {}: {err}", path.display()))?;
        if file_type.is_dir() {
            collect_guest_files(&path, files)?;
        } else if is_guest_module(&path) {
            files.push(path);
        }
    }
    Ok(())
}

fn is_guest_module(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("wat") | Some("wasm")
    )
}

fn load_case(path: &Path, rel: &str, meta: Option<CaseMetadata>) -> Result<GuestCase, String> {
    let meta = meta.unwrap_or_default();
    let name = meta.name.unwrap_or_else(|| {
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("external_guest")
            .to_string()
    });
    let source = match path.extension().and_then(|ext| ext.to_str()) {
        Some("wat") => GuestSource::Wat(
            fs::read_to_string(path)
                .map_err(|err| format!("failed to read {}: {err}", path.display()))?,
        ),
        Some("wasm") => GuestSource::Wasm(
            fs::read(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?,
        ),
        _ => return Err(format!("unsupported guest module {}", path.display())),
    };
    let category = meta.category.unwrap_or_else(|| "external".into());

    Ok(GuestCase {
        name,
        description: meta
            .description
            .unwrap_or_else(|| format!("external corpus module {rel}")),
        expected_code: meta.expected_code.unwrap_or(abi::OK),
        kind: meta.kind.unwrap_or(CaseKind::RunExport),
        category,
        severity: meta.severity.unwrap_or_else(|| "info".into()),
        control: meta
            .control
            .unwrap_or_else(|| "observe external guest under configured host policy".into()),
        stage: meta
            .stage
            .unwrap_or_else(|| "external corpus validation".into()),
        ttp: meta
            .ttp
            .unwrap_or_else(|| "external-host-import-abuse".into()),
        detection: meta.detection.unwrap_or_else(|| {
            "external guest telemetry records configured boundary decisions".into()
        }),
        source_path: path.to_string_lossy().replace('\\', "/"),
        source,
    })
}

fn relative_key(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn normalize_manifest_path(path: &str) -> String {
    path.trim_start_matches("./").replace('\\', "/")
}

fn parse_quoted_or_bare(value: &str, line_number: usize) -> Result<String, String> {
    let value = value.trim();
    if value.starts_with('"') {
        if !value.ends_with('"') || value.len() < 2 {
            return Err(format!("line {line_number}: unterminated string"));
        }
        parse_quoted_string(&value[1..value.len() - 1], line_number)
    } else {
        Ok(value.to_string())
    }
}

fn parse_quoted_string(value: &str, line_number: usize) -> Result<String, String> {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let Some(escaped) = chars.next() else {
                return Err(format!("line {line_number}: trailing escape in string"));
            };
            match escaped {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                other => return Err(format!("line {line_number}: unsupported escape \\{other}")),
            }
        } else {
            out.push(ch);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn loads_wat_and_wasm_external_corpus() {
        let root = unique_temp_dir();
        fs::create_dir_all(&root).expect("create temp corpus");

        let wat = r#"
        (module
          (import "host" "accept_packet" (func $accept_packet (param i32 i32 i32) (result i32)))
          (import "host" "read_cap" (func $read_cap (param i32 i32) (result i32)))
          (import "host" "alloc_cap" (func $alloc_cap (param i32) (result i32)))
          (import "host" "tick" (func $tick (result i32)))
          (memory (export "memory") 1 2)
          (func (export "run") (result i32)
            i32.const -16
            i32.const 64
            i32.const 8
            call $accept_packet))
        "#;
        fs::write(root.join("overflow.wat"), wat).expect("write wat");
        fs::write(
            root.join("good.wasm"),
            wat::parse_str(wat).expect("compile wasm"),
        )
        .expect("write wasm");
        fs::write(
            root.join("corpus.toml"),
            r#"
            [[case]]
            file = "overflow.wat"
            name = "external_overflow"
            expected = "ERR_BOUNDS"
            category = "memory"
            severity = "critical"
            description = "external overflow case"
            control = "checked_add catches external overflow"

            [[case]]
            file = "good.wasm"
            name = "external_wasm_overflow"
            expected = "ERR_BOUNDS"
            "#,
        )
        .expect("write manifest");

        let cases = load_corpus(root.to_str().expect("utf8 temp dir")).expect("load corpus");
        assert_eq!(cases.len(), 2);
        assert!(cases.iter().any(|case| case.name == "external_overflow"));
        assert!(
            cases
                .iter()
                .any(|case| matches!(case.source, GuestSource::Wasm(_)))
        );
        for case in &cases {
            let report = crate::runner::run_case(
                case,
                crate::config::Backend::Cranelift,
                crate::policy::Policy::default(),
            );
            assert!(report.passed(), "{} did not pass", report.name);
        }

        let _ = fs::remove_dir_all(root);
    }

    fn unique_temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("wasmer-demo-corpus-{nanos}"))
    }
}
