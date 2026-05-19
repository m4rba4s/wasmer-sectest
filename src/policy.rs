use std::fs;

#[derive(Debug, Clone)]
pub struct Policy {
    pub max_packet_len: u32,
    pub max_cap_string_len: u32,
    pub max_alloc: u32,
    pub initial_fuel: u32,
    pub max_memory_pages: u32,
    pub require_tick_import: bool,
    pub supervisor_timeout_ms: u64,
    allowed_paths: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_packet_len: 4096,
            max_cap_string_len: 256,
            max_alloc: 64 * 1024,
            initial_fuel: 256,
            max_memory_pages: 16,
            require_tick_import: true,
            supervisor_timeout_ms: 250,
            allowed_paths: vec!["/sandbox/allowed.txt".into()],
        }
    }
}

impl Policy {
    pub fn from_file(path: &str) -> Result<Self, String> {
        let contents =
            fs::read_to_string(path).map_err(|err| format!("failed to read {path}: {err}"))?;
        Self::parse(&contents).map_err(|err| format!("{path}: {err}"))
    }

    pub fn parse(contents: &str) -> Result<Self, String> {
        let mut policy = Self::default();

        for (line_index, raw_line) in contents.lines().enumerate() {
            let line_number = line_index + 1;
            let line = raw_line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            let Some((key, value)) = line.split_once('=') else {
                return Err(format!("line {line_number}: expected key = value"));
            };
            let key = key.trim();
            let value = value.trim();

            match key {
                "max_packet_len" => policy.max_packet_len = parse_u32(value, line_number, key)?,
                "max_cap_string_len" => {
                    policy.max_cap_string_len = parse_u32(value, line_number, key)?;
                }
                "max_alloc" => policy.max_alloc = parse_u32(value, line_number, key)?,
                "initial_fuel" => policy.initial_fuel = parse_u32(value, line_number, key)?,
                "max_memory_pages" => {
                    policy.max_memory_pages = parse_u32(value, line_number, key)?;
                }
                "require_tick_import" => {
                    policy.require_tick_import = parse_bool(value, line_number, key)?;
                }
                "supervisor_timeout_ms" => {
                    policy.supervisor_timeout_ms = parse_u64(value, line_number, key)?;
                }
                "allowed_paths" => policy.allowed_paths = parse_string_array(value, line_number)?,
                other => return Err(format!("line {line_number}: unsupported key '{other}'")),
            }
        }

        if policy.allowed_paths.is_empty() {
            return Err("allowed_paths must contain at least one exact capability".into());
        }

        Ok(policy)
    }

    pub fn is_path_allowed(&self, path: &str) -> bool {
        self.allowed_paths.iter().any(|allowed| allowed == path)
    }

    pub fn allowed_paths(&self) -> &[String] {
        &self.allowed_paths
    }
}

fn parse_u32(value: &str, line_number: usize, key: &str) -> Result<u32, String> {
    value
        .parse()
        .map_err(|err| format!("line {line_number}: invalid {key}: {err}"))
}

fn parse_u64(value: &str, line_number: usize, key: &str) -> Result<u64, String> {
    value
        .parse()
        .map_err(|err| format!("line {line_number}: invalid {key}: {err}"))
}

fn parse_bool(value: &str, line_number: usize, key: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!(
            "line {line_number}: invalid {key}: expected true or false"
        )),
    }
}

fn parse_string_array(value: &str, line_number: usize) -> Result<Vec<String>, String> {
    let value = value.trim();
    if !value.starts_with('[') || !value.ends_with(']') {
        return Err(format!(
            "line {line_number}: allowed_paths must be a string array"
        ));
    }

    let inner = &value[1..value.len() - 1];
    let mut paths = Vec::new();
    let mut chars = inner.chars().peekable();

    loop {
        skip_ws_and_commas(&mut chars);
        if chars.peek().is_none() {
            break;
        }

        if chars.next() != Some('"') {
            return Err(format!(
                "line {line_number}: allowed_paths entries must be quoted strings"
            ));
        }

        let mut path = String::new();
        let mut closed = false;
        while let Some(ch) = chars.next() {
            match ch {
                '"' => {
                    closed = true;
                    break;
                }
                '\\' => {
                    let Some(escaped) = chars.next() else {
                        return Err(format!("line {line_number}: trailing escape in string"));
                    };
                    match escaped {
                        '"' => path.push('"'),
                        '\\' => path.push('\\'),
                        'n' => path.push('\n'),
                        'r' => path.push('\r'),
                        't' => path.push('\t'),
                        other => {
                            return Err(format!(
                                "line {line_number}: unsupported escape \\{other}"
                            ));
                        }
                    }
                }
                other => path.push(other),
            }
        }

        if !closed {
            return Err(format!("line {line_number}: unterminated string"));
        }
        paths.push(path);

        skip_ws(&mut chars);
        match chars.peek() {
            Some(',') => continue,
            Some(_) => {
                return Err(format!(
                    "line {line_number}: expected comma after allowed path"
                ));
            }
            None => break,
        }
    }

    Ok(paths)
}

fn skip_ws_and_commas<I>(chars: &mut std::iter::Peekable<I>)
where
    I: Iterator<Item = char>,
{
    while matches!(chars.peek(), Some(ch) if ch.is_whitespace() || *ch == ',') {
        chars.next();
    }
}

fn skip_ws<I>(chars: &mut std::iter::Peekable<I>)
where
    I: Iterator<Item = char>,
{
    while matches!(chars.peek(), Some(ch) if ch.is_whitespace()) {
        chars.next();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_policy_file_shape() {
        let policy = Policy::parse(
            r#"
            max_packet_len = 1024
            max_cap_string_len = 64
            max_alloc = 2048
            initial_fuel = 9
            max_memory_pages = 4
            require_tick_import = false
            supervisor_timeout_ms = 33
            allowed_paths = ["/sandbox/allowed.txt", "/sandbox/extra.txt"]
            "#,
        )
        .expect("policy parses");

        assert_eq!(policy.max_packet_len, 1024);
        assert_eq!(policy.max_cap_string_len, 64);
        assert_eq!(policy.max_alloc, 2048);
        assert_eq!(policy.initial_fuel, 9);
        assert_eq!(policy.max_memory_pages, 4);
        assert!(!policy.require_tick_import);
        assert_eq!(policy.supervisor_timeout_ms, 33);
        assert!(policy.is_path_allowed("/sandbox/extra.txt"));
        assert!(!policy.is_path_allowed("/etc/passwd"));
    }
}
